// Copyright 2025 mosaic-store-lmdb Developers
// Licensed under the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>
// This file may not be copied, modified, or distributed except according to those terms.

//! Defines a Store type for storing, indexing, and accessing mosaic records.
//!
//! Indexes point at offsets into a record map to avoid additional tree searches during lookups.
//!
//! Tries to comply with as many mosaic spec requirements as possible that can be fully
//! implemented at the storage layer.

#![deny(
    missing_debug_implementations,
    trivial_numeric_casts,
    clippy::string_slice,
    unused_import_braces,
    unused_results,
    unused_lifetimes,
    unused_labels,
    unused_extern_crates,
    non_ascii_idents,
    keyword_idents,
    deprecated_in_future,
    unstable_features,
    single_use_lifetimes,
    unreachable_pub,
    missing_copy_implementations,
    missing_docs
)]

mod error;
pub use error::{Error, InnerError};

mod records;
use records::Records;

mod indexes;
use indexes::{Indexes, Key, KeyKind};

pub use heed;
use heed::types::Bytes;
use heed::{Database, RoTxn, RwTxn, WithoutTls};

use mosaic_core::{Filter, FilterElementType, Id, Record, Reference, Timestamp};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// A Mosaic Record storage system
#[derive(Debug)]
pub struct Store {
    records: Records,
    indexes: Indexes,
    dir: PathBuf,
    // extra_table_names: Vec<&'static str>,
}

impl Store {
    /// Setup persistent storage.
    ///
    /// The directory must already exist and be writable. If it already has storage,
    /// it will open that storage and use it. Otherwise, it will create new storage.
    ///
    /// Pass in the names of extra key-value tables you want. You can use them for
    /// any purpose, mapping opaque binary data to opaque binary data.
    pub fn new<P: AsRef<Path>>(
        directory: P,
        extra_table_names: Vec<&'static str>,
        maximum_size_in_gigabytes: usize,
    ) -> Result<Store, Error> {
        let dir = directory.as_ref().to_owned();

        // Create the directory if it doesn't exist, ignoring errors
        let _ = fs::create_dir(&dir);

        let mut records_path = dir.clone();
        records_path.push("records.map");

        let mut indexes_path = dir.clone();
        indexes_path.push("lmdb");

        // Create the lmdb subdirectory if it doesn't exist, ignoring errors
        let _ = fs::create_dir(&indexes_path);

        let records = Records::new(&records_path)?;
        let indexes = Indexes::new(&indexes_path, &extra_table_names, maximum_size_in_gigabytes)?;

        Ok(Store {
            records,
            indexes,
            dir,
            // extra_table_names,
        })
    }

    /// Get the directory where this store resides
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Sync the data to disk. This happens periodically, but sometimes it's useful to force
    /// it.
    pub fn sync(&self) -> Result<(), Error> {
        self.indexes.sync()?;
        Ok(())
    }

    /// Store a `Record`.
    ///
    /// Returns the offset where the `Record` is stored at, which can be used to fetch
    /// the `Record` efficiently via get_record_by_offset().
    ///
    /// If the record already exists, you will get an InnerError::Duplicate
    ///
    /// We do not validate the record.
    pub fn store_record(&self, record: &Record) -> Result<u64, Error> {
        let mut txn = self.indexes.write_txn()?;

        // Return Duplicate if it already exists
        if self
            .indexes
            .get_offset_by_ref(&txn, record.id().to_reference())?
            .is_some()
        {
            return Err(InnerError::Duplicate.into());
        }

        // Store the record
        let offset = self.records.store_record(record)? as u64;

        // Index the record
        self.indexes.index(&mut txn, record, offset)?;

        txn.commit()?;

        Ok(offset)
    }

    /// Deindex record by offset.
    pub fn deindex_record_by_offset(
        &self,
        txn: &mut RwTxn<'_>,
        offset: usize,
    ) -> Result<(), Error> {
        let record = unsafe { self.records.get_record_by_offset(offset)? };
        self.indexes.deindex(txn, record, false)?;
        Ok(())
    }

    /// Deindex record by id
    pub fn deindex_record_by_id(&self, txn: &mut RwTxn<'_>, id: Id) -> Result<(), Error> {
        let reference = id.to_reference();
        let Some(offset) = self.indexes.get_offset_by_ref(txn, reference)? else {
            return Ok(());
        };
        self.deindex_record_by_offset(txn, offset as usize)
    }

    /// Get access to an extra LMDB table
    pub fn extra_table(&self, name: &'static str) -> Option<Database<Bytes, Bytes>> {
        self.indexes.extra_table(name)
    }

    /// Get a read transaction for use with extra_table() or otherwise
    pub fn read_txn(&self) -> Result<RoTxn<WithoutTls>, Error> {
        self.indexes.read_txn()
    }

    /// Get a write transaction for use with extra_table() or otherwise
    pub fn write_txn(&self) -> Result<RwTxn, Error> {
        self.indexes.write_txn()
    }

    /// Get a `Record` by its offset.
    pub fn get_record_by_offset(&self, offset: usize) -> Result<&Record, Error> {
        unsafe { self.records.get_record_by_offset(offset) }
    }

    /// Get a `Record` by its reference.
    pub fn get_record_by_ref(&self, reference: Reference) -> Result<Option<&Record>, Error> {
        let txn = self.indexes.read_txn()?;
        if let Some(offset) = self.indexes.get_offset_by_ref(&txn, reference)? {
            unsafe { Some(self.records.get_record_by_offset(offset as usize)).transpose() }
        } else {
            Ok(None)
        }
    }

    /// Do we have a Record for the given reference?
    pub fn has_record(&self, reference: Reference) -> Result<bool, Error> {
        let txn = self.indexes.read_txn()?;
        Ok(self.indexes.get_offset_by_ref(&txn, reference)?.is_some())
    }

    /// Find all records that match the `Filter` and also pass the screen function.
    ///
    /// `allow_scraping` searches even when only a single narrow filter is present.
    /// Otherwise, either timestamp or at least two narrow filters are required.
    ///
    /// # Errors
    ///
    /// If the filter has no narrow elements at all, this function Errs.
    pub fn find_records<F>(
        &self,
        filter: &Filter,
        limit: usize,
        screen: F,
        allow_scraping: bool,
    ) -> Result<Vec<&Record>, Error>
    where
        F: Fn(&Record) -> bool,
    {
        if !filter.is_narrow() {
            return Err(InnerError::FilterTooWide.into());
        }

        let has_timestamps = filter.get_element(FilterElementType::TIMESTAMPS).is_some();
        let has_keys = filter.get_element(FilterElementType::AUTHOR_KEYS).is_some()
            || filter
                .get_element(FilterElementType::SIGNING_KEYS)
                .is_some();
        let has_tags = filter
            .get_element(FilterElementType::INCLUDED_TAGS)
            .is_some();
        let has_kinds = filter.get_element(FilterElementType::KINDS).is_some();

        if has_timestamps {
            self.find_records_by_timestamps(filter, limit, screen)
        } else if has_keys && has_tags {
            self.find_records_by_keys_and_tags(filter, limit, screen)
        } else if has_tags && has_kinds {
            self.find_records_by_tags_and_kinds(filter, limit, screen)
        } else if has_keys && has_kinds {
            self.find_records_by_keys_and_kinds(filter, limit, screen)
        } else if allow_scraping && has_tags {
            self.find_records_by_tags(filter, limit, screen)
        } else if allow_scraping && has_keys {
            self.find_records_by_keys(filter, limit, screen)
        } else if allow_scraping && has_kinds {
            self.find_records_by_kinds(filter, limit, screen)
        } else {
            Err(InnerError::FilterTooWide.into())
        }
    }

    fn find_records_by_timestamps<F>(
        &self,
        _filter: &Filter,
        _limit: usize,
        _screen: F,
    ) -> Result<Vec<&Record>, Error>
    where
        F: Fn(&Record) -> bool,
    {
        unimplemented!()
    }

    fn find_records_by_keys_and_tags<F>(
        &self,
        _filter: &Filter,
        _limit: usize,
        _screen: F,
    ) -> Result<Vec<&Record>, Error>
    where
        F: Fn(&Record) -> bool,
    {
        unimplemented!()
    }

    fn find_records_by_tags_and_kinds<F>(
        &self,
        _filter: &Filter,
        _limit: usize,
        _screen: F,
    ) -> Result<Vec<&Record>, Error>
    where
        F: Fn(&Record) -> bool,
    {
        unimplemented!()
    }

    fn find_records_by_keys_and_kinds<F>(
        &self,
        _filter: &Filter,
        _limit: usize,
        _screen: F,
    ) -> Result<Vec<&Record>, Error>
    where
        F: Fn(&Record) -> bool,
    {
        unimplemented!()
    }

    fn find_records_by_tags<F>(
        &self,
        filter: &Filter,
        limit: usize,
        screen: F,
    ) -> Result<Vec<&Record>, Error>
    where
        F: Fn(&Record) -> bool,
    {
        // We rely on the BTreeSet to keep our events in order.
        // Because iter_tag uses `tag_kind_ts_index`, we don't have
        // an easy way to walk through timestamps in order.
        // We can't even do limit until we collect all of them.
        // This is not very efficient, but it is hard to fix without a
        // different kind of indexing. This is a fallback/scrape anyway.

        let txn = self.indexes.read_txn()?;

        // We insert into a BTreeSet to keep them reverse time-ordered
        let mut output: BTreeSet<&Record> = BTreeSet::new();

        let since = match filter.get_element(FilterElementType::SINCE) {
            None => Timestamp::min(),
            Some(fe) => fe.since()?.unwrap_or(Timestamp::min()),
        };

        let until = match filter.get_element(FilterElementType::UNTIL) {
            None => Timestamp::max(),
            Some(fe) => fe.since()?.unwrap_or(Timestamp::max()),
        };

        // We can unwrap, because if we couldn't this function would not
        // have been called
        let iter = filter
            .get_element(FilterElementType::INCLUDED_TAGS)
            .unwrap()
            .tags()
            .unwrap();

        for tag in iter {
            for elem in self.indexes.iter_tag(&txn, tag)? {
                let (lmdbkey, offset) = elem?;
                let key = Key::from_bytes_and_kind(lmdbkey, KeyKind::TagpreKindTs);

                // Timebound
                let ts = key.timestamp().unwrap();
                if ts < since {
                    continue;
                }
                if ts >= until {
                    continue;
                }

                // Get at the record
                let record = unsafe { self.records.get_record_by_offset(offset as usize)? };

                // Screen and filter
                if screen(record) && filter.matches(record)? {
                    let _ = output.insert(record);
                }
            }
        }

        let events = output.iter().take(limit).copied().collect();

        Ok(events)
    }

    fn find_records_by_keys<F>(
        &self,
        filter: &Filter,
        limit: usize,
        screen: F,
    ) -> Result<Vec<&Record>, Error>
    where
        F: Fn(&Record) -> bool,
    {
        // We rely on the BTreeSet to keep our events in order.
        // Because iter_eitherkey uses `eitherkey_tag_ts_index`, we don't have
        // an easy way to walk through timestamps in order.
        // We can't even do limit until we collect all of them.
        // This is not very efficient, but it is hard to fix without a
        // different kind of indexing. This is a fallback/scrape anyway.

        let txn = self.indexes.read_txn()?;

        // We insert into a BTreeSet to keep them reverse time-ordered
        let mut output: BTreeSet<&Record> = BTreeSet::new();

        let since = match filter.get_element(FilterElementType::SINCE) {
            None => Timestamp::min(),
            Some(fe) => fe.since()?.unwrap_or(Timestamp::min()),
        };

        let until = match filter.get_element(FilterElementType::UNTIL) {
            None => Timestamp::max(),
            Some(fe) => fe.since()?.unwrap_or(Timestamp::max()),
        };

        // We can unwrap, because if we couldn't this function would not
        // have been called
        let iter = match filter
            .get_element(FilterElementType::AUTHOR_KEYS)
            .unwrap()
            .keys()
        {
            Some(iter) => iter,
            None => filter
                .get_element(FilterElementType::SIGNING_KEYS)
                .unwrap()
                .keys()
                .unwrap()
        };

        for eitherkey in iter {
            for elem in self.indexes.iter_eitherkey(&txn, eitherkey)? {
                let (lmdbkey, offset) = elem?;
                let key = Key::from_bytes_and_kind(lmdbkey, KeyKind::PkpreTagpreTs);

                // Timebound
                let ts = key.timestamp().unwrap();
                if ts < since {
                    continue;
                }
                if ts >= until {
                    continue;
                }

                // Get at the record
                let record = unsafe { self.records.get_record_by_offset(offset as usize)? };

                // Screen and filter
                if screen(record) && filter.matches(record)? {
                    let _ = output.insert(record);
                }
            }
        }

        let events = output.iter().take(limit).copied().collect();

        Ok(events)
    }

    fn find_records_by_kinds<F>(
        &self,
        filter: &Filter,
        limit: usize,
        screen: F,
    ) -> Result<Vec<&Record>, Error>
    where
        F: Fn(&Record) -> bool,
    {
        // We rely on the BTreeSet to keep our events in order.
        // Because iter_kind uses `kind_eitherkey_ts_index`, we don't have
        // an easy way to walk through timestamps in order.
        // We can't even do limit until we collect all of them.
        // This is not very efficient, but it is hard to fix without a
        // different kind of indexing. This is a fallback/scrape anyway.

        let txn = self.indexes.read_txn()?;

        // We insert into a BTreeSet to keep them reverse time-ordered
        let mut output: BTreeSet<&Record> = BTreeSet::new();

        let since = match filter.get_element(FilterElementType::SINCE) {
            None => Timestamp::min(),
            Some(fe) => fe.since()?.unwrap_or(Timestamp::min()),
        };

        let until = match filter.get_element(FilterElementType::UNTIL) {
            None => Timestamp::max(),
            Some(fe) => fe.since()?.unwrap_or(Timestamp::max()),
        };

        // We can unwrap, because if we couldn't this function would not
        // have been called
        let iter = filter
            .get_element(FilterElementType::KINDS)
            .unwrap()
            .kinds()
            .unwrap();

        for kind in iter {
            for elem in self.indexes.iter_kind(&txn, kind)? {
                let (lmdbkey, offset) = elem?;
                let key = Key::from_bytes_and_kind(lmdbkey, KeyKind::KindPkpreTs);

                // Timebound
                let ts = key.timestamp().unwrap();
                if ts < since {
                    continue;
                }
                if ts >= until {
                    continue;
                }

                // Get at the record
                let record = unsafe { self.records.get_record_by_offset(offset as usize)? };

                // Screen and filter
                if screen(record) && filter.matches(record)? {
                    let _ = output.insert(record);
                }
            }
        }

        let events = output.iter().take(limit).copied().collect();

        Ok(events)
    }
}
