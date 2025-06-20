// Copyright 2025 mosaic-store-lmdb Developers
// Licensed under the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>
// This file may not be copied, modified, or distributed except according to those terms.

//! Defines a Store type for storing, indexing, and accessing mosaic records.
//!
//! Is rather simple and direct, and not yet implementing any code related to replacements
//! or deletions.
//!
//! Achieves good performance by having the Indexes point at offsets into a record map
//! rather than to an ID to avoid additional tree searches during lookups.
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
pub use records::RecordsIter;

mod indexes;
use indexes::Indexes;

pub use heed;
use heed::types::Bytes;
use heed::{Database, RoTxn, RwTxn, WithoutTls};

use itertools::Itertools;
use mosaic_core::{Filter, FilterElementType, Id, Record, Reference, Timestamp};
use sorted_iter::SortedIterator;
use sorted_iter::assume::AssumeSortedByItemExt;
use std::cmp::Ordering;
use std::fs;
use std::path::{Path, PathBuf};

macro_rules! iter_over_records_with_keys {
    ($self:ident, $filter:ident, $since:ident, $until:ident, $txn:ident, $screen:ident, $errors:expr) => {
        $filter
            .get_element(FilterElementType::AUTHOR_KEYS)
            .unwrap_or_else(|| // &FilterElement
                $filter
                    .get_element(FilterElementType::SIGNING_KEYS)
                    .unwrap())
            .keys() // Option<FeKeysIter>
            .unwrap() // FeKeysIter
            .filter_map(|pubkey| {
                // for each PublicKey
                $self.indexes
                    .iter_pubkey(&$txn, pubkey, $since, $until) // Result<RoRange<...>, Error>
                    .map_err(|e| $errors.push(e)) // Result<RoRange<...>, ()>
                    .ok() // Option<RoRange<...>>
            }) // RoRange<...>
            .map(|rorange| {
                // FIXME, we should detect heed errors here.
                rorange.take_while(|r| r.is_ok()).map(|r| r.unwrap())
            })
            .kmerge_by(|a, b| a.0.timestamp >= b.0.timestamp) // merge multiple sorted iterators into one sorted interator
            .unique()
            .filter_map(|(_, offset)| {
                // FIXME, detect errors
                let record = unsafe { $self.records.get_record_by_offset(offset as usize).unwrap() };

                if $screen(record) && $filter.matches(record).unwrap() {
                    Some(RecordWrapper(record))
                } else {
                    None
                }
            })
            .assume_sorted_by_item()
    };
}

macro_rules! iter_over_records_with_kinds {
    ($self:ident, $filter:ident, $since:ident, $until:ident, $txn:ident, $screen:ident, $errors:expr) => {
        $filter
            .get_element(FilterElementType::KINDS) // Option<&FilterElement>
            .unwrap() // &FilterElement
            .kinds() // Option<FeKindsIter>
            .unwrap() // FeKindsIter
            .filter_map(|kind| {
                // for each Kind
                $self.indexes
                    .iter_kind(&$txn, kind, $since, $until) // Result<RoRange<...>, Error>
                    .map_err(|e| $errors.push(e)) // Result<RoRange<...>, ()>
                    .ok() // Option<RoRange<...>>
            }) // RoRange<...>
            .map(|rorange| {
                // FIXME, we should detect heed errors here.
                rorange.take_while(|r| r.is_ok()).map(|r| r.unwrap())
            })
            .kmerge_by(|a, b| a.0.timestamp >= b.0.timestamp) // merge multiple sorted iterators into one sorted interator
            .unique()
            .filter_map(|(_, offset)| {
                // FIXME, detect errors
                let record = unsafe { $self.records.get_record_by_offset(offset as usize).unwrap() };

                if $screen(record) && $filter.matches(record).unwrap() {
                    Some(RecordWrapper(record))
                } else {
                    None
                }
            })
            .assume_sorted_by_item()
    };
}

macro_rules! iter_over_records_with_tags {
    ($self:ident, $filter:ident, $since:ident, $until:ident, $txn:ident, $screen:ident, $errors:expr) => {
        $filter
            .get_element(FilterElementType::INCLUDED_TAGS)
            .unwrap() // &FilterElement
            .tags() // Option<FeTagsIter>
            .unwrap() // FeTagsIter
            .filter_map(|tag| {
                // for each Tag
                $self.indexes
                    .iter_tag(&$txn, tag, $since, $until) // Result<RoRange<...>, Error>
                    .map_err(|e| $errors.push(e)) // Result<RoRange<...>, ()>
                    .ok() // Option<RoRange<...>>
            }) // RoRange<...>
            .map(|rorange| {
                // FIXME, we should detect heed errors here.
                rorange.take_while(|r| r.is_ok()).map(|r| r.unwrap())
            })
            .kmerge_by(|a, b| a.0.timestamp >= b.0.timestamp) // merge multiple sorted iterators into one sorted interator
            .unique()
            .filter_map(|(_, offset)| {
                // FIXME, detect errors
                let record = unsafe { $self.records.get_record_by_offset(offset as usize).unwrap() };

                if $screen(record) && $filter.matches(record).unwrap() {
                    Some(RecordWrapper(record))
                } else {
                    None
                }
            })
            .assume_sorted_by_item()
    };
}

/// A Mosaic Record storage system.
///
/// The core functionality includes `new()`, `store_record()` and `find_records()`
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
    pub fn store_record(&self, record: &Record) -> Result<usize, Error> {
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
        let offset = self.records.store_record(record)?;

        // Index the record
        self.indexes.index(&mut txn, record, offset as u64)?;

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
        self.indexes.deindex(txn, record, offset as u64, false)?;
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

    /// Iterate through all records. This is expensive.
    pub fn all_records(&self) -> RecordsIter<'_> {
        self.records.iter()
    }

    /// Find all records that match the `Filter` and also pass the screen function.
    ///
    /// `allow_scraping` searches even when only a single narrow filter is present.
    /// Otherwise, either timestamp or at least two narrow filters are required.
    ///
    /// # Errors
    ///
    /// This function returns Err if the filter has no narrow elements at all, or if it
    /// only has one and `allow_scraping` is false, or if there is a deeper error in
    /// the storage mechanism. Some deeper errors are currently swallowed.
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

        let since = match filter.get_element(FilterElementType::SINCE) {
            None => Timestamp::min(),
            Some(fe) => fe.since()?.unwrap_or(Timestamp::min()),
        };

        let until = match filter.get_element(FilterElementType::UNTIL) {
            None => Timestamp::max(),
            Some(fe) => fe.until()?.unwrap_or(Timestamp::max()),
        };

        if has_timestamps {
            self.find_records_by_timestamps(filter, limit, screen)
        } else if has_keys && has_tags {
            self.find_records_by_keys_and_tags(filter, since, until, limit, screen)
        } else if has_tags && has_kinds {
            self.find_records_by_tags_and_kinds(filter, since, until, limit, screen)
        } else if has_keys && has_kinds {
            self.find_records_by_keys_and_kinds(filter, since, until, limit, screen)
        } else if allow_scraping && has_tags {
            self.find_records_by_tags(filter, since, until, limit, screen)
        } else if allow_scraping && has_keys {
            self.find_records_by_keys(filter, since, until, limit, screen)
        } else if allow_scraping && has_kinds {
            self.find_records_by_kinds(filter, since, until, limit, screen)
        } else {
            Err(InnerError::FilterTooWide.into())
        }
    }

    fn find_records_by_timestamps<F>(
        &self,
        filter: &Filter,
        limit: usize,
        screen: F,
    ) -> Result<Vec<&Record>, Error>
    where
        F: Fn(&Record) -> bool,
    {
        let txn = self.indexes.read_txn()?;

        let mut errors: Vec<Error> = vec![];

        let records = filter
            .get_element(FilterElementType::TIMESTAMPS)
            .unwrap()
            .timestamps() // Option<FeTimestampsIter>
            .unwrap() // FeTimestampsIter
            .filter_map(|timestamp| {
                // for each Timestamp
                self.indexes
                    .iter_timestamp(&txn, timestamp) // Result<RoPrefix<...>, Error>
                    .map_err(|e| errors.push(e)) // Result<RoPrefix<...>, ()>
                    .ok() // Option<RoPrefix<...>>
            }) // RoRange<...>
            .map(|rorange| {
                // FIXME, we should detect heed errors here.
                rorange.take_while(|r| r.is_ok()).map(|r| r.unwrap())
            })
            // keys in the ref_index are IDs, we sort them backwards
            .kmerge_by(|a, b| a >= b) // merge multiple sorted iterators into one sorted interator
            .unique()
            .filter_map(|(_, offset)| {
                // FIXME, detect errors
                let record = unsafe { self.records.get_record_by_offset(offset as usize).unwrap() };

                if screen(record) && filter.matches(record).unwrap() {
                    Some(record)
                } else {
                    None
                }
            })
            .take(limit)
            .collect();

        if let Some(e) = errors.pop() {
            return Err(e);
        }

        Ok(records)
    }

    fn find_records_by_keys_and_tags<F>(
        &self,
        filter: &Filter,
        since: Timestamp,
        until: Timestamp,
        limit: usize,
        screen: F,
    ) -> Result<Vec<&Record>, Error>
    where
        F: Fn(&Record) -> bool,
    {
        let txn = self.indexes.read_txn()?;

        let mut errors: Vec<Error> = vec![];

        let by_keys =
            iter_over_records_with_keys!(self, filter, since, until, txn, screen, &mut errors);
        let by_tags =
            iter_over_records_with_tags!(self, filter, since, until, txn, screen, &mut errors);

        let records = by_keys
            .intersection(by_tags)
            .map(|rw| rw.0)
            .take(limit)
            .collect();

        if let Some(e) = errors.pop() {
            return Err(e);
        }

        Ok(records)
    }

    fn find_records_by_tags_and_kinds<F>(
        &self,
        filter: &Filter,
        since: Timestamp,
        until: Timestamp,
        limit: usize,
        screen: F,
    ) -> Result<Vec<&Record>, Error>
    where
        F: Fn(&Record) -> bool,
    {
        let txn = self.indexes.read_txn()?;

        let mut errors: Vec<Error> = vec![];

        let by_tags =
            iter_over_records_with_tags!(self, filter, since, until, txn, screen, &mut errors);
        let by_kinds =
            iter_over_records_with_kinds!(self, filter, since, until, txn, screen, &mut errors);

        let records = by_tags
            .intersection(by_kinds)
            .map(|rw| rw.0)
            .take(limit)
            .collect();

        if let Some(e) = errors.pop() {
            return Err(e);
        }

        Ok(records)
    }

    fn find_records_by_keys_and_kinds<F>(
        &self,
        filter: &Filter,
        since: Timestamp,
        until: Timestamp,
        limit: usize,
        screen: F,
    ) -> Result<Vec<&Record>, Error>
    where
        F: Fn(&Record) -> bool,
    {
        let txn = self.indexes.read_txn()?;

        let mut errors: Vec<Error> = vec![];

        let by_keys =
            iter_over_records_with_keys!(self, filter, since, until, txn, screen, &mut errors);
        let by_kinds =
            iter_over_records_with_kinds!(self, filter, since, until, txn, screen, &mut errors);

        let records = by_keys
            .intersection(by_kinds)
            .map(|rw| rw.0)
            .take(limit)
            .collect();

        if let Some(e) = errors.pop() {
            return Err(e);
        }

        Ok(records)
    }

    fn find_records_by_tags<F>(
        &self,
        filter: &Filter,
        since: Timestamp,
        until: Timestamp,
        limit: usize,
        screen: F,
    ) -> Result<Vec<&Record>, Error>
    where
        F: Fn(&Record) -> bool,
    {
        let txn = self.indexes.read_txn()?;

        let mut errors: Vec<Error> = vec![];

        let records =
            iter_over_records_with_tags!(self, filter, since, until, txn, screen, &mut errors)
                .map(|rw| rw.0)
                .take(limit)
                .collect();

        if let Some(e) = errors.pop() {
            return Err(e);
        }

        Ok(records)
    }

    fn find_records_by_keys<F>(
        &self,
        filter: &Filter,
        since: Timestamp,
        until: Timestamp,
        limit: usize,
        screen: F,
    ) -> Result<Vec<&Record>, Error>
    where
        F: Fn(&Record) -> bool,
    {
        let txn = self.indexes.read_txn()?;

        let mut errors: Vec<Error> = vec![];

        let records =
            iter_over_records_with_keys!(self, filter, since, until, txn, screen, &mut errors)
                .map(|rw| rw.0)
                .take(limit)
                .collect();

        if let Some(e) = errors.pop() {
            return Err(e);
        }

        Ok(records)
    }

    fn find_records_by_kinds<F>(
        &self,
        filter: &Filter,
        since: Timestamp,
        until: Timestamp,
        limit: usize,
        screen: F,
    ) -> Result<Vec<&Record>, Error>
    where
        F: Fn(&Record) -> bool,
    {
        let txn = self.indexes.read_txn()?;

        let mut errors: Vec<Error> = vec![];

        let records =
            iter_over_records_with_kinds!(self, filter, since, until, txn, screen, &mut errors)
                .map(|rw| rw.0)
                .take(limit)
                .collect();

        if let Some(e) = errors.pop() {
            return Err(e);
        }

        Ok(records)
    }
}

// We use this wrapper that sorts in reverse time order in order to use
// the sorted_iter crate's intersection()
#[derive(Debug, PartialEq, Eq)]
struct RecordWrapper<'a>(&'a Record);

impl PartialOrd for RecordWrapper<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RecordWrapper<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        // We sort in backwards timestamp order
        other.0.timestamp().cmp(&self.0.timestamp())
    }
}
