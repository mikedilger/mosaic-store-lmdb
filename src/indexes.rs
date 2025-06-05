use crate::Error;
use heed::byteorder::NativeEndian;
use heed::types::{Bytes, U64};
use heed::{
    Database, DatabaseFlags, Env, EnvFlags, EnvOpenOptions, RoIter, RoPrefix, RoTxn, RwTxn,
    WithoutTls,
};
use mosaic_core::{Id, Kind, PublicKey, Record, Reference, Tag, Timestamp};
use std::collections::HashMap;
use std::path::Path;

// We use only this many prefix bytes from tags and keys in the indexes to make them smaller.
// If not unique, that's ok we will just be scanning through a bit more.
const PREFIX: usize = 12;

/* Four indexes:
 *
 *    [ref]                           ref = 48 bytes of ID or Address
 *                                    USE: looking up by ID
 *                                    USE: looking up by Address
 *                                    USE: filter has a timestamp (because ID starts w/ timestamp)
 *
 *    [eitherkey + tagprefix + ts]    eitherkey = 12 bytes of key prefix
 *                                    tagprefix = 12 bytes of tag prefix
 *                                    ts = 6 bytes of reverse big-endian timestamp
 *                                    USE: filter has both eitherkey & tagprefix
 *                                    USE: filter has just eitherkey and no other index is better
 *                                         [SCRAPE]
 *
 *    [kind + eitherkey + ts]         kind = 2 bytes
 *                                    eitherkey = 12 bytes of key prefix
 *                                    ts = 6 bytes of reverse big-endian timestamp
 *                                    USE: filter has both kind & eitherkey
 *                                    USE: filter has just kind and no other index is better
 *                                         [SCRAPE]
 *
 *    [tagprefix + kind + ts]         tagprefix = 12 bytes of tag prefix
 *                                    kind = 2 bytes of kind
 *                                    ts = 6 bytes of reverse big-endian timestamp
 *                                    USE: filter has both tagprefix & kind
 *                                    USE: filter has just tagprefix and no other index is better
 *                                         [SCRAPE]
 *
 * Space used per event:   112 bytes + 104 bytes per tag
 *
 *     index by id:    key=48, value=8    perevent=1   56 bytes
 *     index by addr:  key=48, value=8    perevent=1   56 bytes
 *     author+tags:    key=30, value=8    perevent=T   38 bytes * T
 *     signing+tags:   key=30, value=8    perevent=T   38 bytes * T
 *     kind+author:    key=20, value=8    perevent=1   28 bytes
 *     kind+signing:   key=20, value=8    perevent=1   28 bytes
 *     tag+kind:       key=20, value=8    perevent=T   28 bytes * T
 */

/// Indexes
///
/// Note that key collisions are not catastrophic. We use DUP_SORT and DUP_FIXED to prevent
/// clobbers.
///
/// Note that we do not need a separate "timestamp" index, because every event is indexed by it's
/// Id which starts with a big-endian-reversed timestamp.  So we can just use the ref index.
///
/// Note that we do not need to index author and signing keys in separate indexes. Keys are unique
/// enough to not collide, and collisions aren't catastrophic.
///
/// Note that every index key ends in the timestamp.  This is so we can quickly further filter
/// within a time range (since, until).
///
/// Note that we don't use the full public key or full tags, but just the first 16 bytes.
/// DUP_SORT avoid collisions, but we may look up more than we were seeking. That is OK as long
/// as every lookup is followed by a check against the entire filter to remove false positives.
#[derive(Debug)]
pub(crate) struct Indexes {
    env: Env<WithoutTls>,
    general: Database<Bytes, Bytes>,
    ref_index: Database<Bytes, U64<NativeEndian>>,
    eitherkey_tag_id_index: Database<Bytes, U64<NativeEndian>>,
    kind_eitherkey_id_index: Database<Bytes, U64<NativeEndian>>,
    tag_kind_id_index: Database<Bytes, U64<NativeEndian>>,
    extra_tables: HashMap<&'static str, Database<Bytes, Bytes>>,
}

impl Indexes {
    pub(crate) fn new<P: AsRef<Path>>(
        directory: P,
        extra_table_names: &[&'static str],
        maximum_size_in_gigabytes: usize,
    ) -> Result<Indexes, Error> {
        let mut builder = EnvOpenOptions::new().read_txn_without_tls();
        unsafe {
            let _ = builder.flags(EnvFlags::NO_SYNC | EnvFlags::NO_META_SYNC);
        }
        let _ = builder
            .max_dbs(10 + extra_table_names.len() as u32)
            .map_size(1048576 * 1024 * maximum_size_in_gigabytes);

        let env = unsafe { builder.open(directory)? };

        // Open/Create maps
        let mut txn = env.write_txn()?;
        let general = env
            .database_options()
            .types::<Bytes, Bytes>()
            .create(&mut txn)?;
        let ref_index = env
            .database_options()
            .types::<Bytes, U64<NativeEndian>>()
            .name("ref_index")
            .create(&mut txn)?;
        let eitherkey_tag_id_index = env
            .database_options()
            .types::<Bytes, U64<NativeEndian>>()
            .flags(DatabaseFlags::DUP_SORT | DatabaseFlags::DUP_FIXED)
            .name("eitherkey_tag_id_index")
            .create(&mut txn)?;
        let kind_eitherkey_id_index = env
            .database_options()
            .types::<Bytes, U64<NativeEndian>>()
            .flags(DatabaseFlags::DUP_SORT | DatabaseFlags::DUP_FIXED)
            .name("kind_eitherkey_id_index")
            .create(&mut txn)?;
        let tag_kind_id_index = env
            .database_options()
            .types::<Bytes, U64<NativeEndian>>()
            .flags(DatabaseFlags::DUP_SORT | DatabaseFlags::DUP_FIXED)
            .name("tag_kind_id_index")
            .create(&mut txn)?;

        let mut extra_tables = HashMap::with_capacity(extra_table_names.len());
        for extra_table_name in extra_table_names.iter() {
            let table = env
                .database_options()
                .types::<Bytes, Bytes>()
                .name(extra_table_name)
                .create(&mut txn)?;
            let _ = extra_tables.insert(*extra_table_name, table);
        }

        txn.commit()?;

        let indexes = Indexes {
            env,
            general,
            ref_index,
            eitherkey_tag_id_index,
            kind_eitherkey_id_index,
            tag_kind_id_index,
            extra_tables,
        };

        Ok(indexes)
    }

    /// Sync the data to disk. This happens periodically, but sometimes it's useful to force
    /// it.
    pub(crate) fn sync(&self) -> Result<(), Error> {
        self.env.force_sync()?;
        Ok(())
    }

    pub(crate) fn close(self) -> Result<(), Error> {
        let Indexes {
            env, extra_tables, ..
        } = self;
        env.force_sync()?;
        drop(extra_tables);
        let closing_event = env.prepare_for_closing();
        closing_event.wait();
        Ok(())
    }

    /// Get a read transaction
    pub(crate) fn read_txn(&self) -> Result<RoTxn<WithoutTls>, Error> {
        Ok(self.env.read_txn()?)
    }

    /// Get a write transaction
    pub(crate) fn write_txn(&self) -> Result<RwTxn, Error> {
        Ok(self.env.write_txn()?)
    }

    /// Index a Record
    pub(crate) fn index(
        &self,
        txn: &mut RwTxn<'_>,
        record: &Record,
        offset: u64,
    ) -> Result<(), Error> {
        // Index by id (functionally also by be_reverse_timestamp)
        self.ref_index.put(txn, record.id().as_bytes(), &offset)?;

        // Index by address
        self.ref_index
            .put(txn, record.address().as_bytes(), &offset)?;

        // Index by author key and every tag
        for tag in record.tags() {
            let k = (record.author_public_key(), tag, record.timestamp()).to_index_bytes();
            self.eitherkey_tag_id_index.put(txn, &k, &offset)?;
        }

        // Index by signing key and every tag
        for tag in record.tags() {
            let k = (record.signing_public_key(), tag, record.timestamp()).to_index_bytes();
            self.eitherkey_tag_id_index.put(txn, &k, &offset)?;
        }

        // Index by kind and author key
        let k = (
            record.kind(),
            record.author_public_key(),
            record.timestamp(),
        )
            .to_index_bytes();
        self.kind_eitherkey_id_index.put(txn, &k, &offset)?;

        // Index by kind and signing key
        let k = (
            record.kind(),
            record.signing_public_key(),
            record.timestamp(),
        )
            .to_index_bytes();
        self.kind_eitherkey_id_index.put(txn, &k, &offset)?;

        // Index by every tag and kind
        for tag in record.tags() {
            let k = (tag, record.kind(), record.timestamp()).to_index_bytes();
            self.tag_kind_id_index.put(txn, &k, &offset)?;
        }

        Ok(())
    }

    /// Deindex a record
    pub(crate) fn deindex(
        &self,
        txn: &mut RwTxn<'_>,
        record: &Record,
        leave_in_ref_index_by_id: bool,
    ) -> Result<(), Error> {
        // Deindex by every tag and kind
        for tag in record.tags() {
            let k = (tag, record.kind(), record.timestamp()).to_index_bytes();
            let _ = self.tag_kind_id_index.delete(txn, &k)?;
        }

        // Deindex by kind and signing key
        let k = (
            record.kind(),
            record.signing_public_key(),
            record.timestamp(),
        )
            .to_index_bytes();
        let _ = self.kind_eitherkey_id_index.delete(txn, &k)?;

        // Deindex by kind and author key
        let k = (
            record.kind(),
            record.author_public_key(),
            record.timestamp(),
        )
            .to_index_bytes();
        let _ = self.kind_eitherkey_id_index.delete(txn, &k)?;

        // Deindex by signing key and every tag
        for tag in record.tags() {
            let k = (record.signing_public_key(), tag, record.timestamp()).to_index_bytes();
            let _ = self.eitherkey_tag_id_index.delete(txn, &k)?;
        }

        // Deindex by author key and every tag
        for tag in record.tags() {
            let k = (record.author_public_key(), tag, record.timestamp()).to_index_bytes();
            let _ = self.eitherkey_tag_id_index.delete(txn, &k)?;
        }

        // Deindex by address
        let _ = self.ref_index.delete(txn, record.address().as_bytes())?;

        if !leave_in_ref_index_by_id {
            // Deindex by id (functionally also by be_reverse_timestamp)
            let _ = self.ref_index.delete(txn, record.id().as_bytes())?;
        }

        Ok(())
    }

    /// Deindex an Id from the ref_index
    pub(crate) fn deindex_id(&self, txn: &mut RwTxn<'_>, id: Id) -> Result<(), Error> {
        let _ = self.ref_index.delete(txn, id.as_bytes())?;
        Ok(())
    }

    /// Get the offset from reference
    pub(crate) fn get_offset_by_ref(
        &self,
        txn: &RoTxn<'_>,
        reference: Reference,
    ) -> Result<Option<u64>, Error> {
        Ok(self.ref_index.get(txn, reference.as_bytes())?)
    }

    /// Get access to an extra table
    pub(crate) fn extra_table(&self, name: &'static str) -> Option<Database<Bytes, Bytes>> {
        self.extra_tables.get(name).copied()
    }

    /// Iterate through ref_index
    pub(crate) fn iter_refs<'a>(
        &'a self,
        txn: &'a RoTxn,
    ) -> Result<RoIter<'a, Bytes, U64<NativeEndian>>, Error> {
        Ok(self.ref_index.iter(txn)?)
    }

    /// Iterate through records of a given timestamp
    ///
    /// Keys will be IDs (starting with that timestamp), values will be Offsets
    pub(crate) fn iter_timestamp<'a>(
        &'a self,
        txn: &'a RoTxn,
        timestamp: Timestamp,
    ) -> Result<RoPrefix<'a, Bytes, U64<NativeEndian>>, Error> {
        Ok(self
            .ref_index
            .prefix_iter(txn, timestamp.to_inverse_bytes().as_slice())?)
    }

    /// Iterate through records of a given public key (author or signing)
    pub(crate) fn iter_eitherkey<'a>(
        &'a self,
        txn: &'a RoTxn,
        pubkey: PublicKey,
    ) -> Result<RoPrefix<'a, Bytes, U64<NativeEndian>>, Error> {
        Ok(self
            .eitherkey_tag_id_index
            .prefix_iter(txn, pubkey.as_bytes())?)
    }

    /// Iterate through records of a given public key (author and/or signing) and tagprefix
    pub(crate) fn iter_eitherkey_tag<'a>(
        &'a self,
        txn: &'a RoTxn,
        pubkey: PublicKey,
        tag: &Tag,
    ) -> Result<RoPrefix<'a, Bytes, U64<NativeEndian>>, Error> {
        let key = (pubkey, tag).to_index_bytes();
        Ok(self.eitherkey_tag_id_index.prefix_iter(txn, &key)?)
    }

    /// Iterate through records of a given kind
    pub(crate) fn iter_kind<'a>(
        &'a self,
        txn: &'a RoTxn,
        kind: Kind,
    ) -> Result<RoPrefix<'a, Bytes, U64<NativeEndian>>, Error> {
        Ok(self
            .kind_eitherkey_id_index
            .prefix_iter(txn, kind.0.to_be_bytes().as_slice())?)
    }

    /// Iterate through records of a given kind and public key (author and/or signing)
    pub(crate) fn iter_kind_eitherkey<'a>(
        &'a self,
        txn: &'a RoTxn,
        kind: Kind,
        pubkey: PublicKey,
    ) -> Result<RoPrefix<'a, Bytes, U64<NativeEndian>>, Error> {
        let key = (kind, pubkey).to_index_bytes();
        Ok(self.kind_eitherkey_id_index.prefix_iter(txn, &key)?)
    }

    /// Iterate through records of a given tag (prefix)
    pub(crate) fn iter_tag<'a>(
        &'a self,
        txn: &'a RoTxn,
        tag: &Tag,
    ) -> Result<RoPrefix<'a, Bytes, U64<NativeEndian>>, Error> {
        Ok(self.tag_kind_id_index.prefix_iter(txn, tag.as_bytes())?)
    }

    /// Iterate through records of a given tag (prefix) and kind
    pub(crate) fn iter_tag_kind<'a>(
        &'a self,
        txn: &'a RoTxn,
        tag: &Tag,
        kind: Kind,
    ) -> Result<RoPrefix<'a, Bytes, U64<NativeEndian>>, Error> {
        let k = (tag, kind).to_index_bytes();
        Ok(self.tag_kind_id_index.prefix_iter(txn, &k)?)
    }
}

pub(crate) trait IndexBytes {
    fn to_index_bytes(self) -> Vec<u8>;
}

impl IndexBytes for (PublicKey, &Tag) {
    fn to_index_bytes(self) -> Vec<u8> {
        let eitherkey = self.0;
        let tag = self.1;
        let mut key: Vec<u8> = vec![0; PREFIX + PREFIX];
        key[0..PREFIX].copy_from_slice(&eitherkey.as_bytes().as_slice()[..16]);
        let taglen = tag.as_bytes().len();
        if taglen >= PREFIX {
            key[PREFIX..PREFIX + PREFIX].copy_from_slice(&tag.as_bytes()[..16]);
        } else {
            key[PREFIX..PREFIX + taglen].copy_from_slice(tag.as_bytes());
            // leave the rest zeroes
        }
        key
    }
}

impl IndexBytes for (PublicKey, &Tag, Timestamp) {
    fn to_index_bytes(self) -> Vec<u8> {
        let eitherkey = self.0;
        let tag = self.1;
        let timestamp = self.2;
        let mut key: Vec<u8> = vec![0; PREFIX + PREFIX + 6];
        key[0..PREFIX].copy_from_slice(&eitherkey.as_bytes().as_slice()[..16]);
        let taglen = tag.as_bytes().len();
        if taglen >= PREFIX {
            key[PREFIX..PREFIX + PREFIX].copy_from_slice(&tag.as_bytes()[..16]);
        } else {
            key[PREFIX..PREFIX + taglen].copy_from_slice(tag.as_bytes());
            // leave the rest zeroes
        }
        key[PREFIX + PREFIX..].copy_from_slice(timestamp.to_inverse_bytes().as_slice());
        key
    }
}

impl IndexBytes for (Kind, PublicKey) {
    fn to_index_bytes(self) -> Vec<u8> {
        let kind = self.0;
        let eitherkey = self.1;
        let mut key: Vec<u8> = vec![0; 2 + PREFIX];
        key[0..2].copy_from_slice(kind.0.to_be_bytes().as_slice());
        key[2..2 + PREFIX].copy_from_slice(&eitherkey.as_bytes().as_slice()[..16]);
        key
    }
}

impl IndexBytes for (Kind, PublicKey, Timestamp) {
    fn to_index_bytes(self) -> Vec<u8> {
        let kind = self.0;
        let eitherkey = self.1;
        let timestamp = self.2;
        let mut key: Vec<u8> = vec![0; 2 + PREFIX + 6];
        key[0..2].copy_from_slice(kind.0.to_be_bytes().as_slice());
        key[2..2 + PREFIX].copy_from_slice(&eitherkey.as_bytes().as_slice()[..16]);
        key[2 + PREFIX..].copy_from_slice(timestamp.to_inverse_bytes().as_slice());
        key
    }
}

impl IndexBytes for (&Tag, Kind) {
    fn to_index_bytes(self) -> Vec<u8> {
        let tag = self.0;
        let kind = self.1;
        let mut key: Vec<u8> = vec![0; PREFIX + 2];
        let taglen = tag.as_bytes().len();
        if taglen >= PREFIX {
            key[0..PREFIX].copy_from_slice(&tag.as_bytes()[..16]);
        } else {
            key[0..taglen].copy_from_slice(tag.as_bytes());
        }
        key[PREFIX..PREFIX + 2].copy_from_slice(kind.0.to_be_bytes().as_slice());
        key
    }
}

impl IndexBytes for (&Tag, Kind, Timestamp) {
    fn to_index_bytes(self) -> Vec<u8> {
        let tag = self.0;
        let kind = self.1;
        let timestamp = self.2;
        let mut key: Vec<u8> = vec![0; PREFIX + 2];
        let taglen = tag.as_bytes().len();
        if taglen >= PREFIX {
            key[0..PREFIX].copy_from_slice(&tag.as_bytes()[..16]);
        } else {
            key[0..taglen].copy_from_slice(tag.as_bytes());
        }
        key[PREFIX..PREFIX + 2].copy_from_slice(kind.0.to_be_bytes().as_slice());
        key[PREFIX + 2..].copy_from_slice(timestamp.to_inverse_bytes().as_slice());
        key
    }
}
