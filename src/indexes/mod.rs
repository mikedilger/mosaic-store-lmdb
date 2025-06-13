use crate::Error;
use heed::byteorder::NativeEndian;
use heed::types::{Bytes, U64};
use heed::{
    Database, DatabaseFlags, Env, EnvFlags, EnvOpenOptions, RoIter, RoPrefix, RoRange, RoTxn,
    RwTxn, WithoutTls,
};
use mosaic_core::{Id, Kind, PublicKey, Record, Reference, Tag, Timestamp};
use std::collections::HashMap;
use std::path::Path;

mod keys;
pub(crate) use keys::{KindRevstamp, KindRevstampCodec};
pub(crate) use keys::{PrefixRevstamp, PrefixRevstampCodec};

/* Four indexes:
 *
 *    [ref]                           ref = 48 bytes of ID or Address
 *                                    USE: looking up by ID
 *                                    USE: looking up by Address
 *                                    USE: filter has a timestamp (because ID starts w/ timestamp)
 *
 *    [pubkey + rts]                  pubkey = 12 bytes of key prefix
 *                                    rts = 8 bytes of reverse big-endian timestamp
 *
 *    [kind + rts]                    kind = 8 bytes
 *                                    rts = 8 bytes of reverse big-endian timestamp
 *
 *    [tagprefix + rts]               tagprefix = 12 bytes of tag prefix
 *                                    rts = 8 bytes of reverse big-endian timestamp
 *
 * Space used per event:   138 + 84T
 *
 *     index by id:    key=48, value=8    perevent=1   56 bytes
 *     index by addr:  key=48, value=8    perevent=1   56 bytes
 *     author:         key=20, value=8    perevent=T   28 bytes * T
 *     signing:        key=20, value=8    perevent=T   28 bytes * T  [unless same as author]
 *     kind:           key=16, value=8    perevent=1   24 bytes
 *     tag:            key=20, value=8    perevent=T   28 bytes * T
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
/// Note that we don't use the full public key or full tags, but just the first 12 bytes.
/// DUP_SORT avoids collisions, but we may look up more than we were seeking. That is OK as long
/// as every lookup is followed by a check against the entire filter to remove false positives.
#[derive(Debug)]
pub(crate) struct Indexes {
    env: Env<WithoutTls>,
    general: Database<Bytes, Bytes>,
    ref_index: Database<Bytes, U64<NativeEndian>>,
    pubkey_rts_index: Database<PrefixRevstampCodec, U64<NativeEndian>>,
    kind_rts_index: Database<KindRevstampCodec, U64<NativeEndian>>,
    tag_rts_index: Database<PrefixRevstampCodec, U64<NativeEndian>>,
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
        let pubkey_rts_index = env
            .database_options()
            .types::<PrefixRevstampCodec, U64<NativeEndian>>()
            .flags(DatabaseFlags::DUP_SORT | DatabaseFlags::DUP_FIXED)
            .name("pubkey_rts_index")
            .create(&mut txn)?;
        let kind_rts_index = env
            .database_options()
            .types::<KindRevstampCodec, U64<NativeEndian>>()
            .flags(DatabaseFlags::DUP_SORT | DatabaseFlags::DUP_FIXED)
            .name("kind_rts_index")
            .create(&mut txn)?;
        let tag_rts_index = env
            .database_options()
            .types::<PrefixRevstampCodec, U64<NativeEndian>>()
            .flags(DatabaseFlags::DUP_SORT | DatabaseFlags::DUP_FIXED)
            .name("tag_rts_index")
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
            pubkey_rts_index,
            kind_rts_index,
            tag_rts_index,
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
        // Index by id (functionally also by timestamp)
        self.ref_index.put(txn, record.id().as_bytes(), &offset)?;

        // Index by address
        self.ref_index
            .put(txn, record.address().as_bytes(), &offset)?;

        // Index by author key
        let mut prts = PrefixRevstamp {
            prefix: record.author_public_key().as_bytes()[..12]
                .try_into()
                .unwrap(),
            timestamp: record.timestamp(),
        };
        self.pubkey_rts_index.put(txn, &prts, &offset)?;

        // Index by signing key
        if record.signing_public_key() != record.author_public_key() {
            prts.set_prefix_from_pubkey(record.signing_public_key());
            self.pubkey_rts_index.put(txn, &prts, &offset)?;
        }

        // Index by kind
        let krts = KindRevstamp {
            kind: record.kind(),
            timestamp: record.timestamp(),
        };
        self.kind_rts_index.put(txn, &krts, &offset)?;

        // Index by every tag
        for tag in record.tag_set() {
            prts.set_prefix_from_tag(tag);
            self.tag_rts_index.put(txn, &prts, &offset)?;
        }

        Ok(())
    }

    /// Deindex a record
    pub(crate) fn deindex(
        &self,
        txn: &mut RwTxn<'_>,
        record: &Record,
        offset: u64,
        leave_in_ref_index_by_id: bool,
    ) -> Result<(), Error> {
        let mut prts = PrefixRevstamp {
            prefix: [0; 12],
            timestamp: record.timestamp(),
        };

        // Deindex by every tag
        for tag in record.tag_set() {
            prts.set_prefix_from_tag(tag);
            let _ = self
                .tag_rts_index
                .delete_one_duplicate(txn, &prts, &offset)?;
        }

        // Deindex by kind
        let krts = KindRevstamp {
            kind: record.kind(),
            timestamp: record.timestamp(),
        };
        let _ = self
            .kind_rts_index
            .delete_one_duplicate(txn, &krts, &offset)?;

        // Deindex by signing key
        if record.signing_public_key() != record.author_public_key() {
            prts.set_prefix_from_pubkey(record.signing_public_key());
            let _ = self
                .pubkey_rts_index
                .delete_one_duplicate(txn, &prts, &offset)?;
        }

        // Deindex by author key
        prts.set_prefix_from_pubkey(record.author_public_key());
        let _ = self
            .pubkey_rts_index
            .delete_one_duplicate(txn, &prts, &offset)?;

        // Deindex by address
        let _ = self.ref_index.delete(txn, record.address().as_bytes())?;

        // Deindex by id
        if !leave_in_ref_index_by_id {
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
            .prefix_iter(txn, timestamp.to_bytes().as_slice())?)
    }

    /// Iterate through records of a given public key (author or signing)
    pub(crate) fn iter_pubkey<'a>(
        &'a self,
        txn: &'a RoTxn,
        pubkey: PublicKey,
        since: Timestamp,
        until: Timestamp,
    ) -> Result<RoRange<'a, PrefixRevstampCodec, U64<NativeEndian>>, Error> {
        let prefix: [u8; 12] = pubkey.as_bytes()[..12].try_into().unwrap();

        let start = PrefixRevstamp {
            prefix,
            timestamp: until,
        };

        let end = PrefixRevstamp {
            prefix,
            timestamp: since,
        };

        let range = start..=end;

        Ok(self.pubkey_rts_index.range(txn, &range)?)
    }

    /// Iterate through records of a given kind
    pub(crate) fn iter_kind<'a>(
        &'a self,
        txn: &'a RoTxn,
        kind: Kind,
        since: Timestamp,
        until: Timestamp,
    ) -> Result<RoRange<'a, KindRevstampCodec, U64<NativeEndian>>, Error> {
        let start = KindRevstamp {
            kind,
            timestamp: until,
        };

        let end = KindRevstamp {
            kind,
            timestamp: since,
        };

        let range = start..=end;

        Ok(self.kind_rts_index.range(txn, &range)?)
    }

    /// Iterate through records of a given tag (prefix)
    pub(crate) fn iter_tag<'a>(
        &'a self,
        txn: &'a RoTxn,
        tag: &Tag,
        since: Timestamp,
        until: Timestamp,
    ) -> Result<RoRange<'a, PrefixRevstampCodec, U64<NativeEndian>>, Error> {
        let prefix = keys::tag_to_prefix(tag);

        let start = PrefixRevstamp {
            prefix,
            timestamp: until,
        };

        let end = PrefixRevstamp {
            prefix,
            timestamp: since,
        };

        let range = start..=end;

        Ok(self.tag_rts_index.range(txn, &range)?)
    }
}
