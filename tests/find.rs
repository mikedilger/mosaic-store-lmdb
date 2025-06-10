use core::time::Duration;
use mosaic_core::{
    Filter, FilterElement, Id, Kind, OwnedFilter, OwnedFilterElement, OwnedRecord, PublicKey,
    Record, RecordFlags, RecordParts, SecretKey, Tag, Timestamp,
};
use mosaic_store_lmdb::Store;
use rand::prelude::SliceRandom;
use rand::rngs::OsRng;

#[test]
fn test_find_by_kind() {
    let mut csprng = OsRng;

    let secret_key = SecretKey::generate(&mut csprng);

    let kinds = vec![Kind(1), Kind(2), Kind(3), Kind(4)];

    let timestamps = vec![
        Timestamp::from_nanoseconds(1749511490000000000).unwrap(),
        Timestamp::from_nanoseconds(1749511491111100000).unwrap(),
        Timestamp::from_nanoseconds(1749511492222200000).unwrap(),
        Timestamp::from_nanoseconds(1749511493333300000).unwrap(),
        Timestamp::from_nanoseconds(1749511494444400000).unwrap(),
        Timestamp::from_nanoseconds(1749511495555500000).unwrap(),
        Timestamp::from_nanoseconds(1749511496666600000).unwrap(),
        Timestamp::from_nanoseconds(1749511497777700000).unwrap(),
    ];

    let mut all_records: Vec<OwnedRecord> = vec![];

    let mut parts = RecordParts {
        kind: kinds[0],
        deterministic_nonce: None,
        timestamp: timestamps[0],
        flags: RecordFlags::empty(),
        tags_bytes: &[],
        payload: &[],
    };

    for i in 0..kinds.len() {
        for j in 0..timestamps.len() {
            parts.kind = kinds[i];
            parts.timestamp = timestamps[j];
            let r = OwnedRecord::new(&secret_key, &parts).unwrap();
            all_records.push(r);
        }
    }

    all_records.shuffle(&mut csprng);

    assert_eq!(all_records.len(), 4 * 8);

    let tempdir = tempfile::tempdir().unwrap();
    let store = Store::new(tempdir, vec![], 2).unwrap();

    for r in all_records.iter() {
        store.store_record(&r).unwrap();
    }

    assert_eq!(store.all_records().count(), 4 * 8);

    let filter = OwnedFilter::new(&[
        // All but Kind[1]
        &OwnedFilterElement::new_kinds(&[kinds[0], kinds[2], kinds[3]]).unwrap(),
        // All but first timestamp
        &OwnedFilterElement::new_since(timestamps[1]),
        // All but last timestamp
        &OwnedFilterElement::new_until(timestamps[6]),
    ])
    .unwrap();

    let found_records = store.find_records(&filter, 100, |_| true, true).unwrap();

    // Make sure we get the right number of records
    assert_eq!(found_records.len(), 3 * 6);

    // Make sure we get no records that are outside of our specification
    assert_eq!(
        found_records.iter().any(|r| {
            r.kind() == kinds[1] || r.timestamp() == timestamps[0] || r.timestamp() == timestamps[7]
        }),
        false
    );

    // Make sure the timestamps are all in order, newest to oldest
    assert!(found_records.is_sorted_by(|a, b| a.timestamp() >= b.timestamp()));
}
