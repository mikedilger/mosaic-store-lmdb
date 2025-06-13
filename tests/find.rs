use core::time::Duration;
use mosaic_core::{
    EMPTY_TAG_SET, Filter, FilterElement, Id, Kind, OwnedFilter, OwnedFilterElement, OwnedRecord,
    OwnedTag, OwnedTagSet, PublicKey, Record, RecordFlags, RecordParts, SecretKey, Tag, TagType,
    Timestamp,
};
use mosaic_store_lmdb::Store;
use rand::prelude::SliceRandom;
use rand::rngs::OsRng;

#[test]
fn test_find_by_kind() {
    let mut csprng = OsRng;

    let secret_key = SecretKey::generate(&mut csprng);

    let kinds = vec![
        Kind::from_bytes([0, 0, 0, 0, 99, 0, 1, 14]),
        Kind::from_bytes([0, 0, 0, 0, 99, 0, 2, 14]),
        Kind::from_bytes([0, 0, 0, 0, 99, 0, 3, 28]),
        Kind::from_bytes([0, 0, 0, 0, 99, 0, 4, 28]),
    ];

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
        tag_set: &*EMPTY_TAG_SET,
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

#[test]
fn test_find_by_pubkey() {
    let mut csprng = OsRng;

    let secret_keys = vec![
        SecretKey::generate(&mut csprng),
        SecretKey::generate(&mut csprng),
        SecretKey::generate(&mut csprng),
        SecretKey::generate(&mut csprng),
    ];

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
        kind: Kind::from_bytes([0, 0, 0, 0, 99, 0, 1, 14]),
        deterministic_nonce: None,
        timestamp: timestamps[0],
        flags: RecordFlags::empty(),
        tag_set: &*EMPTY_TAG_SET,
        payload: &[],
    };

    for i in 0..secret_keys.len() {
        for j in 0..timestamps.len() {
            parts.timestamp = timestamps[j];
            let r = OwnedRecord::new(&secret_keys[i], &parts).unwrap();
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
        // All but secret_keys[1]
        &OwnedFilterElement::new_author_keys(&[
            secret_keys[0].public(),
            secret_keys[2].public(),
            secret_keys[3].public(),
        ])
        .unwrap(),
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
            r.author_public_key() == secret_keys[1].public()
                || r.timestamp() == timestamps[0]
                || r.timestamp() == timestamps[7]
        }),
        false
    );

    // Make sure the timestamps are all in order, newest to oldest
    assert!(found_records.is_sorted_by(|a, b| a.timestamp() >= b.timestamp()));
}
