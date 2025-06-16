use lazy_static::lazy_static;
use mosaic_core::{
    EMPTY_TAG_SET, Kind, OwnedFilter, OwnedFilterElement, OwnedRecord, OwnedTag, OwnedTagSet,
    PublicKey, Record, RecordFlags, RecordParts, SecretKey, Tag, TagType, Timestamp,
};
use mosaic_store_lmdb::Store;
use rand::prelude::SliceRandom;
use rand::rngs::OsRng;

struct Data {
    secret_keys: Vec<SecretKey>,
    kinds: Vec<Kind>,
    timestamps: Vec<Timestamp>,
    tags: Vec<OwnedTag>,
    records: Vec<OwnedRecord>,
    store: Store,
}

lazy_static! {
    static ref DATA: Data = {
        let mut csprng = OsRng;

        let secret_keys = vec![
            SecretKey::generate(&mut csprng),
            SecretKey::generate(&mut csprng),
            SecretKey::generate(&mut csprng),
            SecretKey::generate(&mut csprng),
        ];

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

        let tags = vec![
            OwnedTag::new_notify_public_key(&secret_keys[1].public()),
            OwnedTag::new_nostr_sister(&[0; 32]),
            OwnedTag::new(TagType(100), b"testing").unwrap(),
            OwnedTag::new(TagType(101), b"more testing").unwrap(),
        ];

        let mut records: Vec<OwnedRecord> = vec![];

        let parts = RecordParts {
            kind: kinds[0],
            deterministic_nonce: None,
            timestamp: timestamps[0],
            flags: RecordFlags::empty(),
            tag_set: &*EMPTY_TAG_SET,
            payload: &[],
        };

        for secret_key_index in 0..secret_keys.len() {
            for kind_index in 0..kinds.len() {
                for timestamp_index in 0..timestamps.len() {
                    for tag_index in 0..tags.len() - 1 {
                        let mut parts = parts.clone();
                        parts.kind = kinds[kind_index];
                        parts.timestamp = timestamps[timestamp_index];
                        let tagset = OwnedTagSet::from_tags(
                            tags.iter().map(|t| &**t).skip(tag_index).take(2),
                        );
                        parts.tag_set = &tagset;
                        let r = OwnedRecord::new(&secret_keys[secret_key_index], &parts).unwrap();
                        records.push(r);
                    }
                }
            }
        }

        records.shuffle(&mut csprng);

        let tempdir = tempfile::tempdir().unwrap();
        let store = Store::new(tempdir, vec![], 2).unwrap();
        for r in records.iter() {
            store.store_record(&r).unwrap();
        }

        assert_eq!(records.len(), 4 * 4 * 8 * 3);
        assert_eq!(store.all_records().count(), 4 * 4 * 8 * 3);

        Data {
            secret_keys,
            kinds,
            timestamps,
            tags,
            records,
            store,
        }
    };
}

fn verify_find_output(
    found_records: &[&Record],
    expected_len: usize,
    missing_pubkeys: &[PublicKey],
    missing_kinds: &[Kind],
    missing_timestamps: &[Timestamp],
) {
    // Make sure we get the right number of records
    assert_eq!(found_records.len(), expected_len);

    // Make sure the timestamps are all in order, newest to oldest
    assert!(found_records.is_sorted_by(|a, b| a.timestamp() >= b.timestamp()));

    // Make sure we get no records with the forbidden data
    assert_eq!(
        found_records.iter().any(|r| {
            missing_pubkeys.contains(&r.author_public_key())
                || missing_kinds.contains(&r.kind())
                || missing_timestamps.contains(&r.timestamp())
        }),
        false
    );

    // Make sure all the records are distinct
    let mut v1 = found_records.to_vec();
    let v2 = v1.clone();
    v1.dedup();
    assert_eq!(v1, v2);
}

#[test]
fn test_find_by_kinds() {
    let filter = OwnedFilter::new(&[
        // All but Kind[1]
        &OwnedFilterElement::new_kinds(&[DATA.kinds[0], DATA.kinds[2], DATA.kinds[3]]).unwrap(),
        // All but first timestamp
        &OwnedFilterElement::new_since(DATA.timestamps[1]),
        // All but last timestamp
        &OwnedFilterElement::new_until(DATA.timestamps[6]),
    ])
    .unwrap();

    let found_records = DATA
        .store
        .find_records(&filter, 300, |_| true, true)
        .unwrap();

    verify_find_output(
        found_records.as_slice(),
        4 * 3 * 6 * 3,
        &[],
        &[DATA.kinds[1]],
        &[DATA.timestamps[0], DATA.timestamps[7]],
    );
}

#[test]
fn test_find_by_keys() {
    let filter = OwnedFilter::new(&[
        // All but secret_keys[1] and secret_keys[3]
        &OwnedFilterElement::new_author_keys(&[
            DATA.secret_keys[0].public(),
            DATA.secret_keys[2].public(),
        ])
        .unwrap(),
        // All but first timestamp
        &OwnedFilterElement::new_since(DATA.timestamps[1]),
        // All but last timestamp
        &OwnedFilterElement::new_until(DATA.timestamps[6]),
    ])
    .unwrap();

    let found_records = DATA
        .store
        .find_records(&filter, 300, |_| true, true)
        .unwrap();

    verify_find_output(
        found_records.as_slice(),
        2 * 4 * 6 * 3,
        &[DATA.secret_keys[1].public(), DATA.secret_keys[3].public()],
        &[],
        &[DATA.timestamps[0], DATA.timestamps[7]],
    );
}

#[test]
fn test_find_by_tags() {
    let elements = vec![
        // Only tag 3
        OwnedFilterElement::new_included_tags(&[&DATA.tags[3]]).unwrap(),
        // All but first timestamp
        OwnedFilterElement::new_since(DATA.timestamps[1]),
        // All but last timestamp
        OwnedFilterElement::new_until(DATA.timestamps[6]),
    ];

    let filter = OwnedFilter::new(&*elements).unwrap();

    let found_records = DATA
        .store
        .find_records(&filter, 100, |_| true, true)
        .unwrap();

    verify_find_output(
        found_records.as_slice(),
        4 * 4 * 6 * 1,
        &[],
        &[],
        &[DATA.timestamps[0], DATA.timestamps[7]],
    );

    // Make sure we get no records that include tag 0 or tag 1
    assert_eq!(
        found_records.iter().any(|r| {
            r.tag_set()
                .iter()
                .any(|t| *t == *DATA.tags[0] || *t == *DATA.tags[1])
        }),
        false
    );
}

#[test]
fn test_find_by_keys_and_kinds() {
    let filter = OwnedFilter::new(&[
        // 2 secret keys
        &OwnedFilterElement::new_author_keys(&[
            DATA.secret_keys[0].public(),
            DATA.secret_keys[2].public(),
        ])
        .unwrap(),
        // 3 kinds
        &OwnedFilterElement::new_kinds(&[DATA.kinds[0], DATA.kinds[2], DATA.kinds[3]]).unwrap(),
        // Timestamps including 2,3,4,5,6
        &OwnedFilterElement::new_since(DATA.timestamps[2]),
        &OwnedFilterElement::new_until(DATA.timestamps[6]),
    ])
    .unwrap();

    let found_records = DATA
        .store
        .find_records(&filter, 300, |_| true, true)
        .unwrap();

    verify_find_output(
        found_records.as_slice(),
        2 * 3 * 5 * 3,
        &[DATA.secret_keys[1].public(), DATA.secret_keys[3].public()],
        &[DATA.kinds[1]],
        &[DATA.timestamps[0], DATA.timestamps[1], DATA.timestamps[7]],
    );
}

#[test]
fn test_find_by_tags_and_kinds() {
    let elements = vec![
        // Only tag 3
        OwnedFilterElement::new_included_tags(&[&DATA.tags[3]]).unwrap(),
        // 3 kinds
        OwnedFilterElement::new_kinds(&[DATA.kinds[0], DATA.kinds[2], DATA.kinds[3]]).unwrap(),
        // All but first timestamp
        OwnedFilterElement::new_since(DATA.timestamps[1]),
        // All but last timestamp
        OwnedFilterElement::new_until(DATA.timestamps[5]),
    ];

    let filter = OwnedFilter::new(&*elements).unwrap();

    let found_records = DATA
        .store
        .find_records(&filter, 300, |_| true, true)
        .unwrap();

    verify_find_output(
        found_records.as_slice(),
        4 * 3 * 5 * 1, // 4 keys, 3 kinds, 5 timestamps, 1 tag
        &[],
        &[DATA.kinds[1]],
        &[DATA.timestamps[0], DATA.timestamps[6], DATA.timestamps[7]],
    );

    // Make sure we get no records that include tag 0 or tag 1 (tag2 and tag3 sometimes go together)
    assert_eq!(
        found_records.iter().any(|r| {
            r.tag_set()
                .iter()
                .any(|t| *t == *DATA.tags[0] || *t == *DATA.tags[1])
        }),
        false
    );
}

#[test]
fn test_find_by_keys_and_tags() {
    let elements = vec![
        // 2 secret keys
        OwnedFilterElement::new_author_keys(&[
            DATA.secret_keys[0].public(),
            DATA.secret_keys[2].public(),
        ])
        .unwrap(),
        // Only tag 3
        OwnedFilterElement::new_included_tags(&[&DATA.tags[3]]).unwrap(),
        // All but first timestamp
        OwnedFilterElement::new_since(DATA.timestamps[1]),
        // All but last timestamp
        OwnedFilterElement::new_until(DATA.timestamps[5]),
    ];

    let filter = OwnedFilter::new(&*elements).unwrap();

    let found_records = DATA
        .store
        .find_records(&filter, 300, |_| true, true)
        .unwrap();

    verify_find_output(
        found_records.as_slice(),
        2 * 4 * 5 * 1, // 2 keys, 4 kinds, 5 timestamps, 1 tag
        &[DATA.secret_keys[1].public(), DATA.secret_keys[3].public()],
        &[],
        &[DATA.timestamps[0], DATA.timestamps[6], DATA.timestamps[7]],
    );

    // Make sure we get no records that include tag 0 or tag 1 (tag2 and tag3 sometimes go together)
    assert_eq!(
        found_records.iter().any(|r| {
            r.tag_set()
                .iter()
                .any(|t| *t == *DATA.tags[0] || *t == *DATA.tags[1])
        }),
        false
    );
}
