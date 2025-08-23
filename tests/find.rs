use lazy_static::lazy_static;
use mosaic_core::{
    EMPTY_TAG_SET, Kind, OwnedFilter, OwnedFilterElement, OwnedRecord, OwnedTag, OwnedTagSet,
    PublicKey, Record, RecordAddressData, RecordFlags, RecordParts, RecordSigningData, SecretKey,
    TagType, Timestamp,
};
use mosaic_store_lmdb::Store;
use rand::prelude::SliceRandom;

struct Data {
    secret_keys: Vec<SecretKey>,
    kinds: Vec<Kind>,
    timestamps: Vec<Timestamp>,
    tags: Vec<OwnedTag>,
    store: Store,
}

lazy_static! {
    static ref DATA: Data = {
        let secret_keys = vec![
            SecretKey::generate(),
            SecretKey::generate(),
            SecretKey::generate(),
            SecretKey::generate(),
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
            signing_data: RecordSigningData::SecretKey(secret_keys[0].clone()),
            address_data: RecordAddressData::Random(secret_keys[0].public(), kinds[0]),
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

                        parts.signing_data =
                            RecordSigningData::SecretKey(secret_keys[secret_key_index].clone());
                        parts.address_data = RecordAddressData::Random(
                            secret_keys[secret_key_index].public(),
                            kinds[kind_index],
                        );
                        parts.timestamp = timestamps[timestamp_index];
                        let tagset = OwnedTagSet::from_tags(
                            tags.iter().map(|t| &**t).skip(tag_index).take(2),
                        );
                        parts.tag_set = &tagset;
                        let r = OwnedRecord::new(&parts).unwrap();
                        records.push(r);
                    }
                }
            }
        }

        let mut rng = rand::rng();
        records.shuffle(&mut rng);

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
    // Make sure all the records are distinct
    let mut v1 = found_records.to_vec();
    let v2 = v1.clone();
    v1.dedup();
    assert_eq!(v1, v2);

    // Make sure the timestamps are all in order, newest to oldest
    assert!(found_records.is_sorted_by(|a, b| a.timestamp() >= b.timestamp()));

    // Make sure we get no records with the forbidden pubkeys
    assert_eq!(
        found_records
            .iter()
            .any(|r| missing_pubkeys.contains(&r.author_public_key())),
        false
    );

    // Make sure we get no records with forbidden kinds
    assert_eq!(
        found_records
            .iter()
            .any(|r| missing_kinds.contains(&r.kind())),
        false
    );

    // Make sure we get no records with forbidden timestamps
    assert_eq!(
        found_records
            .iter()
            .any(|r| missing_timestamps.contains(&r.timestamp())),
        false
    );

    // Make sure we get the right number of records
    assert_eq!(found_records.len(), expected_len);
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

    assert_eq!(filter.elements().count(), 3);

    let found_records = DATA
        .store
        .find_records(&filter, 300, |_| true, true)
        .unwrap();

    verify_find_output(
        found_records.as_slice(),
        4 * 3 * 6 * 3,
        &[],
        &[DATA.kinds[1]],
        &[DATA.timestamps[0], DATA.timestamps[7]], // GINA FAIL
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

    assert_eq!(filter.elements().count(), 3);

    let found_records = DATA
        .store
        .find_records(&filter, 300, |_| true, true)
        .unwrap();

    verify_find_output(
        found_records.as_slice(),
        2 * 4 * 6 * 3,
        &[DATA.secret_keys[1].public(), DATA.secret_keys[3].public()],
        &[],
        &[DATA.timestamps[0], DATA.timestamps[7]], // GINA FAIL
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

    assert_eq!(filter.elements().count(), 3);

    let found_records = DATA
        .store
        .find_records(&filter, 100, |_| true, true)
        .unwrap();

    verify_find_output(
        found_records.as_slice(),
        4 * 4 * 6 * 1,
        &[],
        &[],
        &[DATA.timestamps[0], DATA.timestamps[7]], // GINA FAIL
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

    assert_eq!(filter.elements().count(), 4);

    let found_records = DATA
        .store
        .find_records(&filter, 300, |_| true, true)
        .unwrap();

    verify_find_output(
        found_records.as_slice(),
        2 * 3 * 5 * 3,
        &[DATA.secret_keys[1].public(), DATA.secret_keys[3].public()],
        &[DATA.kinds[1]], // GINA FAIL
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

    assert_eq!(filter.elements().count(), 4);

    let found_records = DATA
        .store
        .find_records(&filter, 300, |_| true, true)
        .unwrap();

    verify_find_output(
        found_records.as_slice(),
        4 * 3 * 5 * 1, // 4 keys, 3 kinds, 5 timestamps, 1 tag
        &[],
        &[DATA.kinds[1]], // GINA FAIL
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
        // All but last two timestamps
        OwnedFilterElement::new_until(DATA.timestamps[5]),
    ];

    let filter = OwnedFilter::new(&*elements).unwrap();

    assert_eq!(filter.elements().count(), 4);

    let found_records = DATA
        .store
        .find_records(&filter, 300, |_| true, true)
        .unwrap();

    verify_find_output(
        found_records.as_slice(),
        2 * 4 * 5 * 1, // 2 keys, 4 kinds, 5 timestamps, 1 tag
        &[DATA.secret_keys[1].public(), DATA.secret_keys[3].public()],
        &[],
        &[DATA.timestamps[0], DATA.timestamps[6], DATA.timestamps[7]], // GINA FAIL
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
fn test_find_by_timestamps() {
    let filter =
        OwnedFilter::new(&[&OwnedFilterElement::new_timestamps(&[DATA.timestamps[1]]).unwrap()])
            .unwrap();

    assert_eq!(filter.elements().count(), 1);

    let found_records = DATA
        .store
        .find_records(&filter, 300, |_| true, true)
        .unwrap();

    verify_find_output(
        found_records.as_slice(),
        4 * 4 * 1 * 3,
        &[],
        &[],
        &[
            DATA.timestamps[0],
            DATA.timestamps[2],
            DATA.timestamps[3],
            DATA.timestamps[4],
            DATA.timestamps[5],
            DATA.timestamps[6],
            DATA.timestamps[7],
        ],
    );
}
