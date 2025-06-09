use core::time::Duration;
use mosaic_core::{
    Filter, FilterElement, Id, Kind, OwnedFilter, OwnedFilterElement, OwnedRecord, PublicKey,
    Record, RecordFlags, RecordParts, SecretKey, Tag, Timestamp,
};
use mosaic_store_lmdb::Store;
use rand::rngs::OsRng;

#[test]
fn test_find_by_kind() {
    let mut csprng = OsRng;

    let secret_key = SecretKey::generate(&mut csprng);

    let kind1 = Kind(1);
    let kind2 = Kind(2);
    let kind3 = Kind(3);

    let ts1 = Timestamp::now().unwrap();
    let ts2 = ts1 + Duration::new(1, 500_000_000);
    let ts3 = ts2 + Duration::new(1, 500_000_000);
    let ts4 = ts3 + Duration::new(1, 500_000_000);
    let ts5 = ts4 + Duration::new(1, 500_000_000);
    let ts6 = ts5 + Duration::new(1, 500_000_000);
    let ts7 = ts6 + Duration::new(1, 500_000_000);

    let mut parts = RecordParts {
        kind: kind1,
        deterministic_nonce: None,
        timestamp: ts1,
        flags: RecordFlags::empty(),
        tags_bytes: &[],
        payload: &[],
    };

    parts.kind = kind1;
    parts.timestamp = ts2;
    let record_k1_ts2 = OwnedRecord::new(&secret_key, &parts).unwrap();
    parts.timestamp = ts3;
    let record_k1_ts3 = OwnedRecord::new(&secret_key, &parts).unwrap();
    parts.timestamp = ts5;
    let record_k1_ts5 = OwnedRecord::new(&secret_key, &parts).unwrap();

    parts.kind = kind2;
    parts.timestamp = ts1;
    let record_k2_ts1 = OwnedRecord::new(&secret_key, &parts).unwrap();
    parts.timestamp = ts4;
    let record_k2_ts4 = OwnedRecord::new(&secret_key, &parts).unwrap();
    parts.timestamp = ts7;
    let record_k2_ts7 = OwnedRecord::new(&secret_key, &parts).unwrap();

    parts.kind = kind3;
    parts.timestamp = ts6;
    let record_k3_ts6 = OwnedRecord::new(&secret_key, &parts).unwrap();

    let tempdir = tempfile::tempdir().unwrap();
    let store = Store::new(tempdir, vec![], 2).unwrap();

    store.store_record(&record_k2_ts4).unwrap();
    store.store_record(&record_k1_ts3).unwrap();
    store.store_record(&record_k1_ts5).unwrap();
    store.store_record(&record_k3_ts6).unwrap();
    store.store_record(&record_k1_ts2).unwrap();
    store.store_record(&record_k2_ts1).unwrap();
    store.store_record(&record_k2_ts7).unwrap();

    let filter = OwnedFilter::new(&[
        &OwnedFilterElement::new_kinds(&[kind1, kind2, kind3]).unwrap(),
        &OwnedFilterElement::new_since(ts1),
        &OwnedFilterElement::new_until(ts7),
    ])
    .unwrap();

    let records = store.find_records(&filter, 100, |_| true, true).unwrap();
    let mut iter = records.iter();

    println!("k1_ts2: {:?}", record_k1_ts2.id());
    println!("k1_ts3: {:?}", record_k1_ts3.id());
    println!("k1_ts5: {:?}", record_k1_ts5.id());
    println!("k2_ts1: {:?}", record_k2_ts1.id());
    println!("k2_ts4: {:?}", record_k2_ts4.id());
    println!("k2_ts7: {:?}", record_k2_ts7.id());
    println!("k3_ts6: {:?}", record_k3_ts6.id());

    let r = iter.next().unwrap();
    assert_eq!(r.id(), record_k2_ts7.id());
    let r = iter.next().unwrap();
    assert_eq!(r.id(), record_k3_ts6.id());
    let r = iter.next().unwrap();
    assert_eq!(r.id(), record_k1_ts5.id());
    let r = iter.next().unwrap();
    assert_eq!(r.id(), record_k2_ts4.id());
    let r = iter.next().unwrap();
    assert_eq!(r.id(), record_k1_ts3.id());
    let r = iter.next().unwrap();
    assert_eq!(r.id(), record_k1_ts2.id());
    let r = iter.next().unwrap();
    assert_eq!(r.id(), record_k2_ts1.id());

    assert_eq!(iter.next(), None);
}
