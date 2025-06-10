use heed::{BoxedError, BytesDecode, BytesEncode};
use mosaic_core::{Kind, PublicKey, Tag, Timestamp};
use std::borrow::Cow;
use std::cmp::Ordering;

pub(crate) fn tag_to_prefix(tag: &Tag) -> [u8; 12] {
    let taglen = tag.as_bytes().len();
    let mut prefix: [u8; 12] = [0; 12];
    if taglen >= 12 {
        prefix.copy_from_slice(&tag.as_bytes()[..12]);
    } else {
        prefix[0..taglen].copy_from_slice(tag.as_bytes());
    }
    prefix
}

/// An LMDB key into the pubkey or tag index
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct PrefixRevstamp {
    pub(crate) prefix: [u8; 12],
    pub(crate) timestamp: Timestamp,
}

impl PartialOrd for PrefixRevstamp {
    fn partial_cmp(&self, other: &PrefixRevstamp) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PrefixRevstamp {
    fn cmp(&self, other: &PrefixRevstamp) -> Ordering {
        // Compare their encoded bytes with the reversed timestamp
        PrefixRevstampCodec::bytes_encode(self)
            .unwrap()
            .cmp(&PrefixRevstampCodec::bytes_encode(other).unwrap())
    }
}

impl PrefixRevstamp {
    const TWELVE_ZEROES: [u8; 12] = [0; 12];

    pub(crate) fn set_prefix_from_tag(&mut self, tag: &Tag) {
        let taglen = tag.as_bytes().len();
        if taglen >= 12 {
            self.prefix.copy_from_slice(&tag.as_bytes()[..12]);
        } else {
            self.prefix[0..taglen].copy_from_slice(tag.as_bytes());
            self.prefix[taglen..12].copy_from_slice(&Self::TWELVE_ZEROES[taglen..12]);
        }
    }

    pub(crate) fn set_prefix_from_pubkey(&mut self, pubkey: PublicKey) {
        self.prefix = pubkey.as_bytes()[..12].try_into().unwrap();
    }
}

/// A codec for mapping a `PrefixRevstamp` into bytes and back
pub(crate) struct PrefixRevstampCodec;

impl<'a> BytesEncode<'a> for PrefixRevstampCodec {
    type EItem = PrefixRevstamp;
    fn bytes_encode(k: &'a Self::EItem) -> Result<Cow<'a, [u8]>, BoxedError> {
        let mut bytes: Vec<u8> = vec![0; 12 + 8];
        bytes[0..12].copy_from_slice(k.prefix.as_slice());
        bytes[12..12 + 8].copy_from_slice(k.timestamp.to_inverse_bytes().as_slice());
        Ok(Cow::Owned(bytes))
    }
}

impl<'a> BytesDecode<'a> for PrefixRevstampCodec {
    type DItem = PrefixRevstamp;
    fn bytes_decode(bytes: &'a [u8]) -> Result<Self::DItem, BoxedError> {
        let pkp: [u8; 12] = match bytes.get(..12) {
            Some(bytes) => bytes.try_into().unwrap(),
            None => return Err("invalid prefix revstamp key, prefix part".into()),
        };
        let ts: Timestamp = match bytes.get(12..12 + 8) {
            Some(bytes) => Timestamp::from_inverse_bytes(bytes.try_into().unwrap())
                .map_err(|e| -> BoxedError { format!("{e}").into() })?,
            None => return Err("invalid prefix revstamp key, timestamp part".into()),
        };
        Ok(PrefixRevstamp {
            prefix: pkp,
            timestamp: ts,
        })
    }
}

/// An LMDB key into the kind index
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct KindRevstamp {
    pub(crate) kind: Kind,
    pub(crate) timestamp: Timestamp,
}

impl PartialOrd for KindRevstamp {
    fn partial_cmp(&self, other: &KindRevstamp) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for KindRevstamp {
    fn cmp(&self, other: &KindRevstamp) -> Ordering {
        // Compare their encoded bytes with the reversed timestamp
        KindRevstampCodec::bytes_encode(self)
            .unwrap()
            .cmp(&KindRevstampCodec::bytes_encode(other).unwrap())
    }
}

/// A codec for mapping a `KindRevstamp` into bytes and back
pub(crate) struct KindRevstampCodec;

impl<'a> BytesEncode<'a> for KindRevstampCodec {
    type EItem = KindRevstamp;
    fn bytes_encode(k: &'a Self::EItem) -> Result<Cow<'a, [u8]>, BoxedError> {
        let mut bytes: Vec<u8> = vec![0; 2 + 8];
        bytes[0..2].copy_from_slice(&k.kind.0.to_be_bytes());
        bytes[2..2 + 8].copy_from_slice(k.timestamp.to_inverse_bytes().as_slice());
        Ok(Cow::Owned(bytes))
    }
}

impl<'a> BytesDecode<'a> for KindRevstampCodec {
    type DItem = KindRevstamp;
    fn bytes_decode(bytes: &'a [u8]) -> Result<Self::DItem, BoxedError> {
        let kind_u16 = match bytes.get(..2) {
            Some(bytes) => bytes.try_into().map(u16::from_be_bytes).unwrap(),
            None => return Err("invalid kind revstamp key, kind part".into()),
        };
        let ts: Timestamp = match bytes.get(2..2 + 8) {
            Some(bytes) => Timestamp::from_inverse_bytes(bytes.try_into().unwrap())
                .map_err(|e| -> BoxedError { format!("{e}").into() })?,
            None => return Err("invalid kind revstamp key, timestamp part".into()),
        };

        Ok(KindRevstamp {
            kind: Kind(kind_u16),
            timestamp: ts,
        })
    }
}
