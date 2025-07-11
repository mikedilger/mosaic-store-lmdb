use heed::{BoxedError, BytesDecode, BytesEncode};
use mosaic_core::{Kind, PublicKey, Tag, Timestamp};
use std::borrow::Cow;
use std::cmp::Ordering;

pub(crate) const PREFIX_LEN: usize = 22;

pub(crate) fn tag_to_prefix(tag: &Tag) -> [u8; PREFIX_LEN] {
    let mut prefix: [u8; PREFIX_LEN] = [0; PREFIX_LEN];
    let taglen = tag.as_bytes().len();
    if taglen >= PREFIX_LEN + 2 {
        prefix.copy_from_slice(&tag.as_bytes()[2..PREFIX_LEN + 2]);
    } else {
        prefix[0..taglen - 2].copy_from_slice(&tag.as_bytes()[2..taglen]);
    }
    prefix
}

/// An LMDB key into the pubkey or tag index
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct PrefixRevstamp {
    pub(crate) prefix: [u8; PREFIX_LEN],
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
    const ZEROES: [u8; PREFIX_LEN] = [0; PREFIX_LEN];

    pub(crate) fn set_prefix_from_tag(&mut self, tag: &Tag) {
        let taglen = tag.as_bytes().len();
        if taglen >= PREFIX_LEN + 2 {
            self.prefix
                .copy_from_slice(&tag.as_bytes()[2..PREFIX_LEN + 2]);
        } else {
            self.prefix[0..taglen - 2].copy_from_slice(&tag.as_bytes()[2..taglen]);
            self.prefix[taglen - 2..PREFIX_LEN]
                .copy_from_slice(&Self::ZEROES[..PREFIX_LEN + 2 - taglen]);
        }
    }

    pub(crate) fn set_prefix_from_pubkey(&mut self, pubkey: PublicKey) {
        self.prefix = pubkey.as_bytes()[..PREFIX_LEN].try_into().unwrap();
    }
}

/// A codec for mapping a `PrefixRevstamp` into bytes and back
pub(crate) struct PrefixRevstampCodec;

impl<'a> BytesEncode<'a> for PrefixRevstampCodec {
    type EItem = PrefixRevstamp;
    fn bytes_encode(k: &'a Self::EItem) -> Result<Cow<'a, [u8]>, BoxedError> {
        let mut bytes: Vec<u8> = vec![0; PREFIX_LEN + 8];
        bytes[0..PREFIX_LEN].copy_from_slice(k.prefix.as_slice());
        bytes[PREFIX_LEN..PREFIX_LEN + 8]
            .copy_from_slice(k.timestamp.to_inverse_bytes().as_slice());
        Ok(Cow::Owned(bytes))
    }
}

impl<'a> BytesDecode<'a> for PrefixRevstampCodec {
    type DItem = PrefixRevstamp;
    fn bytes_decode(bytes: &'a [u8]) -> Result<Self::DItem, BoxedError> {
        let pkp: [u8; PREFIX_LEN] = match bytes.get(..PREFIX_LEN) {
            Some(bytes) => bytes.try_into().unwrap(),
            None => return Err("invalid prefix revstamp key, prefix part".into()),
        };
        let ts: Timestamp = match bytes.get(PREFIX_LEN..PREFIX_LEN + 8) {
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
        let mut bytes: Vec<u8> = vec![0; 8 + 8];
        bytes[0..8].copy_from_slice(k.kind.to_bytes().as_slice());
        bytes[8..8 + 8].copy_from_slice(k.timestamp.to_inverse_bytes().as_slice());
        Ok(Cow::Owned(bytes))
    }
}

impl<'a> BytesDecode<'a> for KindRevstampCodec {
    type DItem = KindRevstamp;
    fn bytes_decode(bytes: &'a [u8]) -> Result<Self::DItem, BoxedError> {
        let kind: Kind = match bytes.get(..8) {
            Some(bytes) => Kind::from_bytes(bytes.try_into().unwrap()),
            None => return Err("invalid kind revstamp key, too short for kind part".into()),
        };

        let ts: Timestamp = match bytes.get(8..8 + 8) {
            Some(bytes) => Timestamp::from_inverse_bytes(bytes.try_into().unwrap())
                .map_err(|e| -> BoxedError { format!("{e}").into() })?,
            None => return Err("invalid kind revstamp key, timestamp part".into()),
        };

        Ok(KindRevstamp {
            kind,
            timestamp: ts,
        })
    }
}

#[cfg(test)]
mod test {
    use super::{
        KindRevstamp, KindRevstampCodec, PrefixRevstamp, PrefixRevstampCodec, tag_to_prefix,
    };
    use mosaic_core::{Kind, OwnedTag, TagType, Timestamp};

    #[test]
    fn test_tag_to_prefix() {
        let tag = OwnedTag::new(TagType(100), b"testing").unwrap();
        let prefix = tag_to_prefix(&tag);
        assert_eq!(&prefix, b"\x64\0testing\0\0\0\0\0\0\0\0\0\0\0\0\0");

        let tag = OwnedTag::new(
            TagType(100),
            b"The quick brown fox jumps over the lazy dog.",
        )
        .unwrap();
        let prefix = tag_to_prefix(&tag);
        assert_eq!(&prefix, b"\x64\0The quick brown fox ");
    }

    #[test]
    fn test_prefix_revstamp() {
        let mut pr = PrefixRevstamp {
            prefix: [0; 22],
            timestamp: Timestamp::now().unwrap(),
        };

        let tag = OwnedTag::new(TagType(100), b"testing").unwrap();
        pr.set_prefix_from_tag(&tag);
        assert_eq!(&pr.prefix, b"\x64\0testing\0\0\0\0\0\0\0\0\0\0\0\0\0");

        let tag = OwnedTag::new(
            TagType(100),
            b"The quick brown fox jumps over the lazy dog.",
        )
        .unwrap();
        pr.set_prefix_from_tag(&tag);
        assert_eq!(&pr.prefix, b"\x64\0The quick brown fox ");
    }

    #[test]
    fn test_prefix_revstamp_codec() {
        use heed::{BytesDecode, BytesEncode};

        let mut pr = PrefixRevstamp {
            prefix: [0; 22],
            timestamp: Timestamp::now().unwrap(),
        };
        let tag = OwnedTag::new(TagType(100), b"testing").unwrap();
        pr.set_prefix_from_tag(&tag);

        let coded = <PrefixRevstampCodec as BytesEncode>::bytes_encode(&pr).unwrap();
        let decoded: PrefixRevstamp =
            <PrefixRevstampCodec as BytesDecode>::bytes_decode(&coded).unwrap();
        assert_eq!(pr, decoded);

        let tag = OwnedTag::new(
            TagType(100),
            b"The quick brown fox jumps over the lazy dog.",
        )
        .unwrap();
        pr.set_prefix_from_tag(&tag);

        let coded = <PrefixRevstampCodec as BytesEncode>::bytes_encode(&pr).unwrap();
        let decoded: PrefixRevstamp =
            <PrefixRevstampCodec as BytesDecode>::bytes_decode(&coded).unwrap();
        assert_eq!(pr, decoded);
    }

    #[test]
    fn test_kind_revstamp_codec() {
        use heed::{BytesDecode, BytesEncode};

        let pr = KindRevstamp {
            kind: Kind::from_bytes([0, 0, 0, 0, 99, 0, 1, 14]),
            timestamp: Timestamp::now().unwrap(),
        };

        let coded = <KindRevstampCodec as BytesEncode>::bytes_encode(&pr).unwrap();
        let decoded: KindRevstamp =
            <KindRevstampCodec as BytesDecode>::bytes_decode(&coded).unwrap();
        assert_eq!(pr, decoded);
    }
}
