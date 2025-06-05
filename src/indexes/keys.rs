use mosaic_core::{Kind, PublicKey, Tag, Timestamp};

// We use only this many prefix bytes from tags and keys in the indexes to make them smaller.
// If not unique, that's ok we will just be scanning through a bit more.
const PREFIX: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum KeyKind {
    Pkpre,
    PkpreTagpre,
    PkpreTagpreTs,
    Kind,
    KindPkpre,
    KindPkpreTs,
    Tagpre,
    TagpreKind,
    TagpreKindTs,
}

pub(crate) struct OwnedKey {
    data: Vec<u8>,
    kind: KeyKind,
}

pub(crate) struct Key<'a> {
    data: &'a [u8],
    kind: KeyKind,
}

impl Key<'_> {
    // View a slice of bytes as a key
    fn from_inner<S: AsRef<[u8]> + ?Sized>(s: &S) -> &Key {
        unsafe { &*(std::ptr::from_ref::<[u8]>(s.as_ref()) as *const Key) }
    }

    // View a mutable slice of bytes as a Key
    fn from_inner_mut(inner: &mut [u8]) -> &mut Key {
        // SAFETY: Key is just a wrapper around [u8],
        // therefore converting &mut [u8] to &mut Key is safe.
        unsafe { &mut *(std::ptr::from_mut::<[u8]>(inner) as *mut Key) }
    }

    /// Interpret a sequence of bytes as a `Key`.
    pub(crate) fn from_bytes_and_kind(input: &[u8], kind: KeyKind) -> Key {
        Key { data: input, kind }
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.data
    }

    pub(crate) fn public_key_prefix(&self) -> Option<&[u8]> {
        match self.kind {
            KeyKind::Pkpre | KeyKind::PkpreTagpre | KeyKind::PkpreTagpreTs => {
                Some(&self.data[..PREFIX])
            }
            KeyKind::KindPkpre | KeyKind::KindPkpreTs => Some(&self.data[2..2 + PREFIX]),
            _ => None,
        }
    }

    pub(crate) fn tag_prefix(&self) -> Option<&[u8]> {
        match self.kind {
            KeyKind::PkpreTagpre | KeyKind::PkpreTagpreTs => Some(&self.data[32..32 + PREFIX]),
            KeyKind::Tagpre | KeyKind::TagpreKind | KeyKind::TagpreKindTs => {
                Some(&self.data[..PREFIX])
            }
            _ => None,
        }
    }

    pub(crate) fn timestamp(&self) -> Option<Timestamp> {
        match self.kind {
            KeyKind::PkpreTagpreTs => Some(
                Timestamp::from_inverse_bytes(
                    self.data[32 + PREFIX..32 + PREFIX + 8].try_into().unwrap(),
                )
                .unwrap(),
            ),
            KeyKind::KindPkpreTs => Some(
                Timestamp::from_inverse_bytes(self.data[2 + 32..2 + 32 + 8].try_into().unwrap())
                    .unwrap(),
            ),
            KeyKind::TagpreKindTs => Some(
                Timestamp::from_inverse_bytes(
                    self.data[PREFIX + 2..PREFIX + 2 + 8].try_into().unwrap(),
                )
                .unwrap(),
            ),
            _ => None,
        }
    }

    pub(crate) fn kind(&self) -> Option<Kind> {
        match self.kind {
            KeyKind::Kind | KeyKind::KindPkpre | KeyKind::KindPkpreTs => Some(Kind(
                u16::from_be_bytes(self.data[0..2].try_into().unwrap()),
            )),
            _ => None,
        }
    }
}

impl OwnedKey {
    pub(super) fn as_key<'a>(&'a self) -> Key<'a> {
        Key {
            data: &self.data,
            kind: self.kind,
        }
    }
}

impl From<PublicKey> for OwnedKey {
    fn from(pk: PublicKey) -> OwnedKey {
        let mut bytes: Vec<u8> = vec![0; PREFIX];
        bytes[0..PREFIX].copy_from_slice(&pk.as_bytes().as_slice()[..16]);
        OwnedKey {
            data: bytes,
            kind: KeyKind::Pkpre,
        }
    }
}

impl From<(PublicKey, &Tag)> for OwnedKey {
    fn from(tuple: (PublicKey, &Tag)) -> OwnedKey {
        let eitherkey = tuple.0;
        let tag = tuple.1;
        let mut bytes: Vec<u8> = vec![0; PREFIX + PREFIX];
        bytes[0..PREFIX].copy_from_slice(&eitherkey.as_bytes().as_slice()[..16]);
        let taglen = tag.as_bytes().len();
        if taglen >= PREFIX {
            bytes[PREFIX..PREFIX + PREFIX].copy_from_slice(&tag.as_bytes()[..16]);
        } else {
            bytes[PREFIX..PREFIX + taglen].copy_from_slice(tag.as_bytes());
            // leave the rest zeroes
        }
        OwnedKey {
            data: bytes,
            kind: KeyKind::PkpreTagpre,
        }
    }
}

impl From<(PublicKey, &Tag, Timestamp)> for OwnedKey {
    fn from(tuple: (PublicKey, &Tag, Timestamp)) -> OwnedKey {
        let eitherkey = tuple.0;
        let tag = tuple.1;
        let timestamp = tuple.2;
        let mut bytes: Vec<u8> = vec![0; PREFIX + PREFIX + 6];
        bytes[0..PREFIX].copy_from_slice(&eitherkey.as_bytes().as_slice()[..16]);
        let taglen = tag.as_bytes().len();
        if taglen >= PREFIX {
            bytes[PREFIX..PREFIX + PREFIX].copy_from_slice(&tag.as_bytes()[..16]);
        } else {
            bytes[PREFIX..PREFIX + taglen].copy_from_slice(tag.as_bytes());
            // leave the rest zeroes
        }
        bytes[PREFIX + PREFIX..].copy_from_slice(timestamp.to_inverse_bytes().as_slice());
        OwnedKey {
            data: bytes,
            kind: KeyKind::PkpreTagpreTs,
        }
    }
}

impl From<Kind> for OwnedKey {
    fn from(kind: Kind) -> OwnedKey {
        let mut bytes: Vec<u8> = vec![0; 2];
        bytes[0..2].copy_from_slice(kind.0.to_be_bytes().as_slice());
        OwnedKey {
            data: bytes,
            kind: KeyKind::Kind,
        }
    }
}

impl From<(Kind, PublicKey)> for OwnedKey {
    fn from(tuple: (Kind, PublicKey)) -> OwnedKey {
        let kind = tuple.0;
        let eitherkey = tuple.1;
        let mut bytes: Vec<u8> = vec![0; 2 + PREFIX];
        bytes[0..2].copy_from_slice(kind.0.to_be_bytes().as_slice());
        bytes[2..2 + PREFIX].copy_from_slice(&eitherkey.as_bytes().as_slice()[..16]);
        OwnedKey {
            data: bytes,
            kind: KeyKind::KindPkpre,
        }
    }
}

impl From<(Kind, PublicKey, Timestamp)> for OwnedKey {
    fn from(tuple: (Kind, PublicKey, Timestamp)) -> OwnedKey {
        let kind = tuple.0;
        let eitherkey = tuple.1;
        let timestamp = tuple.2;
        let mut bytes: Vec<u8> = vec![0; 2 + PREFIX + 6];
        bytes[0..2].copy_from_slice(kind.0.to_be_bytes().as_slice());
        bytes[2..2 + PREFIX].copy_from_slice(&eitherkey.as_bytes().as_slice()[..16]);
        bytes[2 + PREFIX..].copy_from_slice(timestamp.to_inverse_bytes().as_slice());
        OwnedKey {
            data: bytes,
            kind: KeyKind::KindPkpreTs,
        }
    }
}

impl From<&Tag> for OwnedKey {
    fn from(tag: &Tag) -> OwnedKey {
        let mut bytes: Vec<u8> = vec![0; PREFIX];
        let taglen = tag.as_bytes().len();
        if taglen >= PREFIX {
            bytes[0..PREFIX].copy_from_slice(&tag.as_bytes()[..16]);
        } else {
            bytes[0..taglen].copy_from_slice(tag.as_bytes());
        }
        OwnedKey {
            data: bytes,
            kind: KeyKind::Tagpre,
        }
    }
}

impl From<(&Tag, Kind)> for OwnedKey {
    fn from(tuple: (&Tag, Kind)) -> OwnedKey {
        let tag = tuple.0;
        let kind = tuple.1;
        let mut bytes: Vec<u8> = vec![0; PREFIX + 2];
        let taglen = tag.as_bytes().len();
        if taglen >= PREFIX {
            bytes[0..PREFIX].copy_from_slice(&tag.as_bytes()[..16]);
        } else {
            bytes[0..taglen].copy_from_slice(tag.as_bytes());
        }
        bytes[PREFIX..PREFIX + 2].copy_from_slice(kind.0.to_be_bytes().as_slice());
        OwnedKey {
            data: bytes,
            kind: KeyKind::TagpreKind,
        }
    }
}

impl From<(&Tag, Kind, Timestamp)> for OwnedKey {
    fn from(tuple: (&Tag, Kind, Timestamp)) -> OwnedKey {
        let tag = tuple.0;
        let kind = tuple.1;
        let timestamp = tuple.2;
        let mut bytes: Vec<u8> = vec![0; PREFIX + 2];
        let taglen = tag.as_bytes().len();
        if taglen >= PREFIX {
            bytes[0..PREFIX].copy_from_slice(&tag.as_bytes()[..16]);
        } else {
            bytes[0..taglen].copy_from_slice(tag.as_bytes());
        }
        bytes[PREFIX..PREFIX + 2].copy_from_slice(kind.0.to_be_bytes().as_slice());
        bytes[PREFIX + 2..].copy_from_slice(timestamp.to_inverse_bytes().as_slice());
        OwnedKey {
            data: bytes,
            kind: KeyKind::TagpreKindTs,
        }
    }
}
