use std::error::Error as StdError;
use std::panic::Location;

/// Errors that can occur in the mosaic-store-lmdb crate
#[derive(Debug)]
pub struct Error {
    /// The error itself
    pub inner: InnerError,
    location: &'static Location<'static>,
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.inner)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}, {}", self.inner, self.location)
    }
}

/// Errors that can occur in the crate
#[derive(Debug)]
pub enum InnerError {
    /// Buffer Too Small
    BufferTooSmall,

    /// The record duplicates a record that we already have
    Duplicate,

    /// End of Input
    EndOfInput,

    /// Filter is too wide
    FilterTooWide,

    /// A general error
    General(String),

    /// An upstream I/O error
    Io(std::io::Error),

    /// An error from LMDB, our upstream storage crate
    Lmdb(heed::Error),

    /// A Mosaic Core error
    MosaicCore(mosaic_core::Error),
}

impl std::fmt::Display for InnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InnerError::BufferTooSmall => write!(f, "Buffer too small"),
            InnerError::Duplicate => write!(f, "Duplicate"),
            InnerError::EndOfInput => write!(f, "End of input"),
            InnerError::FilterTooWide => write!(f, "Filter is too wide"),
            InnerError::General(s) => write!(f, "{s}"),
            InnerError::Io(e) => write!(f, "I/O: {e}"),
            InnerError::Lmdb(e) => write!(f, "LMDB: {e}"),
            InnerError::MosaicCore(e) => write!(f, "Mosaic Core: {e}"),
        }
    }
}

impl StdError for InnerError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            InnerError::Io(e) => Some(e),
            InnerError::Lmdb(e) => Some(e),
            InnerError::MosaicCore(e) => Some(e),
            _ => None,
        }
    }
}

// Note: we impl Into because our typical pattern is InnerError::Variant.into()
//       when we tried implementing From, the location was deep in rust code's
//       blanket into implementation, which wasn't the line number we wanted.
//
//       As for converting other error types, the try! macro uses From so it
//       is correct.
#[allow(clippy::from_over_into)]
impl Into<Error> for InnerError {
    #[track_caller]
    fn into(self) -> Error {
        Error {
            inner: self,
            location: Location::caller(),
        }
    }
}

impl From<std::io::Error> for Error {
    #[track_caller]
    fn from(err: std::io::Error) -> Self {
        Error {
            inner: InnerError::Io(err),
            location: Location::caller(),
        }
    }
}

impl From<heed::Error> for Error {
    #[track_caller]
    fn from(err: heed::Error) -> Self {
        Error {
            inner: InnerError::Lmdb(err),
            location: Location::caller(),
        }
    }
}

impl From<mosaic_core::Error> for Error {
    #[track_caller]
    fn from(err: mosaic_core::Error) -> Self {
        Error {
            inner: InnerError::MosaicCore(err),
            location: Location::caller(),
        }
    }
}
