use crate::error::{Error, InnerError};
use mmap_append::MmapAppend;
use mosaic_core::Record;
use std::fs::{File, OpenOptions};
use std::mem;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

/// This is the size of the initial `Record` map, and also how large it grows by
/// when we need to grow it. This should be a multiple of the page size (4096)
// While debugging, we like to use a small value to increase the frequency of
// resizing, to help detect if there are problems in the algorithm.
#[cfg(debug_assertions)]
const MAP_CHUNK: usize = 2048;
#[cfg(not(debug_assertions))]
const MAP_CHUNK: usize = 4096 * 1024; // grow by 4 megabytes at a time

/// `Records` is a fast low-level storage facility for `Record`s.
///
/// It only stores records and returns an offset where they are, and fetches records
/// if handed an appropriate offset.
///
/// It does no indexing, no validation, and no duplicate checks.
#[derive(Debug)]
pub(crate) struct Records {
    // the Mmap doesn't need us to keep the file, but we keep it for resizing.
    map_file: File,
    map_file_len: AtomicUsize,

    // This is a linear sequence of `Record`s in an append-only memory mapped file which
    // internally remembers the 'end' pointer and internally prevents multiple writers.
    map: MmapAppend,
}

impl Records {
    /// Create a new `Records`. The `map_file` is the eventually large file
    /// that holds all the `Record`s.
    pub(crate) fn new<P: AsRef<Path>>(map_file: P) -> Result<Records, Error> {
        // Open the map file, possibly creating if it isn't there
        let map_file = OpenOptions::new()
            .read(true)
            .write(true)
            .truncate(false)
            .create(true)
            .open(map_file)?;

        // Get it's size
        let metadata = map_file.metadata()?;
        let mut len = metadata.len() as usize;

        // Determine if we just created it
        // (not long enough for the required end offset)
        let new = len < mem::size_of::<usize>();

        // If brand new:
        if new {
            // grow to initial size
            len = MAP_CHUNK;
            map_file.set_len(MAP_CHUNK as u64)?;
        }

        // Memory map it
        let map = unsafe { MmapAppend::new(&map_file, new)? };

        Ok(Records {
            map_file,
            map_file_len: AtomicUsize::new(len),
            map,
        })
    }

    /// Get the number of bytes used in the map
    #[inline]
    pub(crate) fn read_map_end(&self) -> usize {
        self.map.get_end()
    }

    /// Get a `Record` by its offset in the map
    pub(crate) unsafe fn get_record_by_offset(&self, offset: usize) -> Result<&Record, Error> {
        if offset >= self.read_map_end() {
            return Err(InnerError::EndOfInput.into());
        }
        let record = unsafe { Record::from_bytes(&self.map[offset..])? };
        Ok(record)
    }

    /// Store `Record`
    ///
    /// This does not validate the `Record`.
    /// This does not check if the `Record` already is stored so this could create a duplicate.
    /// This does not index the `Record`.
    ///
    /// Returns the offset where the `Record` was stored.
    pub(crate) fn store_record(&self, record: &Record) -> Result<usize, Error> {
        // Align to 8 bytes
        let mut end = self.map.get_end();
        if end % 8 != 0 {
            let padding = 8 - (end % 8);
            end += padding;
            assert_eq!(end % 8, 0);
            let _ = self.map.append(padding, |_| Ok(padding))?;
        }

        let size = record.as_bytes().len();

        loop {
            let result = self.map.append(size, |dst| {
                dst[..size].copy_from_slice(record.as_bytes());
                Ok(size)
            });

            match result {
                Ok(offset) => return Ok(offset),
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::Other {
                        if e.to_string() == "Out of space" {
                            // see mmap-append
                            // Determine the new size
                            let new_file_len = {
                                let file_len = self.map_file_len.load(Ordering::Relaxed);
                                file_len + MAP_CHUNK
                            };

                            // Grow the file
                            self.map_file.set_len(new_file_len as u64)?;

                            // Resize the memory map
                            self.map.resize(new_file_len)?;

                            // Save this new length
                            self.map_file_len.store(new_file_len, Ordering::Relaxed);

                            // Try again
                            continue;
                        } else {
                            return Err(e.into());
                        }
                    } else {
                        return Err(e.into());
                    }
                }
            }
        }
    }

    /// Iterate over `Record`s
    pub(crate) fn iter(&self) -> RecordsIter<'_> {
        RecordsIter {
            store: self,
            offset: mmap_append::HEADER_SIZE,
        }
    }
}

/// An iterator over `Record`s in a `Records` store
#[derive(Debug)]
pub struct RecordsIter<'a> {
    store: &'a Records,
    offset: usize,
}

impl<'a> Iterator for RecordsIter<'a> {
    type Item = Result<&'a Record, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            match self.store.get_record_by_offset(self.offset) {
                Err(e) => {
                    if matches!(e.inner, InnerError::EndOfInput) {
                        None
                    } else {
                        Some(Err(e))
                    }
                }
                Ok(record) => {
                    self.offset += record.as_bytes().len();
                    // Bump to next 8-byte alignment point
                    if self.offset % 8 != 0 {
                        self.offset += 8 - (self.offset % 8);
                        assert_eq!(self.offset % 8, 0);
                    }
                    Some(Ok(record))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mosaic_core::{
        EMPTY_TAG_SET, Kind, OwnedRecord, Record, RecordFlags, RecordParts, SecretKey, Timestamp,
    };
    use rand::rngs::OsRng;

    #[test]
    fn test_records() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("mmap");
        let store = Records::new(&path).unwrap();

        println!("Records has {} used bytes", store.read_map_end());

        let mut csprng = OsRng;
        let secret_key = SecretKey::generate(&mut csprng);

        let record1 = OwnedRecord::new(
            &secret_key,
            &RecordParts {
                kind: Kind::MICROBLOG_ROOT,
                deterministic_nonce: None,
                timestamp: Timestamp::now().unwrap(),
                flags: RecordFlags::PRINTABLE,
                tag_set: &*EMPTY_TAG_SET,
                payload: b"Hello World!",
            },
        )
        .unwrap();
        let offset1 = store.store_record(&record1).unwrap();
        println!("Record 1 at offset {offset1}");

        let record2 = OwnedRecord::new(
            &secret_key,
            &RecordParts {
                kind: Kind::MICROBLOG_ROOT,
                deterministic_nonce: None,
                timestamp: Timestamp::now().unwrap(),
                flags: RecordFlags::PRINTABLE,
                tag_set: &*EMPTY_TAG_SET,
                payload: b"Goodbye World!",
            },
        )
        .unwrap();
        let offset2 = store.store_record(&record2).unwrap();
        println!("Record 2 at offset {offset2}");

        println!("Records has {} used bytes", store.read_map_end());

        let record1b = unsafe { store.get_record_by_offset(offset1).unwrap() };
        assert_eq!(&*record1, record1b);

        let record2b = unsafe { store.get_record_by_offset(offset2).unwrap() };
        assert_eq!(&*record2, record2b);

        let mut iter = store.iter();
        let r1 = iter.next().unwrap().unwrap();
        let r2 = iter.next().unwrap().unwrap();
        assert!(iter.next().is_none());

        assert_eq!(r1, &*record1);
        assert_eq!(r2, &*record2);
    }
}
