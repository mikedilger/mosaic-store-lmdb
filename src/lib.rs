// Copyright 2025 mosaic-store-lmdb Developers
// Licensed under the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>
// This file may not be copied, modified, or distributed except according to those terms.

//! Defines a Store type for storing, indexing, and accessing mosaic records.
//!
//! Indexes point at offsets into a record map to avoid additional tree searches during lookups.
//!
//! Tries to comply with as many mosaic spec requirements as possible that can be fully
//! implemented at the storage layer.

#![deny(
    missing_debug_implementations,
    trivial_numeric_casts,
    clippy::string_slice,
    unused_import_braces,
    unused_results,
    unused_lifetimes,
    unused_labels,
    unused_extern_crates,
    non_ascii_idents,
    keyword_idents,
    deprecated_in_future,
    unstable_features,
    single_use_lifetimes,
    unreachable_pub,
    missing_copy_implementations,
    missing_docs
)]
