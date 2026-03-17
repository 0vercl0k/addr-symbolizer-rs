// Axel '0vercl0k' Souchet - May 26th 2024
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]
#![doc = include_str!("../README.md")]
mod addr_space;
mod error;
mod guid;
mod misc;
mod modules;
mod pdbcache;
mod pe;
mod stats;
mod symbolizer;

pub use addr_space::AddrSpace;
pub use error::{Error, Result};
pub use guid::Guid;
pub use modules::{Module, Modules};
pub use pe::{PdbId, PeId};
pub use stats::Stats;
pub use symbolizer::{PdbLookupConfig, Symbolizer};
