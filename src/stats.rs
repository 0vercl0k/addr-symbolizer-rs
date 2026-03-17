// Axel '0vercl0k' Souchet - April 21 2024
//! This module contains the [`Stats`] type that is used to keep track of
//! various statistics when symbolizing.
use std::collections::HashMap;
use std::fmt::Debug;

use crate::pe::{PdbId, PeId};

/// Various statistics that the symbolizer keeps track of.
#[derive(Default, Clone, Debug)]
pub struct Stats {
    /// The number of addresses symbolized.
    pub n_addrs: u64,
    /// The PDB identifiers that have been downloaded & the associated file size
    /// in bytes.
    pub pdb_downloaded: HashMap<PdbId, u64>,
    /// The PE identifiers that have been downloaded & the associated file size
    /// in bytes.
    pub pe_downloaded: HashMap<PeId, u64>,
    /// The number of time the address cache was a hit.
    pub cache_hit: u64,
}

impl Stats {
    #[must_use]
    pub fn did_download_pdb(&self, pdb_id: &PdbId) -> bool {
        self.pdb_downloaded.contains_key(pdb_id)
    }

    #[must_use]
    pub fn did_download_pe(&self, pe_id: &PeId) -> bool {
        self.pe_downloaded.contains_key(pe_id)
    }

    #[must_use]
    pub fn amount_downloaded(&self) -> u64 {
        0u64.saturating_add(self.pe_downloaded.values().sum())
            .saturating_add(self.pdb_downloaded.values().sum())
    }

    #[must_use]
    pub fn pdb_download_count(&self) -> usize {
        self.pdb_downloaded.len()
    }

    #[must_use]
    pub fn pe_download_count(&self) -> usize {
        self.pe_downloaded.len()
    }

    pub fn downloaded_pdb(&mut self, pdb_id: PdbId, size: u64) {
        assert!(self.pdb_downloaded.insert(pdb_id, size).is_none());
    }

    pub fn downloaded_pe(&mut self, pe_id: PeId, size: u64) {
        assert!(self.pe_downloaded.insert(pe_id, size).is_none());
    }

    pub fn addr_symbolized(&mut self) {
        self.n_addrs += 1;
    }

    pub fn cache_hit(&mut self) {
        self.cache_hit += 1;
    }
}
