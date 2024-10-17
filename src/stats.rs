// Axel '0vercl0k' Souchet - April 21 2024
//! This module contains the [`Stats`] type that is used to keep track of
//! various statistics when symbolizing.
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Debug;

use crate::pe::{PdbId, PeId};

#[derive(Debug, Default)]
pub struct StatsBuilder {
    inner: RefCell<Stats>,
}

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
    pub fn did_download_pdb(&self, pdb_id: PdbId) -> bool {
        self.pdb_downloaded.contains_key(&pdb_id)
    }

    pub fn did_download_pe(&self, pe_id: PeId) -> bool {
        self.pe_downloaded.contains_key(&pe_id)
    }

    pub fn amount_downloaded(&self) -> u64 {
        let mut total = 0u64;
        for value in self.pdb_downloaded.values() {
            total = total.saturating_add(*value);
        }

        total
    }

    pub fn amount_pdb_downloaded(&self) -> usize {
        self.pdb_downloaded.len()
    }

    pub fn amount_pe_downloaded(&self) -> usize {
        self.pe_downloaded.len()
    }
}

impl StatsBuilder {
    pub fn build(&self) -> Stats {
        self.inner.borrow().clone()
    }

    pub fn downloaded_pdb(&self, pdb_id: PdbId, size: u64) {
        assert!(self
            .inner
            .borrow_mut()
            .pdb_downloaded
            .insert(pdb_id, size)
            .is_none());
    }

    pub fn downloaded_pe(&self, pe_id: PeId, size: u64) {
        assert!(self
            .inner
            .borrow_mut()
            .pe_downloaded
            .insert(pe_id, size)
            .is_none());
    }

    pub fn addr_symbolized(&self) {
        self.inner.borrow_mut().n_addrs += 1;
    }

    pub fn cache_hit(&self) {
        self.inner.borrow_mut().cache_hit += 1;
    }
}
