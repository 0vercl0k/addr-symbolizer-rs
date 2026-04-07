// Axel '0vercl0k' Souchet - February 20 2024
//! This module contains the implementation of the [`Symbolizer`] which is the
//! object that is able to symbolize files using PDB information if available.
use std::collections::HashMap;
use std::fs::{self, File};
use std::hash::{BuildHasher, Hasher};
use std::io::{self, BufWriter, Read, Seek, Write};
use std::path::{Path, PathBuf};

use log::{debug, info, trace, warn};

use crate::addr_space::AddrSpace;
use crate::misc::{fast_hex32, fast_hex64, parse_full_name};
use crate::modules::{Module, Modules};
use crate::pdbcache::{
    PdbCache, PdbCacheBuilder, PdbCacheStore, format_symcache_path, format_symsrv_url,
};
use crate::pe::{PdbId, Pe, PeId, SymcacheEntry};
use crate::stats::Stats;
use crate::{Error, Guid, Result};

#[derive(Debug)]
struct DownloadedFile {
    path: PathBuf,
    size: u64,
}

impl DownloadedFile {
    fn new(path: impl AsRef<Path>, size: u64) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            size,
        }
    }
}

/// Where did we find this PDB? On the file-system somewhere, in a local symbol
/// cache or downloaded on a symbol server.
///
/// This is used mainly to account for statistics; how many files were
/// downloaded, etc.
#[derive(Debug)]
enum PdbLocationKind {
    /// The PDB file was found on the file system but not in a symbol cache.
    Local,
    /// The PDB file was found on the file system in a local symbol cache.
    LocalCache,
    /// The PDB file was downloaded on a remote symbol server.
    Download(u64),
}

#[derive(Debug)]
struct PdbLocation {
    kind: PdbLocationKind,
    path: PathBuf,
}

impl PdbLocation {
    fn new(kind: PdbLocationKind, path: PathBuf) -> Self {
        Self { kind, path }
    }
}

/// Where did we find this PE? In a local symbol cache or downloaded on a symbol
/// server.
///
/// This is used mainly to account for statistics; how many files were
/// downloaded, etc.
#[derive(Debug)]
enum PeLocationKind {
    /// The PE file was found on the file system in a local symbol cache.
    LocalCache,
    /// The PE file was downloaded on a remote symbol server.
    Download(u64),
}

#[derive(Debug)]
struct PeLocation {
    kind: PeLocationKind,
    pdb_id: Option<PdbId>,
}

impl PeLocation {
    fn new(kind: PeLocationKind, pdb_id: Option<PdbId>) -> Self {
        Self { kind, pdb_id }
    }
}

/// Attempt to download a PE/PDB file from a list of symbol servers.
///
/// The code iterates through every symbol servers, and stops as soon as it was
/// able to download a matching file.
fn download_from_symsrv<'s>(
    symcache: impl AsRef<Path>,
    symsrvs: impl Iterator<Item = &'s str>,
    entry: &impl SymcacheEntry,
) -> Result<Option<DownloadedFile>> {
    // The way a symbol path is structured is that there is a directory per module..
    let symcache = symcache.as_ref();
    let entry_root_dir = symcache.join(entry.name());

    // ..and inside, there is a directory per version of the PE/PDB..
    let entry_dir = entry_root_dir.join(entry.index());

    // ..and finally the PE/PDB file itself.
    let entry_path = entry_dir.join(entry.name());

    // Give a try to each of the symbol servers.
    for symsrv in symsrvs {
        // The file doesn't exist on the file system, so let's try to download it from a
        // symbol server.
        let entry_url = format_symsrv_url(symsrv, entry);
        debug!("trying to download {entry_url}..");

        let resp = match ureq::get(&entry_url).call() {
            Ok(o) => o,
            // If we get a 404, it means that the server doesn't know about this file. So we'll skip
            // to the next symbol server.
            Err(ureq::Error::StatusCode(404)) => {
                warn!("got a 404 for {entry_url}");
                continue;
            }
            // If we received any other errors, well that's not expected so let's bail.
            Err(e) => {
                return Err(Error::Download {
                    entry_url,
                    e: e.into(),
                });
            }
        };

        // If the server knows about this file, it is time to create the directory
        // structure in which we'll download the file into.
        if !entry_dir.try_exists()? {
            debug!("creating {}..", entry_dir.display());
            fs::create_dir_all(&entry_dir).map_err(|_| {
                Error::Other(format!("failed to create pdb dir {}", entry_dir.display()))
            })?;
        }

        // Finally, we can download and save the file.
        let file = File::create(&entry_path)
            .map_err(|_| Error::Other(format!("failed to create {}", entry_path.display())))?;

        let size = io::copy(
            &mut resp.into_body().into_reader(),
            &mut BufWriter::new(file),
        )?;

        debug!("downloaded to {}", entry_path.display());
        return Ok(Some(DownloadedFile::new(entry_path, size)));
    }

    Ok(None)
}

/// Try to download a PE file off the symbol servers, and if one is found, try
/// to extract its PDB identifier.
fn get_pdb_id_from_symsrvs(
    pdb_lookup: &PdbLookupConfig,
    pe_id: &PeId,
) -> Result<Option<PeLocation>> {
    Ok(match pdb_lookup.symsrvs() {
        None => {
            // If we're offline, we're done.
            None
        }

        Some(symsrvs) => {
            struct FileAddrSpace(File);

            impl FileAddrSpace {
                fn new(path: impl AsRef<Path>) -> Result<Self> {
                    Ok(Self(File::open(path.as_ref())?))
                }
            }

            impl AddrSpace for FileAddrSpace {
                fn read_at(&mut self, addr: u64, buf: &mut [u8]) -> io::Result<usize> {
                    self.0.seek(io::SeekFrom::Start(addr))?;

                    self.0.read(buf)
                }
            }

            let symcache = &pdb_lookup.symcache;
            let mut pe_path = format_symcache_path(symcache, pe_id);
            let kind = if pe_path.exists() {
                PeLocationKind::LocalCache
            } else {
                // We didn't find a PE on disk, so last resort is to try to download it.
                let Some(downloaded) = download_from_symsrv(symcache, symsrvs, pe_id)? else {
                    debug!("did not find {pe_id} on any symbol server");
                    return Ok(None);
                };

                pe_path = downloaded.path;

                PeLocationKind::Download(downloaded.size)
            };

            debug!("trying to parse {} from disk..", pe_path.display());
            let mut addr_space = FileAddrSpace::new(pe_path)?;
            let pe_file = Pe::new(&mut addr_space, 0)?;
            let pdb_id = pe_file.read_pdbid(&mut addr_space)?;

            debug!("PDB id parsed from the PE: {pdb_id:?}");

            Some(PeLocation::new(kind, pdb_id))
        }
    })
}

/// Try to find a PDB file online or locally from a [`PdbId`].
fn get_pdb(pdb_lookup: &PdbLookupConfig, pdb_id: &PdbId) -> Result<Option<PdbLocation>> {
    // Let's see if the path exists locally..
    if pdb_id.path.is_file() {
        // .. if it does, this is a 'Local' PDB.
        return Ok(Some(PdbLocation::new(
            PdbLocationKind::Local,
            pdb_id.path.clone(),
        )));
    }

    // Now, let's see if it's in the local cache..
    let symcache = &pdb_lookup.symcache;
    let local_path = format_symcache_path(symcache, pdb_id);
    if local_path.is_file() {
        // .. if it does, this is a 'LocalCache' PDB.
        return Ok(Some(PdbLocation::new(
            PdbLocationKind::LocalCache,
            local_path,
        )));
    }

    Ok(match pdb_lookup.symsrvs() {
        None => {
            // If we're offline, let's just skip the downloading part.
            None
        }
        Some(symsrvs) => {
            // We didn't find a PDB on disk, so last resort is to try to download it.
            let downloaded_path = download_from_symsrv(symcache, symsrvs, pdb_id)?;

            downloaded_path
                .map(|file| PdbLocation::new(PdbLocationKind::Download(file.size), file.path))
        }
    })
}

/// A simple 'hasher' that uses the input bytes as a hash.
///
/// This is used for the cache `HashMap` used in the [`Symbolizer`]. We are
/// caching symbol addresses and so we know those addresses are unique and do
/// not need to be hashed.
#[derive(Default)]
struct IdentityHasher {
    h: u64,
}

impl Hasher for IdentityHasher {
    fn finish(&self) -> u64 {
        self.h
    }

    fn write(&mut self, bytes: &[u8]) {
        debug_assert_eq!(bytes.len(), 8);

        self.h = u64::from_le_bytes(bytes.try_into().unwrap());
    }
}

impl BuildHasher for IdentityHasher {
    type Hasher = Self;

    fn build_hasher(&self) -> Self::Hasher {
        Self::default()
    }
}

/// The logic in here has been extracted from the [`Symbolizer`] class to
/// satisfy the borrow checker and avoid having free functions taking 5+
/// arguments.
struct SymbolizerInner<'symbolizer> {
    stats: &'symbolizer mut Stats,
    pdb_lookup: &'symbolizer PdbLookupConfig,
    pdbcache_store: &'symbolizer mut PdbCacheStore,
}

impl<'symbolizer> SymbolizerInner<'symbolizer> {
    fn new(
        stats: &'symbolizer mut Stats,
        pdb_lookup: &'symbolizer PdbLookupConfig,
        pdbcache_store: &'symbolizer mut PdbCacheStore,
    ) -> Self {
        Self {
            stats,
            pdb_lookup,
            pdbcache_store,
        }
    }

    fn get_or_create_module_pdbcache(
        &'symbolizer mut self,
        addr_space: &mut impl AddrSpace,
        module: &Module,
    ) -> Result<&'symbolizer PdbCache> {
        let create_pdbcache = || -> Result<PdbCache> {
            let mut builder = PdbCacheBuilder::new(module);

            // Let's start by parsing the PE to get its exports, and PDB information if
            // there's any.
            let pe = Pe::new(addr_space, module.at.start)?;

            // Ingest the EAT.
            builder.ingest(pe.read_exports(addr_space)?.unwrap_or_default());

            // See if it has PDB information. If it doesn't try to download the
            // original PE file off symbol servers.
            let pdb_id = pe.read_pdbid(addr_space).and_then(|pdb_id| {
                if pdb_id.is_some() {
                    return Ok(pdb_id);
                }

                let pe_id = PeId::new(&module.name, pe.timestamp, pe.size);
                trace!("No PDB information found, trying to download PE file for {pe_id}..");

                let downloaded_pe = get_pdb_id_from_symsrvs(self.pdb_lookup, &pe_id)?;

                Ok(downloaded_pe.and_then(|d| {
                    if let PeLocationKind::Download(size) = d.kind {
                        self.stats.downloaded_pe(pe_id, size);
                    }

                    d.pdb_id
                }))
            })?;

            if let Some(pdb_id) = pdb_id {
                trace!("getting PDB information for {module:?}/{pdb_id}..");

                // Try to get a PDB..
                if let Some(downloaded_pdb) = get_pdb(self.pdb_lookup, &pdb_id)? {
                    if let PdbLocationKind::Download(size) = downloaded_pdb.kind {
                        self.stats.downloaded_pdb(pdb_id, size);
                    }

                    // .. and ingest it if we have one.
                    trace!("Ingesting PDB..");
                    builder.ingest_pdb(downloaded_pdb.path)?;
                }
            }

            // Build the cache..
            let pdbcache = builder.build()?;

            Ok(pdbcache)
        };

        self.pdbcache_store.get_or_create(module, create_pdbcache)
    }

    /// Try to symbolize an address.
    ///
    /// If there's a [`PdbCache`] already created, then ask it to symbolize.
    /// Otherwise, this will create a [`PdbCache`], try to find a PDB (locally
    /// or remotely) and extract every bit of relevant information for us.
    /// Finally, the result will be kept around to symbolize addresses in that
    /// module faster in the future.
    fn try_symbolize_addr_from_pdbs(
        &'symbolizer mut self,
        addr_space: &mut impl AddrSpace,
        module: &Module,
        addr: u64,
    ) -> Result<Option<String>> {
        trace!("symbolizing address {addr:#x} from {}..", module.name);

        // Get a pdbcache..
        let pdbcache = self.get_or_create_module_pdbcache(addr_space, module)?;

        // .. and symbolize `addr`!
        let line = pdbcache.symbolize(module.rva(addr));

        Ok(Some(line))
    }
}

/// Holds the details of where PDBs can be looked up from; both locally and
/// online if possible.
#[derive(Debug)]
pub struct PdbLookupConfig {
    /// This is a path to the local PDB symbol cache where PDBs will be
    /// downloaded into / where some are available.
    symcache: PathBuf,
    /// List of symbol servers to try to download PDBs from when needed.
    symsrvs: Option<Vec<String>>,
}

impl PdbLookupConfig {
    fn inner_new(symcache: PathBuf, symsrvs: Option<Vec<String>>) -> Result<Self> {
        if !symcache.is_dir() {
            return Err(Error::Other(format!(
                "{} directory does not exist",
                symcache.display()
            )));
        }

        Ok(Self { symcache, symsrvs })
    }

    pub fn new(symcache: PathBuf) -> Result<Self> {
        Self::inner_new(symcache, None)
    }

    pub fn with_msft_symsrv(symcache: PathBuf) -> Result<Self> {
        Self::with_symsrvs(symcache, vec![
            "https://msdl.microsoft.com/download/symbols/".to_string(),
        ])
    }

    pub fn with_symsrvs(symcache: PathBuf, symsrvs: Vec<String>) -> Result<Self> {
        Self::inner_new(symcache, Some(symsrvs))
    }

    #[must_use]
    pub fn symcache(&self) -> &Path {
        &self.symcache
    }

    #[must_use]
    pub fn is_offline(&self) -> bool {
        self.symsrvs.is_none()
    }

    #[must_use]
    pub fn is_online(&self) -> bool {
        self.symsrvs.is_some()
    }

    fn symsrvs(&self) -> Option<impl Iterator<Item = &str>> {
        self.symsrvs
            .as_ref()
            .map(|symsrvs| symsrvs.iter().map(AsRef::as_ref))
    }
}

/// The [`Symbolizer`] is the main object that glues all the logic.
///
/// It downloads, parses PDB information, and symbolizes.
pub struct Symbolizer {
    /// Keep track of some statistics such as the number of lines symbolized,
    /// PDB downloaded, etc.
    stats: Stats,
    /// This is the list of kernel / user modules read from the kernel crash
    /// dump.
    modules: Modules,
    /// List of symbol servers to try to download PDBs from when needed.
    pdb_lookup: PdbLookupConfig,
    /// Caches addresses to symbols. This allows us to not have to symbolize an
    /// address again.
    addr_cache: HashMap<u64, Box<str>, IdentityHasher>,
    /// Each parsed module is stored in this cache. We parse PDBs, etc. only
    /// once and then the [`PdbCache`] is used to query.
    pdbcache_store: PdbCacheStore,
}

impl Symbolizer {
    /// Create a [`Symbolizer`].
    #[must_use]
    pub fn new(pdb_lookup: PdbLookupConfig, modules: impl IntoIterator<Item = Module>) -> Self {
        let modules = modules.into_iter().collect();

        Self {
            stats: Stats::default(),
            modules: Modules::new(modules),
            pdb_lookup,
            addr_cache: HashMap::default(),
            pdbcache_store: PdbCacheStore::default(),
        }
    }

    pub fn with_cache_capacity(
        pdb_lookup: PdbLookupConfig,
        modules: impl IntoIterator<Item = Module>,
        cache_capacity_hint: usize,
    ) -> Self {
        let modules = modules.into_iter().collect();
        let addr_cache =
            HashMap::with_capacity_and_hasher(cache_capacity_hint, IdentityHasher::default());

        Self {
            stats: Stats::default(),
            modules: Modules::new(modules),
            pdb_lookup,
            addr_cache,
            pdbcache_store: PdbCacheStore::default(),
        }
    }

    /// Get [`Stats`].
    #[must_use]
    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Try to symbolize an address.
    ///
    /// If the address has been symbolized before, it will be in the
    /// `addr_cache` already. If not, we need to take the slow path and ask the
    /// right [`PdbCache`] which might require to create one in the first place.
    fn try_symbolize_addr(
        &mut self,
        addr_space: &mut impl AddrSpace,
        addr: u64,
    ) -> Result<Option<&str>> {
        use std::collections::hash_map::Entry::{Occupied, Vacant};
        Ok(match self.addr_cache.entry(addr) {
            Occupied(o) => {
                self.stats.cache_hit();

                Some(o.into_mut())
            }
            Vacant(v) => {
                let Some(module) = self.modules.by_addr(addr) else {
                    trace!("address {addr:#x} doesn't belong to any module");
                    return Ok(None);
                };

                let mut inner = SymbolizerInner::new(
                    &mut self.stats,
                    &self.pdb_lookup,
                    &mut self.pdbcache_store,
                );

                let Some(symbol) = inner.try_symbolize_addr_from_pdbs(addr_space, module, addr)?
                else {
                    return Ok(None);
                };

                Some(v.insert(symbol.into_boxed_str()))
            }
        })
    }

    /// Symbolize `addr` in the `module+offset` style.
    pub fn symbolize_modoff(&mut self, addr: u64) -> Result<String> {
        let mut modoff = Vec::new();
        self.symbolize_modoff_into(addr, &mut modoff)?;

        Ok(String::from_utf8(modoff)?)
    }

    /// Symbolize `addr` in the `module!function+offset` style.
    pub fn symbolize_full(&mut self, addr_space: &mut impl AddrSpace, addr: u64) -> Result<String> {
        let mut full = Vec::new();
        self.symbolize_full_into(addr_space, addr, &mut full)?;

        Ok(String::from_utf8(full)?)
    }

    /// Symbolize `addr` in the `module+offset` style and write the result into
    /// `output`.
    pub fn symbolize_modoff_into(&mut self, addr: u64, output: &mut impl Write) -> Result<()> {
        let mut buffer = [0; 16];
        if let Some(module) = self.modules.by_addr(addr) {
            output.write_all(module.name.as_bytes())?;
            output.write_all(b"+0x")?;

            output.write_all(fast_hex32(
                &mut buffer[0..8].try_into().unwrap(),
                module.rva(addr),
            ))
        } else {
            output.write_all(b"0x")?;

            output.write_all(fast_hex64(&mut buffer, addr))
        }
        .map_err(|_| Error::Other("failed to write symbolized value to output".to_string()))?;

        self.stats.addr_symbolized();

        Ok(())
    }

    /// Symbolize `addr` in the `module!function+offset` style and write the
    /// result into `output`.
    pub fn symbolize_full_into(
        &mut self,
        addr_space: &mut impl AddrSpace,
        addr: u64,
        output: &mut impl Write,
    ) -> Result<()> {
        match self.try_symbolize_addr(addr_space, addr)? {
            Some(sym) => {
                output.write_all(sym.as_bytes()).map_err(|_| {
                    Error::Other("failed to write symbolized value to output".to_string())
                })?;

                self.stats.addr_symbolized();

                Ok(())
            }
            None => self.symbolize_modoff_into(addr, output),
        }
    }

    /// Resolves a symbol name (eg `mod.dll!foo+0x1337` / `mod.dll+0x1337`) into
    /// an address.
    pub fn name_to_addr(
        &mut self,
        addr_space: &mut impl AddrSpace,
        name: &str,
    ) -> Result<Option<u64>> {
        let Some(parsed_name) = parse_full_name(name) else {
            return Err(Error::Other(format!("failed to parse {name}")));
        };

        let Some(module) = self.modules.by_name(parsed_name.module_name) else {
            return Ok(None);
        };

        let mut inner =
            SymbolizerInner::new(&mut self.stats, &self.pdb_lookup, &mut self.pdbcache_store);

        let pdbcache = inner.get_or_create_module_pdbcache(addr_space, module)?;

        Ok(pdbcache
            .addr_by_name(parsed_name.function_name)
            .map(|base_addr| u64::from(base_addr).strict_add(parsed_name.offset)))
    }

    /// Imports PDBs from other directory into the symcache that is used by this
    /// [`Symbolizer`].
    pub fn import_pdbs(&self, dirs: impl IntoIterator<Item = impl AsRef<Path>>) -> Result<()> {
        for dir in dirs {
            let dir = dir.as_ref();
            if !(dir.exists() && dir.is_dir()) {
                return Err(Error::Other(format!(
                    "cannot import pdb from {} as it doesn't exist or isn't a directory",
                    dir.display()
                )));
            }

            for file in dir.read_dir()? {
                let path = file?.path();
                if !path.is_file() {
                    debug!("skipping {} because not a file", path.display());
                    continue;
                }

                let Some(ext) = path.extension() else {
                    debug!(
                        "skipping {} because doesn't have an extension",
                        path.display()
                    );
                    continue;
                };

                if ext != "pdb" {
                    debug!("skipping {} because not a pdb file", path.display());
                    continue;
                }

                let Some(filename) = path.file_name() else {
                    debug!("skipping {} because no filename", path.display());
                    continue;
                };

                let mut pdb = pdb2::PDB::open(File::open(&path)?)?;
                let info = pdb.pdb_information()?;
                let debug_info = pdb.debug_information()?;
                let Some(age) = debug_info.age() else {
                    debug!("skipping {} because no age in debug info", path.display());
                    continue;
                };

                let pdbid = PdbId::new(filename, Guid::from(info.guid.to_bytes_le()), age)?;
                let cached_pdb = format_symcache_path(self.pdb_lookup.symcache(), &pdbid);
                if cached_pdb.exists() {
                    debug!(
                        "skipping {} because already in symbol cache",
                        path.display()
                    );
                    continue;
                }

                let Some(cached_pdb_dir) = cached_pdb.parent() else {
                    return Err(Error::Other(format!(
                        "{} has no parent",
                        cached_pdb.display()
                    )));
                };

                info!(
                    "copying {} into the symbol cache at {}",
                    path.display(),
                    cached_pdb.display()
                );
                fs::create_dir_all(cached_pdb_dir)?;
                fs::copy(path, cached_pdb)?;
            }
        }

        Ok(())
    }
}
