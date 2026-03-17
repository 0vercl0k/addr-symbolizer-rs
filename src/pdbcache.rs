// Axel '0vercl0k' Souchet - February 23 2024
//! This module contains the implementation of the [`PdbCache`] which is the
//! object that keeps track of all the information needed to symbolize an
//! address. It extracts it out of a PDB file and doesn't require it to be
//! around.
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::fs::File;
use std::ops::Range;
use std::path::{Path, PathBuf};

use log::{trace, warn};
use pdb2::{
    AddressMap, FallibleIterator, LineProgram, PdbInternalSectionOffset, ProcedureSymbol,
    StringTable, Symbol,
};

use crate::Error;
use crate::error::Result;
use crate::misc::{Rva, elyxir_of_life};
use crate::modules::Module;
use crate::pe::SymcacheEntry;

/// Format a symbol cache path for a PE/PDB.
///
/// Here is an example for a PE:
/// ```text
/// C:\work\dbg\sym\hal.dll\4252FF428c000\hal.dll
/// ^^^^^^^^^^^^^^^ ^^^^^^^ ^^^^^^^^^^^^^ ^^^^^^^
///   cache path    PE name Timestamp Size PE name
/// ```
///
/// Here is an example for a PDB:
/// ```text
/// C:\work\dbg\sym\ntfs.pdb\64D20DCBA29FFC0CD355FFE7440EC5F81\ntfs.pdb
/// ^^^^^^^^^^^^^^^ ^^^^^^^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ ^^^^^^^^
///   cache path    PDB name PDB GUID & PDB Age                PDB name
/// ```
pub(crate) fn format_symcache_path(symcache: &Path, entry: &impl SymcacheEntry) -> PathBuf {
    symcache
        .join(entry.name())
        .join(entry.index())
        .join(entry.name())
}

/// Format a URL to find a PE/PDB on an HTTP symbol server.
pub(crate) fn format_symsrv_url(symsrv: &str, entry: &impl SymcacheEntry) -> String {
    format!(
        "{symsrv}/{}/{}/{}",
        entry.name(),
        entry.index(),
        entry.name()
    )
}

/// A PDB opened via file access.
type Pdb<'p> = pdb2::PDB<'p, File>;

/// A line of source code.
///
/// It maps an offset in the function (like offset
/// `0x1122`) to a line number in a file (like `foo.c:1336`).
#[derive(Default, Debug)]
struct Line {
    /// Offset from the start of the function it's part of.
    offset: u32,
    /// The line number.
    number: Rva,
    /// Most lines in a function are part of the same file which is stored in
    /// the [`SourceInfo`] which contains the lines info. But in case, this line
    /// is stored in a different file, this is its path.
    override_path: Option<Box<str>>,
}

impl Line {
    /// Build a [`Line`].
    fn new(offset: Rva, number: u32, override_path: Option<String>) -> Self {
        let override_path = override_path.map(String::into_boxed_str);

        Self {
            offset,
            number,
            override_path,
        }
    }
}

/// Information related to source code.
///
/// It contains the path to the source code file as well as a mapping between
/// offsets to line number.
#[derive(Debug, Default)]
struct SourceInfo {
    path: Box<str>,
    lines: Box<[Line]>,
}

impl SourceInfo {
    /// Build a [`SourceInfo`].
    fn new(path: String, mut lines: Vec<Line>) -> Self {
        // We assume we have at least one entry in the vector.
        assert!(!lines.is_empty());
        let path = path.into_boxed_str();

        lines.sort_unstable_by_key(|line| line.offset);
        let lines = lines.into_boxed_slice();

        Self { path, lines }
    }

    /// Find the line number associated to a raw offset from inside a function.
    fn line(&self, offset: Rva) -> &Line {
        let idx = self.lines.partition_point(|line| line.offset <= offset);

        if idx == self.lines.len() {
            self.lines.last().unwrap()
        } else {
            &self.lines[idx - 1]
        }
    }
}

/// A function.
///
/// It has a name and if available, information related to the file where the
/// function is implemented as well as the line of code.
#[derive(Default, Debug)]
struct FuncSymbol {
    name: Box<str>,
    source_info: Option<SourceInfo>,
}

impl FuncSymbol {
    fn new(name: Box<str>, source_info: Option<SourceInfo>) -> Self {
        Self { name, source_info }
    }
}

impl From<BuilderEntry> for FuncSymbol {
    fn from(value: BuilderEntry) -> Self {
        FuncSymbol::new(value.name, value.source_info)
    }
}

/// Stores lookup tables to be able to go from [`Rva`] to [`FuncSymbol`]/name,
/// and from name to [`Rva`].
///
/// SAFETY: The structure is self referential to be able to implement the name
/// to [`Rva`] lookup (`names_to_symbols`).
#[expect(non_camel_case_types)]
struct DANGEROUS_InnerPdbCache {
    /// This maps a symbol name to an index. This index can be used to get an
    /// address range by reading `addrs`, or a [`FuncSymbol`] by reading
    /// `symbols`.
    ///
    /// SAFETY: The string slice references aren't static and are backed by the
    /// `name` `Box<str>` in [`FuncSymbol`]. This means those locations cannot
    /// move; so mutating `symbols` or [`FuncSymbol`].name is forbidden. All
    /// those references are acquired once the `symbols` vector has been fully
    /// built up as well.
    ///
    /// Miri tests at the bottom of this file.
    names_to_symbols: HashMap<&'static str, usize>,
    /// Ordered ranges of function RVAs. The same index used can also be used to
    /// index into `symbols`. `addrs[n]` gives you the range of a function, and
    /// `symbols[n]` gives you the associated [`FuncSymbol`].
    addrs: Vec<Range<Rva>>,
    /// Vector of [`FuncSymbol`] that is synchronized with the `addrs` vector.
    /// `symbols[n]` give you a [`FuncSymbol`] describing a function and
    /// `addrs[n]` gives you its range.
    symbols: Vec<FuncSymbol>,
    /// Name of the module for which this cache was created for.
    module_name: Box<str>,
}

impl DANGEROUS_InnerPdbCache {
    fn new(module_name: String, mut symbols: Vec<(Range<Rva>, FuncSymbol)>) -> Self {
        symbols.sort_unstable_by_key(|(range, _)| range.end);
        let skip_invalid = {
            let mut last_range = 0..0;

            move |(range, _): &(Range<Rva>, FuncSymbol)| {
                // Skip empty ranges, and overlapping ranges.
                let valid_range = !range.is_empty() && range.start >= last_range.end;
                last_range = range.clone();

                valid_range
            }
        };

        let (addrs, symbols): (Vec<_>, Vec<_>) = symbols.into_iter().filter(skip_invalid).unzip();
        let names_to_symbols = HashMap::with_capacity(addrs.len());
        let module_name = module_name.into_boxed_str();

        let mut meself = Self {
            names_to_symbols,
            addrs,
            symbols,
            module_name,
        };

        for (idx, symbol) in meself.symbols.iter().enumerate() {
            // SAFETY: The backing store of slice is in a `Box<str>`, therefore has a
            // constant address and the references will be valid as long as the backing
            // store.
            let immortal_name = unsafe { elyxir_of_life(&symbol.name) };
            meself.names_to_symbols.insert(immortal_name, idx);
        }

        meself
    }

    /// Find a symbol that contains `rva`.
    fn sym_by_addr(&self, rva: Rva) -> Option<(Rva, &FuncSymbol)> {
        let idx = self.addrs.partition_point(|probe| probe.end <= rva);
        if idx == self.addrs.len() {
            return None;
        }

        let range = &self.addrs[idx];
        let func = &self.symbols[idx];

        if range.contains(&rva) {
            Some((range.start, func))
        } else {
            None
        }
    }

    /// Find the start address of a function by its name.
    fn addr_by_name(&self, name: &str) -> Option<Rva> {
        self.names_to_symbols
            .get(name)
            .map(|idx| self.addrs[*idx].start)
    }
}

/// A PDB cache.
///
/// It stores all the information about the functions defined in a module. It
/// extracts everything it can off a PDB and then toss it as a PDB file is
/// larger than a [`PdbCache`] (as we don't care about types, variables, etc.).
pub(crate) struct PdbCache {
    inner: DANGEROUS_InnerPdbCache,
}

impl Debug for PdbCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PdbCache")
            .field("module_name", &self.inner.module_name)
            .finish_non_exhaustive()
    }
}

impl PdbCache {
    fn new(module_name: String, symbols: Vec<(Range<Rva>, FuncSymbol)>) -> Self {
        let inner = DANGEROUS_InnerPdbCache::new(module_name, symbols);

        Self { inner }
    }

    /// Find a symbol that contains `rva`.
    fn sym_by_addr(&self, rva: Rva) -> Option<(Rva, &FuncSymbol)> {
        self.inner.sym_by_addr(rva)
    }

    /// Find the start address of a function by its name.
    pub fn addr_by_name(&self, name: &str) -> Option<Rva> {
        self.inner.addr_by_name(name)
    }

    /// Symbolize a raw address.
    ///
    /// This pulls as much information as possible and use any private symbols
    /// if there were any.
    pub fn symbolize(&self, rva: Rva) -> String {
        // Find the function in which this `rva` is in.
        let Some((func_rva, func_symbol)) = self.sym_by_addr(rva) else {
            // If we can't find one, we'll just return `module.dll+rva`.
            return format!("{}+{:#x}", self.inner.module_name, rva);
        };

        debug_assert!(
            rva >= func_rva,
            "The function RVA should always be smaller or equal to the instruction RVA"
        );

        // Calculate the instruction offset.
        let instr_offset = rva - func_rva;

        // Generate the symbolized version.
        if let Some(source_info) = &func_symbol.source_info {
            // If we know which source file this is implemented in and at what line number,
            // then let's use it..
            let line = source_info.line(instr_offset);
            let path = line.override_path.as_deref().unwrap_or(&source_info.path);

            format!(
                "{}!{}+{instr_offset:#x} [{path} @ {}]",
                self.inner.module_name, func_symbol.name, line.number
            )
        } else {
            // ..or do without if it's not present.
            format!(
                "{}!{}+{instr_offset:#x}",
                self.inner.module_name, func_symbol.name
            )
        }
    }
}

#[derive(Debug)]
struct BuilderEntry {
    name: Box<str>,
    len: Option<u32>,
    source_info: Option<SourceInfo>,
}

impl BuilderEntry {
    fn new(name: String, len: Option<u32>, source_info: Option<SourceInfo>) -> Self {
        let name = name.into_boxed_str();

        Self {
            name,
            len,
            source_info,
        }
    }

    fn from_name(name: String) -> Self {
        Self::new(name, None, None)
    }

    fn len(&self) -> Option<u32> {
        self.len
    }
}

/// A [`PdbCache`] builder.
///
/// Ultimately, we try to get as much information possible on modules with what
/// we have. Sometimes, we have public symbols, something we have private
/// symbols and.. sometimes we have nothing (just its PE). If we're dealing with
/// just information extracted from the PE or the public symbols, we have no
/// available information regarding function sizes.
///
/// To work around this issue, what we do is we aggregate all the information in
/// a data structure ordered by the function address. Once we're done, we walk
/// this data structure and we calculate the size of the current function by
/// 'filling the hole' up to the next function. This is innacurate but is the
/// only heuristic I had in store.
///
/// Once we have a list of functions with assigned sizes, we can finally build
/// the [`PdbCache`] structure.
#[derive(Debug)]
pub(crate) struct PdbCacheBuilder<'module> {
    /// The module for which this symbol cache is for.
    module: &'module Module,
    /// Basically all the information we've extracted so far.
    ///
    /// The key is the [`Rva`] of where the module starts, and the value is a
    /// [`BuilderEntry`] which describes the symbol with more details.
    symbols: BTreeMap<Rva, BuilderEntry>,
}

impl<'module> PdbCacheBuilder<'module> {
    pub fn new(module: &'module Module) -> Self {
        Self {
            module,
            symbols: BTreeMap::new(),
        }
    }

    /// Ingest a bunch of symbols.
    ///
    /// The key is the start [`Rva`] of the symbol, and the value is its name.
    /// This is used to ingest for example a list of functions acquired from the
    /// EAT of a module.
    pub fn ingest(&mut self, symbols: impl IntoIterator<Item = (Rva, String)>) {
        for (start, name) in symbols {
            self.symbols.insert(start, BuilderEntry::from_name(name));
        }
    }

    /// Parse a [`ProcedureSymbol`].
    fn parse_procedure_symbol(
        &mut self,
        proc: &ProcedureSymbol,
        address_map: &AddressMap,
        string_table: &StringTable,
        line_program: &LineProgram,
    ) -> Result<()> {
        let proc_name = proc.name.to_string();
        let Some(pdb2::Rva(proc_rva)) = proc.offset.to_rva(address_map) else {
            warn!(
                "failed to get rva for procedure symbol {} / {:?}, skipping",
                proc_name, proc.offset
            );

            return Ok(());
        };

        let mut lines_it = line_program.lines_for_symbol(proc.offset);
        let mut main_path = None;
        let mut lines = Vec::new();
        while let Some(line) = lines_it.next()? {
            let Some(pdb2::Rva(line_rva)) = line.offset.to_rva(address_map) else {
                warn!(
                    "failed to get rva for procedure symbol {} / {:?}, skipping",
                    proc_name, proc.offset
                );
                continue;
            };

            let file_info = line_program.get_file_info(line.file_index)?;
            let override_path = if let Some(main_path) = &main_path {
                let new_path = file_info.name.to_string_lossy(string_table)?;
                if main_path == &new_path {
                    None
                } else {
                    Some(new_path.into_owned())
                }
            } else {
                main_path = Some(file_info.name.to_string_lossy(string_table)?.into_owned());

                None
            };

            if line_rva < proc_rva {
                warn!("symbol {proc_name} has confusing line information, skipping");
                return Ok(());
            }

            let line_offset = line_rva - proc_rva;
            lines.push(Line::new(line_offset, line.line_start, override_path));
        }

        self.ingest_symbol(
            address_map,
            proc_name,
            proc.offset,
            Some(proc.len),
            main_path.map(|p| SourceInfo::new(p, lines)),
        )
    }

    /// Ingest a symbol with a name.
    fn ingest_symbol_with_name(
        &mut self,
        address_map: &AddressMap,
        name: Cow<str>,
        offset: PdbInternalSectionOffset,
    ) -> Result<()> {
        self.ingest_symbol(address_map, name, offset, None, None)
    }

    /// Ingest a symbol with a name and a length.
    fn ingest_symbol_with_len(
        &mut self,
        address_map: &AddressMap,
        name: Cow<str>,
        offset: PdbInternalSectionOffset,
        len: u32,
    ) -> Result<()> {
        self.ingest_symbol(address_map, name, offset, Some(len), None)
    }

    /// Ingest a symbol.
    ///
    /// Some symbols have a length, some don't, some have source information,
    /// some don't.
    fn ingest_symbol(
        &mut self,
        address_map: &AddressMap,
        name: Cow<str>,
        offset: PdbInternalSectionOffset,
        len: Option<u32>,
        source_info: Option<SourceInfo>,
    ) -> Result<()> {
        use std::collections::btree_map::Entry;

        use msvc_demangler::DemangleFlags as DF;

        let undecorated_name = if name.as_bytes().starts_with(b"?") {
            // Demangle the name if it starts by a '?'.
            match msvc_demangler::demangle(&name, DF::NAME_ONLY) {
                Ok(o) => o,
                Err(e) => {
                    // Let's log the failures as warning because we might care one day?
                    trace!("failed to demangle {name}: {e}");

                    // But if it failed, returning the mangled name is better than nothing.
                    name.into_owned()
                }
            }
        } else {
            // If it isn't a mangled name, then do.. nothing!
            name.into()
        };

        // Get the RVA..
        let pdb2::Rva(rva) = offset.to_rva(address_map).ok_or_else(|| {
            Error::Other(format!(
                "failed to get rva from symbol {undecorated_name} / {offset:?}, skipping"
            ))
        })?;

        //.. and build an entry for this function.
        match self.symbols.entry(rva) {
            Entry::Vacant(v) => {
                v.insert(BuilderEntry::new(undecorated_name, len, source_info));
            }
            Entry::Occupied(mut o) => {
                // If we have a len and we didn't have one before, let's grab it..
                let mut updated = false;
                if o.get().len.is_none() && len.is_some() {
                    o.get_mut().len = len;
                    updated = true;
                }

                // ..and same with `source_info`.
                if o.get().source_info.is_none() && source_info.is_some() {
                    o.get_mut().source_info = source_info;
                    updated = true;
                }

                if !updated {
                    trace!(
                        "symbol {undecorated_name:?} in dbi has a duplicate at {rva:#x} ({o:?}, skipping"
                    );
                }
            }
        }

        Ok(())
    }

    /// Parse a [`Symbol`].
    fn parse_symbol(
        &mut self,
        address_map: &AddressMap,
        symbol: &Symbol,
        extra: Option<(&StringTable, &LineProgram)>,
    ) -> Result<()> {
        use pdb2::SymbolData as SD;
        match symbol.parse()? {
            SD::Procedure(procedure) => {
                let (string_table, line_program) = extra.unwrap();
                self.parse_procedure_symbol(&procedure, address_map, string_table, line_program)?;
            }
            SD::Public(public) => {
                self.ingest_symbol_with_name(address_map, public.name.to_string(), public.offset)?;
            }
            SD::Thunk(thunk) => {
                self.ingest_symbol_with_len(
                    address_map,
                    thunk.name.to_string(),
                    thunk.offset,
                    thunk.len.into(),
                )?;
            }
            _ => {}
        }

        Ok(())
    }

    /// Parse the debug information stream which is where private symbols are
    /// stored in.
    fn parse_dbi(&mut self, pdb: &mut Pdb, address_map: &AddressMap) -> Result<()> {
        // If we don't have a string table, there is no point in parsing the debug
        // information stream.
        let Ok(string_table) = pdb.string_table() else {
            return Ok(());
        };

        // Grab the debug information stream..
        let dbi = pdb
            .debug_information()
            .map_err(|e| Error::Other(format!("failed to get dbi: {e}")))?;
        // ..and grab / walk through the 'modules'.
        let mut module_it = dbi.modules()?;
        while let Some(module) = module_it.next()? {
            // Get information about the module; such as its path, its symbols, etc.
            let Some(info) = pdb.module_info(&module)? else {
                warn!("no module info: {:?}", &module);
                continue;
            };

            let program = info.line_program()?;
            let mut sym_it = info.symbols()?;
            while let Some(symbol) = sym_it.next()? {
                if let Err(e) =
                    self.parse_symbol(address_map, &symbol, Some((&string_table, &program)))
                {
                    warn!("parsing {symbol:?} failed with {e:?}, ignoring");
                }
            }
        }

        Ok(())
    }

    /// Parse the global symbols stream where public symbols are stored at.
    fn parse_global_symbols_table(
        &mut self,
        pdb: &mut Pdb,
        address_map: &AddressMap,
    ) -> Result<()> {
        let global_symbols = pdb.global_symbols()?;
        let mut symbol_it = global_symbols.iter();
        while let Some(symbol) = symbol_it.next()? {
            if let Err(e) = self.parse_symbol(address_map, &symbol, None) {
                warn!("parsing {symbol:?} failed with {e:?}, ignoring");
            }
        }

        Ok(())
    }

    /// Ingest a PDB file stored on the file system.
    pub fn ingest_pdb(&mut self, pdb_path: impl AsRef<Path>) -> Result<()> {
        // Open the PDB file.
        let pdb_path = pdb_path.as_ref();
        let pdb_file = File::open(pdb_path)
            .map_err(|e| Error::Other(format!("failed to open pdb {}: {e}", pdb_path.display())))?;
        let mut pdb = Pdb::open(pdb_file).map_err(|e| {
            Error::Other(format!("failed to parse pdb {}: {e}", pdb_path.display()))
        })?;

        trace!("ingesting {}..", pdb_path.display());

        let address_map = pdb.address_map()?;
        // Parse and extract all the bits we need from the private symbols first. We do
        // this first, because procedures have a length field which isn't the case for
        // global symbols. And if there's duplicates, then we'd rather have the entry
        // that gives us the exact procedure length instead of us guessing.
        self.parse_dbi(&mut pdb, &address_map)
            .map_err(|e| Error::Other(format!("failed to parse private symbols: {e:?}")))?;

        // Parse and extract all the bits we need from the global symbols..
        self.parse_global_symbols_table(&mut pdb, &address_map)
            .map_err(|e| Error::Other(format!("failed to parse public symbols: {e:?}")))?;

        Ok(())
    }

    /// Build a [`PdbCache`].
    pub fn build(mut self) -> Result<PdbCache> {
        // Walk the map of ordered RVA with their associated names and assign lengths to
        // each of the functions. Some function have a length and some don't. If a
        // length is specified, then we'll use it; otherwise we'll assign one ourselves.
        let mut functions = Vec::with_capacity(self.symbols.len());
        while let Some((start, entry)) = self.symbols.pop_first() {
            let end = if let Some(len) = entry.len() {
                // If we have a length, then use it!
                start
                    .checked_add(len)
                    .ok_or(Error::Other("overflow w/ symbol range".to_string()))?
            } else {
                // If we don't have one, the length of the current function is basically up to
                // the next entry.
                //
                // For example imagine the below:
                //  - RVA: 0, Name: foo
                //  - RVA: 5, Name: bar
                //
                // In that case, we consider the first function to be spanning [0..4], and
                // [5..module size] for the second one.

                // If we didn't pop the last value, then just check the one that follows.
                if let Some((&end, _)) = self.symbols.first_key_value() {
                    end
                } else {
                    debug_assert!(self.module.at.end > self.module.at.start);

                    // If we popped the last value, just use the module end as the end of the range.
                    u32::try_from(self.module.at.end - self.module.at.start).map_err(|_| {
                        Error::Other("failed to make the module's end into a rva".to_string())
                    })?
                }
            };

            functions.push((Range { start, end }, entry.into()));
        }

        Ok(PdbCache::new(self.module.name.clone(), functions))
    }
}

#[derive(Default)]
pub(crate) struct PdbCacheStore(HashMap<Range<u64>, PdbCache>);

impl PdbCacheStore {
    pub fn get_or_create(
        &mut self,
        module: &Module,
        create: impl FnOnce() -> Result<PdbCache>,
    ) -> Result<&PdbCache> {
        // This is an infamous issue w/ the NLL (current) borrow checker called 'problem
        // #3'.
        //
        // Some references:
        //   - https://nikomatsakis.github.io/rust-belt-rust-2019/#72
        //   - https://docs.rs/polonius-the-crab/latest/polonius_the_crab/
        //
        // SAFETY: It is a known limitation of the borrow checker. Miri tests at the end
        // of this file.
        //
        // What we are doing here is basically side step lifetimes by using the `cache`
        // through a pointer instead.
        let cache = (&raw mut (self.0)).cast::<HashMap<Range<u64>, PdbCache>>();
        if let Some(pdbcache) = unsafe { (*cache).get(&module.at) } {
            return Ok(pdbcache);
        }

        let pdbcache = create()?;

        Ok(unsafe { (*cache).entry(module.at.clone()).or_insert(pdbcache) })
    }
}

#[cfg(test)]
mod tests {
    use std::mem::swap;

    use crate::Module;
    use crate::pdbcache::{FuncSymbol, Line, PdbCache, PdbCacheStore, SourceInfo};

    #[test]
    fn empty_cache() {
        let cache = PdbCache::new("hello".to_string(), Vec::new());
        assert_eq!(cache.addr_by_name("foo"), None);
        assert!(cache.sym_by_addr(0x1337).is_none());
        assert_eq!(cache.symbolize(0x1337), "hello+0x1337".to_string());
    }

    #[test]
    fn basic_cache() {
        let symbols = vec![
            (0..1, FuncSymbol {
                name: "sym0..1".to_string().into_boxed_str(),
                source_info: None,
            }),
            (2..5, FuncSymbol {
                name: "sym2..5".to_string().into_boxed_str(),
                source_info: None,
            }),
            (100..106, FuncSymbol {
                name: "sym100..106".to_string().into_boxed_str(),
                source_info: Some(SourceInfo::new("foo\\bar\\f.cc".to_string(), vec![
                    Line::new(0, 1337, None),
                    Line::new(3, 1338, None),
                    Line::new(5, 1400, Some("foobar\\overriden.cc".to_string())),
                ])),
            }),
        ];

        let cache = PdbCache::new("hello".to_string(), symbols);
        assert_eq!(cache.addr_by_name("sym100..106").unwrap(), 100);
        assert!(cache.addr_by_name("Sym100..106").is_none());
        assert_eq!(cache.symbolize(1), "hello+0x1".to_string());
        assert_eq!(cache.symbolize(0), "hello!sym0..1+0x0".to_string());
        assert_eq!(cache.symbolize(2), "hello!sym2..5+0x0".to_string());
        assert_eq!(cache.symbolize(4), "hello!sym2..5+0x2".to_string());
        assert_eq!(
            cache.symbolize(100),
            "hello!sym100..106+0x0 [foo\\bar\\f.cc @ 1337]".to_string()
        );
        assert_eq!(
            cache.symbolize(101),
            "hello!sym100..106+0x1 [foo\\bar\\f.cc @ 1337]".to_string()
        );
        assert_eq!(
            cache.symbolize(102),
            "hello!sym100..106+0x2 [foo\\bar\\f.cc @ 1337]".to_string()
        );
        assert_eq!(
            cache.symbolize(103),
            "hello!sym100..106+0x3 [foo\\bar\\f.cc @ 1338]".to_string()
        );
        assert_eq!(
            cache.symbolize(104),
            "hello!sym100..106+0x4 [foo\\bar\\f.cc @ 1338]".to_string()
        );
        assert_eq!(
            cache.symbolize(105),
            "hello!sym100..106+0x5 [foobar\\overriden.cc @ 1400]".to_string()
        );
        assert_eq!(cache.symbolize(106), "hello+0x6a".to_string());
    }

    #[test]
    fn swap_cache() {
        let symbols = vec![
            (0..1, FuncSymbol {
                name: "sym0..1".to_string().into_boxed_str(),
                source_info: None,
            }),
            (2..5, FuncSymbol {
                name: "sym2..5".to_string().into_boxed_str(),
                source_info: None,
            }),
            (100..102, FuncSymbol {
                name: "sym100..102".to_string().into_boxed_str(),
                source_info: None,
            }),
        ];

        let mut cache = PdbCache::new("hello".to_string(), symbols);
        let mut empty_cache = PdbCache::new("foobar".to_string(), vec![]);
        swap(&mut cache, &mut empty_cache);

        assert_eq!(empty_cache.symbolize(0), "hello!sym0..1+0x0".to_string());
        assert_eq!(empty_cache.symbolize(2), "hello!sym2..5+0x0".to_string());
        drop(cache);
        assert_eq!(empty_cache.symbolize(4), "hello!sym2..5+0x2".to_string());
    }

    #[test]
    fn weird_cache() {
        let symbols = vec![
            (0..1, FuncSymbol {
                name: "sym0..1".to_string().into_boxed_str(),
                source_info: None,
            }),
            (0..2, FuncSymbol {
                name: "sym0..1'".to_string().into_boxed_str(),
                source_info: None,
            }),
            (0..3, FuncSymbol {
                name: "sym0..101'".to_string().into_boxed_str(),
                source_info: None,
            }),
            (100..100, FuncSymbol {
                name: "sym100..100".to_string().into_boxed_str(),
                source_info: None,
            }),
        ];

        // Verify that empty range / overlapping ranges are skipped.
        let cache = PdbCache::new("hello.foo".to_string(), symbols);
        assert_eq!(cache.symbolize(0), "hello.foo!sym0..1+0x0".to_string());
        // has been skipped because overlapped w/ previous entry
        assert_eq!(cache.symbolize(1), "hello.foo+0x1".to_string());
        // has been skipped because 0 length range
        assert_eq!(cache.symbolize(100), "hello.foo+0x64".to_string());
    }

    #[test]
    fn cache_store_returns_cached() {
        // Verify that get_or_create returns the cached entry and doesn't call
        // the closure the second time.
        let mut store = PdbCacheStore::default();
        let module = Module::new("mod.dll", 0x0, 0x1_000);

        let symbols = vec![(0..10, FuncSymbol {
            name: "first".to_string().into_boxed_str(),
            source_info: None,
        })];

        // First call populates the cache.
        let c1 = store
            .get_or_create(&module, || Ok(PdbCache::new("mod.dll".into(), symbols)))
            .unwrap();
        assert_eq!(c1.symbolize(0), "mod.dll!first+0x0");

        // Second call should return the cached entry; the closure would panic if
        // invoked.
        let c2 = store.get_or_create(&module, || panic!("")).unwrap();
        assert_eq!(c2.symbolize(0), "mod.dll!first+0x0");
    }

    #[test]
    fn cache_store_propagates_error() {
        let mut store = PdbCacheStore::default();
        let module = Module::new("bad.dll", 0x0, 0x1_000);

        let result = store.get_or_create(&module, || Err(crate::Error::Other("nope".into())));
        assert!(result.is_err());

        // After a failed create, the module should not be cached; a subsequent
        // call with a working closure should succeed.
        let symbols = vec![(0..5, FuncSymbol {
            name: "first".to_string().into_boxed_str(),
            source_info: None,
        })];
        let cache = store
            .get_or_create(&module, || Ok(PdbCache::new("bad.dll".into(), symbols)))
            .unwrap();
        assert_eq!(cache.symbolize(0), "bad.dll!first+0x0");
    }

    #[test]
    fn cache_store_multiple_modules() {
        let mut store = PdbCacheStore::default();
        let modules: Vec<_> = (0..5u64)
            .map(|i| Module::new(format!("mod{i}.dll"), i * 0x1_000, (i + 1) * 0x1_000))
            .collect();

        for module in &modules {
            let name = module.name.clone();
            let cache = store
                .get_or_create(module, || {
                    Ok(PdbCache::new(name, vec![(0..10, FuncSymbol {
                        name: "f".to_string().into_boxed_str(),
                        source_info: None,
                    })]))
                })
                .unwrap();
            assert_eq!(cache.symbolize(0), format!("{}!f+0x0", module.name));
        }

        // All modules should be cached now.
        for module in &modules {
            let cache = store
                .get_or_create(module, || panic!("should not be called"))
                .unwrap();
            assert_eq!(cache.symbolize(5), format!("{}!f+0x5", module.name));
        }
    }

    #[test]
    fn source_info_single_line() {
        let si = SourceInfo::new("main.c".into(), vec![Line::new(0, 1, None)]);
        assert_eq!(si.path.as_ref(), "main.c");

        // Any offset falls through to the last (and only) line.
        let l = si.line(0);
        assert_eq!(l.number, 1);
        assert!(l.override_path.is_none());

        let l = si.line(999);
        assert_eq!(l.number, 1);
    }

    #[test]
    fn cache_unsorted_input() {
        // Symbols given out of order should still be sorted correctly.
        let symbols = vec![
            (50..60, FuncSymbol {
                name: "middle".to_string().into_boxed_str(),
                source_info: None,
            }),
            (0..10, FuncSymbol {
                name: "first".to_string().into_boxed_str(),
                source_info: None,
            }),
            (100..110, FuncSymbol {
                name: "last".to_string().into_boxed_str(),
                source_info: None,
            }),
        ];

        let cache = PdbCache::new("mod.dll".to_string(), symbols);
        assert_eq!(cache.symbolize(0), "mod.dll!first+0x0");
        assert_eq!(cache.symbolize(55), "mod.dll!middle+0x5");
        assert_eq!(cache.symbolize(109), "mod.dll!last+0x9");

        assert_eq!(cache.addr_by_name("first"), Some(0));
        assert_eq!(cache.addr_by_name("middle"), Some(50));
        assert_eq!(cache.addr_by_name("last"), Some(100));
    }

    #[test]
    fn cache_duplicate_names() {
        // Two different ranges with the same symbol name; the last inserted
        // wins in the name→addr map.
        let symbols = vec![
            (0..10, FuncSymbol {
                name: "dup".to_string().into_boxed_str(),
                source_info: None,
            }),
            (20..30, FuncSymbol {
                name: "dup".to_string().into_boxed_str(),
                source_info: None,
            }),
        ];

        let cache = PdbCache::new("d.dll".to_string(), symbols);
        // Both should be reachable by address.
        assert_eq!(cache.symbolize(5), "d.dll!dup+0x5");
        assert_eq!(cache.symbolize(25), "d.dll!dup+0x5");

        // addr_by_name returns one of them.
        assert!(cache.addr_by_name("dup").is_some());
    }

    #[test]
    fn cache_boundary_addresses() {
        let symbols = vec![(10..20, FuncSymbol {
            name: "func".to_string().into_boxed_str(),
            source_info: None,
        })];

        let cache = PdbCache::new("m.dll".to_string(), symbols);

        // Before the range.
        assert_eq!(cache.symbolize(9), "m.dll+0x9");
        // Start of range (inclusive).
        assert_eq!(cache.symbolize(10), "m.dll!func+0x0");
        // Last address in range.
        assert_eq!(cache.symbolize(19), "m.dll!func+0x9");
        // End of range (exclusive).
        assert_eq!(cache.symbolize(20), "m.dll+0x14");
    }
}
