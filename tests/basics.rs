// Axel '0vercl0k' Souchet - May 30 2024

// #[cfg(not(miri))]
mod miri_incompatible_tests {
    use std::env::temp_dir;
    use std::error::Error;
    use std::fs::{self, File};
    use std::io::{self, Read, Seek, Write};
    use std::ops::Range;
    use std::path::{Path, PathBuf};
    use std::sync::LazyLock;
    use std::thread;

    use addr_symbolizer::{AddrSpace, Module, PdbId, PdbLookupConfig, PeId, Symbolizer};
    use object::pe::IMAGE_DIRECTORY_ENTRY_DEBUG;
    use object::read::pe::{ImageNtHeaders, ImageOptionalHeader, PeFile, PeFile64};
    use object::{LittleEndian, ReadCache, ReadRef, pe};
    use zip::ZipArchive;

    type Result<T> = std::result::Result<T, Box<dyn Error>>;

    #[derive(Debug)]
    struct Entry {
        offset: u64,
        full: &'static str,
        modoff: &'static str,
        valid_name: bool,
    }

    impl Entry {
        const fn new(offset: u64, full: &'static str, modoff: &'static str) -> Self {
            Self {
                offset,
                full,
                modoff,
                valid_name: true,
            }
        }

        const fn with_invalid_name(offset: u64, full: &'static str, modoff: &'static str) -> Self {
            Self {
                offset,
                full,
                modoff,
                valid_name: false,
            }
        }

        fn verify(&self, addr_space: &mut impl AddrSpace, symb: &mut Symbolizer) -> Result<()> {
            let res = symb.name_to_addr(addr_space, self.full);
            if self.valid_name {
                assert_eq!(res?.unwrap(), self.offset);
            } else {
                assert!(res.is_err());
            }

            let mut full = Vec::new();
            symb.symbolize_full(addr_space, self.offset, &mut full)?;
            assert_eq!(String::from_utf8(full)?, self.full);

            let mut modoff = Vec::new();
            symb.symbolize_modoff(self.offset, &mut modoff)?;
            assert_eq!(String::from_utf8(modoff)?, self.modoff);

            Ok(())
        }
    }

    // This is an exported function that doesn't require PDB.
    const EXPORTED_FUNCTION32: Entry = Entry::new(
        0x19_c0,
        "clrhost32.dll!DllGetActivationFactory+0x0",
        "clrhost32.dll+0x000019c0",
    );

    // This is a private function that does require PDB.
    const PRIVATE_FUNCTION32: Entry = Entry::new(
        0x16_e0,
        "clrhost32.dll!Microsoft::WRL::Details::ModuleBase::GetMidEntryPointer+0x0",
        "clrhost32.dll+0x000016e0",
    );

    const EXPECTED_RAW32: [&Entry; 2] = [&EXPORTED_FUNCTION32, &PRIVATE_FUNCTION32];

    // This is an exported function that doesn't require PDB.
    const EXPORTED_FUNCTION: Entry = Entry::new(
        0x16_00,
        "clrhost.dll!DllGetActivationFactory+0x0",
        "clrhost.dll+0x00001600",
    );

    // This is a private function that does require PDB.
    const PRIVATE_FUNCTION: Entry = Entry::new(
        0x10_a0,
        "clrhost.dll!Microsoft::WRL::Details::ModuleBase::GetMidEntryPointer+0x0",
        "clrhost.dll+0x000010a0",
    );

    const SLIGHTLY_OOB: Entry =
        Entry::with_invalid_name(0x90_00, "0x0000000000009000", "0x0000000000009000");
    const COMPLETELY_OOB: Entry =
        Entry::with_invalid_name(0xdead_beef, "0x00000000deadbeef", "0x00000000deadbeef");

    const EXPECTED_RAW: [&Entry; 4] = [
        &EXPORTED_FUNCTION,
        &PRIVATE_FUNCTION,
        &SLIGHTLY_OOB,
        &COMPLETELY_OOB,
    ];

    // Utility to extract the `.zip` files in the `testdatas` folder into a temp
    // directory. That directory is used for the whole process (not thread specific
    // like the symcache below) and will be cleaned up when it goes all down.
    struct ZippedTestdatas {
        extracted_dir: PathBuf,
    }

    impl ZippedTestdatas {
        fn new(testdatas_dir: &Path) -> Result<Self> {
            let extracted_dir = temp_dir().join("addr-symbolizer-rs_tests");
            let _ = fs::remove_dir_all(&extracted_dir);
            fs::create_dir(&extracted_dir)?;
            for entry in fs::read_dir(testdatas_dir)? {
                let entry = entry?;
                if let Some(ext) = entry.path().extension()
                    && ext == "zip"
                {
                    Self::extract_into(&entry.path(), &extracted_dir)?;
                }
            }

            Ok(Self { extracted_dir })
        }

        fn path(&self, filename: &str) -> PathBuf {
            self.extracted_dir.join(filename)
        }

        fn extract_into(archive: &Path, output: &Path) -> Result<()> {
            let file = fs::File::open(archive)?;
            let mut archive = ZipArchive::new(file)?;

            for i in 0..archive.len() {
                let mut zfile = archive.by_index(i)?;
                let outfile_path = output.join(zfile.enclosed_name().unwrap());
                let mut outfile = fs::File::create_new(outfile_path.clone())?;
                io::copy(&mut zfile, &mut outfile)?;
                eprintln!(
                    "extracted {} into {}",
                    zfile.enclosed_name().unwrap().display(),
                    &outfile_path.display()
                );
            }

            Ok(())
        }
    }

    static UNZIPPED_TESTDATAS: LazyLock<ZippedTestdatas> = LazyLock::new(|| {
        ZippedTestdatas::new(&Path::new(env!("CARGO_MANIFEST_DIR")).join("testdatas")).unwrap()
    });

    /// Get a path to a specific data files from one of the archives in
    /// testdatas/ (that have been extracted in a temp directory)
    fn testdata(name: &str) -> PathBuf {
        (*UNZIPPED_TESTDATAS).path(name)
    }

    /// Delete a path on drop.
    struct ScopedPath {
        path: PathBuf,
    }

    impl ScopedPath {
        fn new(path: impl AsRef<Path>) -> Self {
            Self {
                path: path.as_ref().to_path_buf(),
            }
        }
    }

    impl AsRef<Path> for ScopedPath {
        fn as_ref(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for ScopedPath {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).unwrap();
        }
    }

    /// Generate a symcache that won't clash with potentially other threads
    /// running & that will get cleaned up on drop.
    fn symcache(name: &str) -> Result<ScopedPath> {
        // tests can run in parallel in different threads so make sure each gets a clean
        // symcache directory.
        let cache = temp_dir().join(format!("{}-{:?}", name, thread::current().id()));
        if cache.exists() {
            fs::remove_dir_all(&cache)?;
        }

        fs::create_dir(&cache)?;

        Ok(ScopedPath::new(cache))
    }

    #[derive(Debug)]
    struct RawAddressSpace {
        raw: File,
        len: u64,
    }

    impl RawAddressSpace {
        fn new(path: &impl AsRef<Path>) -> io::Result<Self> {
            let raw = File::open(path)?;
            let metadata = raw.metadata()?;
            let len = metadata.len();

            Ok(Self { raw, len })
        }

        fn len(&self) -> u64 {
            self.len
        }
    }

    impl AddrSpace for RawAddressSpace {
        fn read_at(&mut self, addr: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            Seek::seek(&mut self.raw, io::SeekFrom::Start(addr))?;

            Read::read(&mut self.raw, buf)
        }
    }

    #[test]
    fn raw_virt() -> Result<()> {
        let mut raw_addr_space = RawAddressSpace::new(&testdata("clrhost.raw"))?;
        let len = raw_addr_space.len();

        let symcache = symcache("basics")?;
        let mut symb = Symbolizer::new(
            PdbLookupConfig::with_msft_symsrv(symcache.as_ref().to_path_buf())?,
            vec![Module::new("clrhost.dll", 0x0, len)],
        );

        for expected in EXPECTED_RAW {
            expected.verify(&mut raw_addr_space, &mut symb)?;
        }

        let stats = symb.stats();
        assert_eq!(stats.pdb_download_count(), 1);
        assert!(stats.did_download_pdb(&PdbId::new(
            "clrhost.pdb",
            "59E5C589F2149783C04A42F26DA1CC23".parse().unwrap(),
            1
        )?));

        // Create a new one, but this time it should hit the cache.
        let mut symb = Symbolizer::new(
            PdbLookupConfig::with_msft_symsrv(symcache.as_ref().to_path_buf())?,
            vec![Module::new("clrhost.dll", 0x0, len)],
        );

        for expected in EXPECTED_RAW {
            expected.verify(&mut raw_addr_space, &mut symb)?;
        }

        let stats = symb.stats();
        assert_eq!(stats.pdb_download_count(), 0);
        assert_eq!(stats.amount_downloaded(), 0);

        Ok(())
    }

    #[test]
    fn raw_virt_offline() -> Result<()> {
        let mut raw_addr_space = RawAddressSpace::new(&testdata("clrhost.raw"))?;
        let len = raw_addr_space.len();

        let symcache = symcache("basics")?;
        let mut symb = Symbolizer::new(
            PdbLookupConfig::new(symcache.as_ref().to_path_buf())?,
            vec![Module::new("clrhost.dll", 0x0, len)],
        );

        for expected in EXPECTED_RAW {
            let mut modoff = Vec::new();
            symb.symbolize_modoff(expected.offset, &mut modoff)?;
            assert_eq!(String::from_utf8(modoff)?, expected.modoff);
        }

        assert_eq!(
            symb.name_to_addr(&mut raw_addr_space, EXPORTED_FUNCTION.full)?
                .unwrap(),
            EXPORTED_FUNCTION.offset
        );

        let mut full = Vec::new();
        symb.symbolize_full(&mut raw_addr_space, EXPORTED_FUNCTION.offset, &mut full)?;
        assert_eq!(String::from_utf8(full)?, EXPORTED_FUNCTION.full);

        assert!(
            symb.name_to_addr(&mut raw_addr_space, PRIVATE_FUNCTION.full)?
                .is_none(),
        );

        let mut full = Vec::new();
        symb.symbolize_full(&mut raw_addr_space, PRIVATE_FUNCTION.offset, &mut full)?;
        assert_ne!(String::from_utf8(full)?, PRIVATE_FUNCTION.full);

        let stats = symb.stats();
        assert_eq!(stats.amount_downloaded(), 0);

        Ok(())
    }

    #[derive(Debug)]
    struct FileAddressSpace<'data, P>
    where
        P: ImageNtHeaders,
    {
        pe: PeFile<'data, P, &'data ReadCache<File>>,
        virt_len: u64,
    }

    impl<'data, P> FileAddressSpace<'data, P>
    where
        P: ImageNtHeaders,
    {
        fn new(cache: &'data ReadCache<File>) -> io::Result<Self> {
            let pe = PeFile::<P, &ReadCache<File>>::parse(cache)
                .map_err(|e| io::Error::new(io::ErrorKind::Unsupported, e))?;

            let virt_len = pe.nt_headers().optional_header().size_of_image().into();

            Ok(Self { pe, virt_len })
        }

        fn len(&self) -> u64 {
            self.virt_len
        }
    }

    impl<P> AddrSpace for FileAddressSpace<'_, P>
    where
        P: ImageNtHeaders,
    {
        fn read_at(&mut self, addr: u64, mut buf: &mut [u8]) -> std::io::Result<usize> {
            if addr >= self.virt_len {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("{addr:#x} vs {:#x} is oob", self.virt_len),
                ));
            }

            let data = match self
                .pe
                .section_table()
                .pe_data_at(self.pe.data(), addr.try_into().unwrap())
            {
                Some(data) => data,
                None => self
                    .pe
                    .data()
                    .read_slice_at(addr, buf.len())
                    .map_err(|()| io::Error::new(io::ErrorKind::Unsupported, "read_slice_at"))?,
            };

            buf.write(data)
        }
    }

    type FileAddressSpace64<'data> = FileAddressSpace<'data, pe::ImageNtHeaders64>;
    type FileAddressSpace32<'data> = FileAddressSpace<'data, pe::ImageNtHeaders32>;

    #[test]
    fn raw_file() -> Result<()> {
        let file = File::open(testdata("clrhost.dll"))?;
        let cache = ReadCache::new(file);
        let mut file_addr_space = FileAddressSpace64::new(&cache)?;
        let len = file_addr_space.len();

        let symcache = symcache("basics")?;
        let mut symb = Symbolizer::new(
            PdbLookupConfig::with_msft_symsrv(symcache.as_ref().to_path_buf())?,
            vec![Module::new("clrhost.dll", 0x0, len)],
        );

        for expected in EXPECTED_RAW {
            expected.verify(&mut file_addr_space, &mut symb)?;
        }

        let stats = symb.stats();
        assert_eq!(stats.pdb_download_count(), 1);
        assert!(stats.did_download_pdb(&PdbId::new(
            "clrhost.pdb",
            "59E5C589F2149783C04A42F26DA1CC23".parse()?,
            1
        )?));

        Ok(())
    }

    #[test]
    fn raw_file32() -> Result<()> {
        let file = File::open(testdata("clrhost32.dll"))?;
        let cache = ReadCache::new(file);
        let mut file_addr_space = FileAddressSpace32::new(&cache)?;
        let len = file_addr_space.len();

        let symcache = symcache("basics")?;
        let mut symb = Symbolizer::new(
            PdbLookupConfig::with_msft_symsrv(symcache.as_ref().to_path_buf())?,
            vec![Module::new("clrhost32.dll", 0x0, len)],
        );

        for expected in EXPECTED_RAW32 {
            expected.verify(&mut file_addr_space, &mut symb)?;
        }

        let stats = symb.stats();
        assert_eq!(stats.pdb_download_count(), 1);
        assert!(stats.did_download_pdb(&PdbId::new(
            "clrhost.pdb",
            "FBB5EFC8A8DF311BCC600A47A42E8B55".parse()?,
            1
        )?));

        Ok(())
    }

    type OnDebugDirReadCallback = dyn Fn(u64, &mut [u8]) -> Option<io::Result<usize>>;
    struct OverrideDebugDirAddrSpace {
        file: File,
        debug_dir: Range<u64>,
        cb: Box<OnDebugDirReadCallback>,
    }

    impl OverrideDebugDirAddrSpace {
        fn new(path: impl AsRef<Path>, cb: Box<OnDebugDirReadCallback>) -> Result<Self> {
            let file = File::open(path.as_ref()).unwrap();
            let cache = ReadCache::new(&file);
            let pe = PeFile64::parse(&cache)?;
            let dir = pe.data_directory(IMAGE_DIRECTORY_ENTRY_DEBUG).unwrap();
            let debug_dir = dir.virtual_address.get(LittleEndian).into()
                ..(dir.virtual_address.get(LittleEndian) + dir.size.get(LittleEndian)).into();

            Ok(Self {
                file,
                debug_dir,
                cb,
            })
        }

        fn len(&self) -> Result<u64> {
            Ok(self.file.metadata()?.len())
        }
    }

    impl AddrSpace for OverrideDebugDirAddrSpace {
        fn read_at(&mut self, addr: u64, buf: &mut [u8]) -> io::Result<usize> {
            // If we're trying to read from the debug directory, pass it to `cb`.
            if self.debug_dir.contains(&addr)
                && let Some(r) = (self.cb)(addr, buf)
            {
                return r;
            }

            self.file.seek(io::SeekFrom::Start(addr))?;

            self.file.read(buf)
        }
    }

    #[test]
    fn download_pe() -> Result<()> {
        let cb = |addr: u64, _buf: &mut [u8]| -> Option<io::Result<usize>> {
            // Make it look like there isn't a debug directory to force the library to not
            // be able to read the associated PDB identifier. It'll have to go and download
            // the PE first.
            //
            // ```text
            // 0:000> !dh clrhost
            // ...
            //     35D0 [      70] address [size] of Debug Directory
            // ```
            if (0x35D0..(0x35D0 + 0x70)).contains(&addr) {
                // Make it look like we couldn't read any bytes from this section.
                Some(Ok(0))
            } else {
                // Let it read from the underlying file.
                None
            }
        };
        let mut addr_space = OverrideDebugDirAddrSpace::new(testdata("clrhost.dll"), Box::new(cb))?;
        let len = addr_space.len()?;

        let symcache = symcache("basics")?;
        let mut symb = Symbolizer::new(
            PdbLookupConfig::with_msft_symsrv(symcache.as_ref().to_path_buf())?,
            vec![Module::new("clrhost.dll", 0x0, len)],
        );

        assert!(
            symb.name_to_addr(&mut addr_space, "noname.dll!unknown1337")?
                .is_none()
        );

        symb.symbolize_full(&mut addr_space, 0, &mut Vec::new())?;

        let stats = symb.stats();
        assert_eq!(stats.pe_download_count(), 1);
        // This is the PE we should have downloaded:
        //
        // ```text
        // File Type: DLL
        // FILE HEADER VALUES
        //     8664 machine (X64)
        //        6 number of sections
        // 7D1F08C1 time date stamp Tue Jul  8 20:10:57 2036
        // ...
        //     9000 size of image
        // ```
        assert!(stats.did_download_pe(&PeId::new("clrhost.dll", 0x7D1F_08C1, 0x9_000)));

        assert_eq!(stats.pdb_download_count(), 1);
        assert!(stats.did_download_pdb(&PdbId::new(
            "clrhost.pdb",
            "59E5C589F2149783C04A42F26DA1CC23".parse()?,
            1
        )?));

        Ok(())
    }

        let stats = symb.stats();
        assert_eq!(stats.pe_download_count(), 1);
        // This is the PE we should have downloaded:
        //
        // ```text
        // File Type: DLL
        // FILE HEADER VALUES
        //     8664 machine (X64)
        //        6 number of sections
        // 7D1F08C1 time date stamp Tue Jul  8 20:10:57 2036
        // ...
        //     9000 size of image
        // ```
        assert!(stats.did_download_pe(&PeId::new("clrhost.dll", 0x7D1F_08C1, 0x9_000)));

        assert_eq!(stats.pdb_download_count(), 1);
        assert!(stats.did_download_pdb(&PdbId::new(
            "clrhost.pdb",
            "59E5C589F2149783C04A42F26DA1CC23".parse()?,
            1
        )?));

        Ok(())
    }

    #[test]
    fn source_info() -> Result<()> {
        const MAIN_OFFSET: u64 = 0x1_05c;
        let file_path = testdata("small.exe");
        let file = File::open(&file_path)?;
        let cache = ReadCache::new(file);
        let mut file_addr_space = FileAddressSpace64::new(&cache)?;
        let len = file_addr_space.len();

        let symcache = symcache("basics")?;
        let mut symb = Symbolizer::new(
            PdbLookupConfig::new(symcache.as_ref().to_path_buf())?,
            vec![Module::new("small.exe", 0x0, len)],
        );

        let parent_dir = file_path.parent().unwrap();
        symb.import_pdbs([parent_dir])?;

        // ```text
        // 0:000> ? small!main - small
        // Evaluate expression: 4188 = 00000000`0000105c
        // ```
        assert_eq!(
            symb.name_to_addr(&mut file_addr_space, "small.exe!main")
                .unwrap(),
            Some(MAIN_OFFSET)
        );

        let mut sym = Vec::new();
        assert!(
            symb.symbolize_full(&mut file_addr_space, MAIN_OFFSET, &mut sym)
                .is_ok()
        );
        assert_eq!(
            str::from_utf8(&sym)?,
            r"small.exe!main+0x0 [C:\Users\over\Downloads\small\small.c @ 2]".to_string()
        );

        // ```text
        // 0:000> u small!main+4 l1
        // small!main+0x4 [C:\Users\over\Downloads\small\small.c @ 3]:
        // 00007ff6`94ab1060 488d0de9110000  lea     rcx,[small!`string' (00007ff6`94ab2250)]
        // ```
        sym.clear();
        assert!(
            symb.symbolize_full(&mut file_addr_space, MAIN_OFFSET + 4, &mut sym)
                .is_ok()
        );
        assert_eq!(
            str::from_utf8(&sym)?,
            r"small.exe!main+0x4 [C:\Users\over\Downloads\small\small.c @ 3]".to_string()
        );
        // ```text
        // 0:000> u small!main+b l1
        // small!main+0xb [C:\Users\over\Downloads\small\small.c @ 3]:
        // 00007ff6`94ab1067 e89cffffff      call    small!printf (00007ff6`94ab1008)
        // ```
        sym.clear();
        assert!(
            symb.symbolize_full(&mut file_addr_space, MAIN_OFFSET + 0xb, &mut sym)
                .is_ok()
        );
        assert_eq!(
            str::from_utf8(&sym)?,
            r"small.exe!main+0xb [C:\Users\over\Downloads\small\small.c @ 3]".to_string()
        );
        // ```text
        // 0:000> u small!main+0x10
        // small!main+0x10 [C:\Users\over\Downloads\small\small.c @ 4]:
        // 00007ff6`94ab106c 33c0            xor     eax,eax
        // ```
        sym.clear();
        assert!(
            symb.symbolize_full(&mut file_addr_space, MAIN_OFFSET + 0x10, &mut sym)
                .is_ok()
        );
        assert_eq!(
            str::from_utf8(&sym)?,
            r"small.exe!main+0x10 [C:\Users\over\Downloads\small\small.c @ 4]".to_string()
        );

        let stats = symb.stats();
        assert_eq!(stats.pe_download_count(), 0);
        assert_eq!(stats.pdb_download_count(), 0);
        assert_eq!(stats.amount_downloaded(), 0);

        Ok(())
    }
}
