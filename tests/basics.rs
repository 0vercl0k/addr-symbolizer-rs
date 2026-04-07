// Axel '0vercl0k' Souchet - May 30 2024

#[cfg(not(miri))]
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
    use object::{ReadCache, ReadRef, pe};
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

            assert_eq!(symb.symbolize_full(addr_space, self.offset)?, self.full);
            assert_eq!(symb.symbolize_modoff(self.offset)?, self.modoff);

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
            assert_eq!(symb.symbolize_modoff(expected.offset)?, expected.modoff);
        }

        assert_eq!(
            symb.name_to_addr(&mut raw_addr_space, EXPORTED_FUNCTION.full)?
                .unwrap(),
            EXPORTED_FUNCTION.offset
        );

        assert_eq!(
            symb.symbolize_full(&mut raw_addr_space, EXPORTED_FUNCTION.offset)?,
            EXPORTED_FUNCTION.full
        );

        assert!(
            symb.name_to_addr(&mut raw_addr_space, PRIVATE_FUNCTION.full)?
                .is_none(),
        );

        assert_ne!(
            symb.symbolize_full(&mut raw_addr_space, PRIVATE_FUNCTION.offset)?,
            PRIVATE_FUNCTION.full
        );

        let stats = symb.stats();
        assert_eq!(stats.amount_downloaded(), 0);

        Ok(())
    }

    /// Read a PE file like it is mapped into memory. The underlying `read_at`
    /// method has logic to figure out in which section a specific address lands
    /// in, and then calculate the file offset to read the appropriate data.
    #[derive(Debug)]
    struct FileAddressSpace<'cache, P>
    where
        P: ImageNtHeaders,
    {
        pe: PeFile<'cache, P, &'cache ReadCache<File>>,
        virt_len: u64,
    }

    impl<'cache, P> FileAddressSpace<'cache, P>
    where
        P: ImageNtHeaders,
    {
        fn new(cache: &'cache ReadCache<File>) -> io::Result<Self> {
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
    struct OverrideDebugDirAddrSpace<'cache> {
        file: FileAddressSpace64<'cache>,
        debug_dir: Range<u64>,
        cb: Box<OnDebugDirReadCallback>,
    }

    impl<'cache> OverrideDebugDirAddrSpace<'cache> {
        fn new(cache: &'cache ReadCache<File>, cb: Box<OnDebugDirReadCallback>) -> Result<Self> {
            // pub(crate) struct ImageDebugDirectory {
            //     pub characteristics: u32,     // +0x00
            //     pub time_date_stamp: u32,     // +0x04
            //     pub major_version: u16,       // +0x08
            //     pub minor_version: u16,       // +0x0a
            //     pub type_: u32,               // +0x0c
            //     pub size_of_data: u32,        // +0x10
            //     pub address_of_raw_data: u32, // +0x14
            //     pub pointer_to_raw_data: u32, // +0x18
            // }
            const OFFSET_SIZE_OF_DATA: usize = 0x10;
            const OFFSET_ADDRESS_OF_RAW_DATA: usize = 0x14;

            // Parse the PE..
            let pe = PeFile64::parse(cache)?;
            // ..read the debug data directory header..
            let dir = pe.data_directory(IMAGE_DIRECTORY_ENTRY_DEBUG).unwrap();
            // ..and read the debug directory content.
            let sections = pe.section_table();
            let debug_dir = dir.data(cache, &sections)?;
            assert!(debug_dir.len() >= OFFSET_ADDRESS_OF_RAW_DATA + size_of::<u32>());

            // Read the `size_of_data` field..
            let mut size_of_data = [0; 4];
            size_of_data.copy_from_slice(&debug_dir[OFFSET_SIZE_OF_DATA..][..size_of::<u32>()]);
            let size_of_data = u32::from_le_bytes(size_of_data);

            // .. and the `address_of_raw_data` field.
            let mut address_of_raw_data = [0; 4];
            address_of_raw_data
                .copy_from_slice(&debug_dir[OFFSET_ADDRESS_OF_RAW_DATA..][..size_of::<u32>()]);
            let address_of_raw_data = u32::from_le_bytes(address_of_raw_data);

            // We now know the range of file reads we'll man-in-the-middle.
            let debug_dir = address_of_raw_data.into()..(address_of_raw_data + size_of_data).into();

            let file = FileAddressSpace::new(cache)?;

            Ok(Self {
                file,
                debug_dir,
                cb,
            })
        }

        fn len(&self) -> u64 {
            self.file.len()
        }
    }

    impl AddrSpace for OverrideDebugDirAddrSpace<'_> {
        fn read_at(&mut self, addr: u64, buf: &mut [u8]) -> io::Result<usize> {
            // If we're trying to read from the debug directory, pass it to `cb`.
            let strictly_contained =
                addr >= self.debug_dir.start && (addr + buf.len() as u64) <= self.debug_dir.end;
            let res = self.file.read_at(addr, buf)?;

            Ok(
                if strictly_contained && let Some(overriden_res) = (self.cb)(addr, buf) {
                    overriden_res?
                } else {
                    res
                },
            )
        }
    }

    #[test]
    fn download_pe() -> Result<()> {
        let cb = |_addr: u64, _buf: &mut [u8]| -> Option<io::Result<usize>> {
            // Make it look like there isn't a debug directory to force the library to not
            // be able to read the associated PDB identifier. It'll have to go and download
            // the PE first.
            //
            // ```text
            // 0:000> !dh clrhost
            // ...
            //     35D0 [      70] address [size] of Debug Directory
            // ```
            Some(Ok(0))
        };
        let cache = ReadCache::new(File::open(testdata("clrhost.dll"))?);
        let mut addr_space = OverrideDebugDirAddrSpace::new(&cache, Box::new(cb))?;
        let len = addr_space.len();

        let symcache = symcache("basics")?;
        let mut symb = Symbolizer::new(
            PdbLookupConfig::with_msft_symsrv(symcache.as_ref().to_path_buf())?,
            vec![Module::new("clrhost.dll", 0x0, len)],
        );

        assert!(
            symb.name_to_addr(&mut addr_space, "noname.dll!unknown1337")?
                .is_none()
        );

        symb.symbolize_full(&mut addr_space, 0)?;

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
    fn load_local_symbol() -> Result<()> {
        let small_path = testdata("small.exe");
        let small_pdb_path = small_path
            .parent()
            .unwrap()
            .join("small.pdb")
            .into_os_string()
            .into_encoded_bytes();

        let cache = ReadCache::new(File::open(small_path)?);

        let cb = move |_addr: u64, buf: &mut [u8]| -> Option<io::Result<usize>> {
            // Make it seems like there is a local hit. A local hit is when the PDB path
            // from the PE file resolves directly to an existing PDB file. To make this
            // happen in the CI, we basically will man-in-the-middle the read requests into
            // the debug directory and overwrite the read PDB path to make it a valid local
            // path.
            //
            // If we don't find a '.pdb\0' into buf, then we're not reading what we're
            // interested in.
            if let Some(last_chunk) = buf.last_chunk::<5>()
                && last_chunk != b".pdb\0"
            {
                return None;
            }

            // Figure out how much padding we need (account for the null byte read as well),
            // and what character we'll padd with..
            let padding = buf.len() - small_pdb_path.len() - 1;
            let padding_byte = if cfg!(windows) { b'\\' } else { b'/' };
            let padding_offset = if cfg!(windows) {
                // Pad right after the 'c:\'
                2
            } else {
                // Pad right after the '/'
                1
            };

            // ..and pad it.
            let mut small_pdb_path = small_pdb_path.clone();
            for _ in 0..padding {
                small_pdb_path.insert(padding_offset, padding_byte);
            }

            // Now, overwrite it w/ the path of where we extracted the pdb/testdata..
            buf[..small_pdb_path.len()].copy_from_slice(&small_pdb_path);

            Some(Ok(buf.len()))
        };

        let mut addr_space = OverrideDebugDirAddrSpace::new(&cache, Box::new(cb))?;
        let len = addr_space.len();

        let symcache = symcache("basics")?;
        let mut symb = Symbolizer::new(
            PdbLookupConfig::with_msft_symsrv(symcache.as_ref().to_path_buf())?,
            vec![Module::new("small.exe", 0x0, len)],
        );

        let main_offset = symb
            .name_to_addr(&mut addr_space, "small.exe!main")?
            .unwrap();

        assert_eq!(
            symb.symbolize_full(&mut addr_space, main_offset)?,
            r"small.exe!main+0x0 [C:\Users\over\Downloads\a_very_long_path_to_make_space_in_the_debug_directory_to_have_enough_room_for_tests\small\small.c @ 2]"
        );

        let stats = symb.stats();
        assert_eq!(stats.pe_download_count(), 0);
        assert_eq!(stats.pdb_download_count(), 0);

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

        assert_eq!(
            symb.symbolize_full(&mut file_addr_space, MAIN_OFFSET)?,
            r"small.exe!main+0x0 [C:\Users\over\Downloads\a_very_long_path_to_make_space_in_the_debug_directory_to_have_enough_room_for_tests\small\small.c @ 2]".to_string()
        );

        // ```text
        // 0:000> u small!main+4 l1
        // small!main+0x4 [C:\Users\over\Downloads\a_very_long_path_to_make_space_in_the_debug_directory_to_have_enough_room_for_tests\small\small.c @ 3]:
        // 00007ff6`94ab1060 488d0de9110000  lea     rcx,[small!`string' (00007ff6`94ab2250)]
        // ```
        assert_eq!(
            symb.symbolize_full(&mut file_addr_space, MAIN_OFFSET + 4)?,
            r"small.exe!main+0x4 [C:\Users\over\Downloads\a_very_long_path_to_make_space_in_the_debug_directory_to_have_enough_room_for_tests\small\small.c @ 3]".to_string()
        );
        // ```text
        // 0:000> u small!main+b l1
        // small!main+0xb [C:\Users\over\Downloads\a_very_long_path_to_make_space_in_the_debug_directory_to_have_enough_room_for_tests\small\small.c @ 3]:
        // 00007ff6`94ab1067 e89cffffff      call    small!printf (00007ff6`94ab1008)
        // ```
        assert_eq!(
            symb.symbolize_full(&mut file_addr_space, MAIN_OFFSET + 0xb)?,
            r"small.exe!main+0xb [C:\Users\over\Downloads\a_very_long_path_to_make_space_in_the_debug_directory_to_have_enough_room_for_tests\small\small.c @ 3]".to_string()
        );
        // ```text
        // 0:000> u small!main+0x10
        // small!main+0x10 [C:\Users\over\Downloads\a_very_long_path_to_make_space_in_the_debug_directory_to_have_enough_room_for_tests\small\small.c @ 4]:
        // 00007ff6`94ab106c 33c0            xor     eax,eax
        // ```
        assert_eq!(
            symb.symbolize_full(&mut file_addr_space, MAIN_OFFSET + 0x10)?,
            r"small.exe!main+0x10 [C:\Users\over\Downloads\a_very_long_path_to_make_space_in_the_debug_directory_to_have_enough_room_for_tests\small\small.c @ 4]".to_string()
        );

        let stats = symb.stats();
        assert_eq!(stats.pe_download_count(), 0);
        assert_eq!(stats.pdb_download_count(), 0);
        assert_eq!(stats.amount_downloaded(), 0);

        Ok(())
    }
}
