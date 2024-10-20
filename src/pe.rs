// Axel '0vercl0k' Souchet - February 19 2024
//! This module contains the implementation of the PE parsing we do.
use std::fmt::Display;
use std::mem::{self, MaybeUninit};
use std::ops::Range;
use std::path::PathBuf;
use std::{io, slice};

use anyhow::{anyhow, Context};
use log::debug;

use crate::addr_space::AddrSpace;
use crate::guid::Guid;
use crate::misc::Rva;
use crate::{Error as E, Result};

/// The IMAGE_DOS_HEADER.
#[derive(Default, Debug, Clone, Copy)]
#[repr(C, packed(2))]
pub struct ImageDosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

/// The IMAGE_NT_HEADERS.
#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
struct NtHeaders {
    signature: u32,
    file_hdr: ImageFileHeader,
}

/// The IMAGE_FILE_HEADER.
#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

/// The IMAGE_DATA_DIRECTORY.
#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

trait ImageOptionalHeader {
    fn debug_dir(&self) -> ImageDataDirectory;
    fn export_dir(&self) -> ImageDataDirectory;
    fn size_of_image(&self) -> u32;
}

/// The IMAGE_OPTIONAL_HEADER32.
#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct ImageOptionalHeader32 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; 16],
}

impl ImageOptionalHeader for ImageOptionalHeader32 {
    fn debug_dir(&self) -> ImageDataDirectory {
        self.data_directory[IMAGE_DIRECTORY_ENTRY_DEBUG]
    }

    fn export_dir(&self) -> ImageDataDirectory {
        self.data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT]
    }

    fn size_of_image(&self) -> u32 {
        self.size_of_image
    }
}

/// The IMAGE_OPTIONAL_HEADER64.
#[derive(Debug, Default, Clone, Copy)]
#[repr(C, packed(4))]
pub struct ImageOptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; 16],
}

impl ImageOptionalHeader for ImageOptionalHeader64 {
    fn debug_dir(&self) -> ImageDataDirectory {
        self.data_directory[IMAGE_DIRECTORY_ENTRY_DEBUG]
    }

    fn export_dir(&self) -> ImageDataDirectory {
        self.data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT]
    }

    fn size_of_image(&self) -> u32 {
        self.size_of_image
    }
}

/// The IMAGE_DEBUG_DIRECTORY.
#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ImageDebugDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub type_: u32,
    pub size_of_data: u32,
    pub address_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
}

/// The IMAGE_EXPORT_DIRECTORY.
#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ImageExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32,
    pub base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub address_of_functions: u32,
    pub address_of_names: u32,
    pub address_of_name_ordinals: u32,
}

/// The code view information.
#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct Codeview {
    pub signature: u32,
    pub guid: [u8; 16],
    pub age: u32,
    // name follows
}

pub const IMAGE_NT_SIGNATURE: u32 = 17744;
pub const IMAGE_FILE_MACHINE_I386: u16 = 332;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 34404;
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;

pub const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 2;

pub trait SymcacheEntry {
    fn name(&self) -> &str;

    fn index(&self) -> String;
}

/// A PDB identifier.
///
/// To download a PDB off Microsoft's Symbol Server, we need three pieces of
/// information: the pdb name, a guid and its age.
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct PdbId {
    pub path: PathBuf,
    pub name: String,
    pub guid: Guid,
    pub age: u32,
}

impl SymcacheEntry for PdbId {
    fn name(&self) -> &str {
        &self.name
    }

    fn index(&self) -> String {
        // It seems that Chrome's symsrv server only accepts the GUID/age part as
        // uppercase hex, so let's use that.
        format!("{}{:x}", self.guid, self.age)
    }
}

impl Display for PdbId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}:{}:{:x}", self.name, self.guid, self.age))
    }
}

impl PdbId {
    pub fn new(path: impl Into<PathBuf>, guid: Guid, age: u32) -> Result<Self> {
        let path = path.into();
        let Some(name) = path.file_name() else {
            return Err(E::PdbPathNoName(path.to_path_buf()));
        };

        let name = name.to_string_lossy().to_string();

        Ok(Self {
            path,
            name,
            guid,
            age,
        })
    }
}

/// A PE identifier.
///
/// The identifier can be used to locate a PE on a symbol server when a
/// [`PdbId`] isn't present (because for example the debug directory isn't
/// present in the address space).
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct PeId {
    pub name: String,
    pub timestamp: u32,
    pub size: u32,
}

impl SymcacheEntry for PeId {
    fn name(&self) -> &str {
        &self.name
    }

    fn index(&self) -> String {
        format!("{:X}{:X}", self.timestamp, self.size)
    }
}

impl PeId {
    pub fn new(name: impl Into<String>, timestamp: u32, size: u32) -> Self {
        Self {
            name: name.into(),
            timestamp,
            size,
        }
    }
}

impl Display for PeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{:?}:{:#x}:{:#x}",
            self.name, self.timestamp, self.size
        ))
    }
}

/// Calculate the absolute address of an array entry based on a base address,
/// the RVA of the array, the entry index and the size of an entry.
pub fn array_offset(base: u64, rva_array: u32, idx: u32, entry_size: usize) -> Option<u64> {
    let offset = idx.checked_mul(entry_size.try_into().ok()?)?;
    let rva = rva_array.checked_add(offset)?;

    base.checked_add(rva.into())
}

/// Read a NULL terminated string from the dump file at a specific address.
pub fn read_string(
    addr_space: &mut impl AddrSpace,
    mut addr: u64,
    max: usize,
) -> Result<Option<String>> {
    let mut s = String::new();
    let mut terminated = false;
    for _ in 0..max {
        let mut buf = [0];
        let Some(_) = addr_space
            .try_read_exact_at(addr, &mut buf)
            .context("failed reading null terminated string")?
        else {
            return Ok(None);
        };

        let c = buf[0];
        if c == 0 {
            terminated = true;
            break;
        }

        s.push(c.into());
        addr += 1;
    }

    if !terminated && s.len() == max {
        s.push_str("...");
    }

    Ok(Some(s))
}

fn read_struct_at<S>(addr_space: &mut impl AddrSpace, addr: u64) -> io::Result<S>
where
    S: Copy,
{
    let mut t = MaybeUninit::uninit();
    let size_of_t = mem::size_of_val(&t);
    let slice_over_t = unsafe { slice::from_raw_parts_mut(t.as_mut_ptr() as *mut u8, size_of_t) };

    addr_space.read_exact_at(addr, slice_over_t)?;

    Ok(unsafe { t.assume_init() })
}

fn try_read_struct_at<S>(addr_space: &mut impl AddrSpace, addr: u64) -> io::Result<Option<S>>
where
    S: Copy,
{
    let mut t: MaybeUninit<S> = MaybeUninit::uninit();
    let size_of_t = mem::size_of_val(&t);
    let slice_over_t = unsafe { slice::from_raw_parts_mut(t.as_mut_ptr() as *mut u8, size_of_t) };

    Ok(addr_space
        .try_read_exact_at(addr, slice_over_t)?
        .map(|_| unsafe { t.assume_init() }))
}

fn read_optional_headers<O>(
    addr_space: &mut impl AddrSpace,
    opt_hdr_addr: u64,
    opt_hdr_size: usize,
) -> Result<(ImageDataDirectory, ImageDataDirectory, u32)>
where
    O: ImageOptionalHeader + Copy,
{
    if opt_hdr_size < mem::size_of::<O>() {
        return Err(anyhow!("optional header's size is too small").into());
    }

    let opt_hdr = read_struct_at::<O>(addr_space, opt_hdr_addr)?;

    Ok((
        opt_hdr.debug_dir(),
        opt_hdr.export_dir(),
        opt_hdr.size_of_image(),
    ))
}

/// A parsed PE headers.
///
/// We are only interested in the PDB identifier and the Export Address Table.
#[derive(Debug, Default)]
pub struct Pe {
    base: u64,
    pub timestamp: u32,
    pub size: u32,
    debug_data_dir: ImageDataDirectory,
    export_data_dir: ImageDataDirectory,
}

impl Pe {
    pub fn new(addr_space: &mut impl AddrSpace, base: u64) -> Result<Self> {
        // All right let's parse the PE.
        debug!("parsing PE @ {:#x}", base);

        // Read the DOS/NT headers.
        let dos_hdr = read_struct_at::<ImageDosHeader>(addr_space, base)
            .context("failed to read ImageDosHeader")?;
        let nt_hdr_addr = base
            .checked_add(dos_hdr.e_lfanew.try_into().unwrap())
            .ok_or(anyhow!("overflow w/ e_lfanew"))?;
        let nt_hdr = read_struct_at::<NtHeaders>(addr_space, nt_hdr_addr)
            .context("failed to read Ntheaders")?;

        // Let's verify the signature..
        if nt_hdr.signature != IMAGE_NT_SIGNATURE {
            return Err(anyhow!("wrong PE signature for {base:#x}").into());
        }

        // ..and let's ignore non Intel PEs.
        let machine = nt_hdr.file_hdr.machine;
        if machine != IMAGE_FILE_MACHINE_AMD64 && machine != IMAGE_FILE_MACHINE_I386 {
            return Err(anyhow!("unsupported architecture for {base:#x}").into());
        }

        // Now locate the optional header, and check that it looks big enough.
        let opt_hdr_addr = nt_hdr_addr
            .checked_add(mem::size_of_val(&nt_hdr).try_into().unwrap())
            .ok_or(anyhow!("overflow w/ nt_hdr"))?;
        let opt_hdr_size = nt_hdr.file_hdr.size_of_optional_header as usize;
        debug!("parsing optional hdr @ {:#x}", opt_hdr_addr);

        // Get both the export / debug data directory.
        let (debug_data_dir, export_data_dir, size_of_image) = {
            if machine == IMAGE_FILE_MACHINE_AMD64 {
                read_optional_headers::<ImageOptionalHeader64>(
                    addr_space,
                    opt_hdr_addr,
                    opt_hdr_size,
                )
            } else {
                read_optional_headers::<ImageOptionalHeader32>(
                    addr_space,
                    opt_hdr_addr,
                    opt_hdr_size,
                )
            }
        }?;

        Ok(Self {
            base,
            timestamp: nt_hdr.file_hdr.time_date_stamp,
            size: size_of_image,
            debug_data_dir,
            export_data_dir,
        })
    }

    pub fn read_pdbid(&self, addr_space: &mut impl AddrSpace) -> Result<Option<PdbId>> {
        // Let's check if there's an ImageDebugDirectory.
        if usize::try_from(self.debug_data_dir.size).unwrap()
            < mem::size_of::<ImageDebugDirectory>()
        {
            debug!("debug dir is too small");
            return Ok(None);
        }

        // Read it.
        let debug_dir_addr = self
            .base
            .checked_add(self.debug_data_dir.virtual_address.into())
            .ok_or(anyhow!("overflow w/ debug_data_dir"))?;
        let Some(debug_dir) =
            try_read_struct_at::<ImageDebugDirectory>(addr_space, debug_dir_addr)?
        else {
            debug!(
                "failed to read ImageDebugDirectory {debug_dir_addr:#x} because of mem translation"
            );
            return Ok(None);
        };

        // If it's not a codeview type.. I don't know what to do, so let's bail.
        if debug_dir.type_ != IMAGE_DEBUG_TYPE_CODEVIEW {
            debug!("debug dir is not a codeview");
            return Ok(None);
        }

        // Let's make sure it's big enough to back a codeview structure.
        if usize::try_from(debug_dir.size_of_data).unwrap() < mem::size_of::<Codeview>() {
            debug!("codeview too small");
            return Ok(None);
        }

        // Let's read it.
        let codeview_addr = self
            .base
            .checked_add(debug_dir.address_of_raw_data.into())
            .ok_or(anyhow!("overflow w/ debug_dir"))?;
        let Some(codeview) = try_read_struct_at::<Codeview>(addr_space, codeview_addr)? else {
            debug!("failed to read codeview {codeview_addr:#x} because of mem translation");
            return Ok(None);
        };

        // The codeview structure is followed by a NULL terminated string which is the
        // module name.
        let leftover =
            usize::try_from(debug_dir.size_of_data).unwrap() - mem::size_of::<Codeview>();
        if leftover == 0 || leftover > 256 {
            return Err(E::CodeViewInvalidPath);
        }

        // Allocate space for it, and read it.
        let mut file_name = vec![0; leftover];
        let file_name_addr = array_offset(
            self.base,
            debug_dir.address_of_raw_data,
            1,
            mem::size_of::<Codeview>(),
        )
        .ok_or(anyhow!("overflow w/ debug_dir filename"))?;

        let Some(amount) = addr_space.try_read_at(file_name_addr, &mut file_name)? else {
            return Ok(None);
        };

        // The last character is supposed to be a NULL byte, bail if it's not there.
        if *file_name.last().unwrap() != 0 {
            return Err(anyhow!("the module path doesn't end with a NULL byte").into());
        }

        file_name.resize(amount - 1, 0);

        // All right, at this point we have everything we need: the PDB name / GUID /
        // age. Those are the three piece of information we need to download a PDB
        // off Microsoft's symbol server.
        Ok(Some(PdbId::new(
            String::from_utf8(file_name)?,
            codeview.guid.into(),
            codeview.age,
        )?))
    }

    pub fn read_exports(
        &self,
        addr_space: &mut impl AddrSpace,
    ) -> Result<Option<Vec<(Rva, String)>>> {
        // Let's check if there's an EAT.
        debug!("parsing EAT..");
        if usize::try_from(self.export_data_dir.size).unwrap()
            < mem::size_of::<ImageDebugDirectory>()
        {
            debug!("debug dir is too small");
            return Ok(None);
        }

        // Read it.
        let export_dir_addr = self
            .base
            .checked_add(u64::from(self.export_data_dir.virtual_address))
            .ok_or(anyhow!("export_data_dir"))?;
        let Some(export_dir) =
            try_read_struct_at::<ImageExportDirectory>(addr_space, export_dir_addr)?
        else {
            debug!("failed to read ImageExportDirectory {export_dir_addr:#x} because of mem translation");
            return Ok(None);
        };

        // Read the ordinal / name arrays.
        // """
        // The export name pointer table is an array of addresses (RVAs) into the export
        // name table. The pointers are 32 bits each and are relative to the image base.
        // The pointers are ordered lexically to allow binary searches.
        // An export name is defined only if the export name pointer table contains a
        // pointer to it. """
        let n_names = export_dir.number_of_names;
        let addr_of_names = export_dir.address_of_names;
        // """
        // The export ordinal table is an array of 16-bit unbiased indexes into the
        // export address table. Ordinals are biased by the Ordinal Base field of the
        // export directory table. In other words, the ordinal base must be subtracted
        // from the ordinals to obtain true indexes into the export address table.
        // """
        let addr_of_ords = export_dir.address_of_name_ordinals;
        let mut names = Vec::with_capacity(n_names.try_into()?);
        let mut ords = Vec::with_capacity(names.len());
        for name_idx in 0..n_names {
            // Read the name RVA's..
            let name_rva_addr =
                array_offset(self.base, addr_of_names, name_idx, mem::size_of::<u32>())
                    .ok_or(anyhow!("name_rva_addr"))?;
            let Some(name_rva) = try_read_struct_at::<u32>(addr_space, name_rva_addr)
                .with_context(|| "failed to read EAT's name array".to_string())?
            else {
                debug!(
                    "failed to read EAT's name array {name_rva_addr:#x} because of mem translation"
                );
                return Ok(None);
            };

            let name_addr = self
                .base
                .checked_add(name_rva.into())
                .ok_or(anyhow!("overflow w/ name_addr"))?;
            // ..then read the string in memory.
            let Some(name) = read_string(addr_space, name_addr, 64)? else {
                debug!("failed to read export's name #{name_idx}");
                return Ok(None);
            };
            names.push(name);

            // Read the ordinal.
            let ord_addr = array_offset(self.base, addr_of_ords, name_idx, mem::size_of::<u16>())
                .ok_or(anyhow!("ord_addr"))?;
            let Some(ord) = try_read_struct_at::<u16>(addr_space, ord_addr)
                .context("failed to read EAT's ord array")?
            else {
                debug!("failed to read EAT's ord array {ord_addr:#x} because of mem translation");
                return Ok(None);
            };
            ords.push(ord);
        }

        debug!("read {n_names} names");

        // Read the address array.
        //
        // """
        // The export address table contains the address of exported entry points and
        // exported data and absolutes. An ordinal number is used as an index into the
        // export address table.
        // """
        let addr_of_functs = export_dir.address_of_functions;
        let n_functs = export_dir.number_of_functions;
        let mut address_rvas = Vec::with_capacity(n_functs.try_into()?);
        for addr_idx in 0..n_functs {
            // Read the RVA.
            let address_rva_addr =
                array_offset(self.base, addr_of_functs, addr_idx, mem::size_of::<u32>())
                    .ok_or(anyhow!("overflow w/ address_rva_addr"))?;

            let Some(address_rva) = try_read_struct_at::<u32>(addr_space, address_rva_addr)
                .with_context(|| "failed to read EAT's address array".to_string())?
            else {
                debug!("failed to read EAT's address array {address_rva_addr:#x} because of mem translation");
                return Ok(None);
            };

            address_rvas.push(address_rva);
        }

        debug!("read {n_functs} addresses");

        // Time to build the EAT.
        let eat_range = Range {
            start: self.export_data_dir.virtual_address,
            end: self
                .export_data_dir
                .virtual_address
                .checked_add(self.export_data_dir.size)
                .ok_or(anyhow!("overflow w/ export data dir size"))?,
        };

        let mut exports = Vec::with_capacity(address_rvas.len());
        for (unbiased_ordinal, addr_rva) in address_rvas.drain(..).enumerate() {
            let ordinal = unbiased_ordinal
                .checked_add(export_dir.base.try_into()?)
                .ok_or(anyhow!("overflow w/ biased_ordinal"))?;
            let name = ords
                .iter()
                .position(|&o| usize::from(o) == unbiased_ordinal)
                .map(|name_idx| names[name_idx].clone())
                .unwrap_or_else(|| format!("ORD#{ordinal}"));

            let forwarder = eat_range.contains(&addr_rva);
            if !forwarder {
                exports.push((addr_rva, name.clone()));
            }
        }

        debug!("built table w/ {} entries", exports.len());

        Ok(Some(exports))
    }
}
