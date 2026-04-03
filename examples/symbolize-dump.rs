// Axel '0vercl0k' Souchet
use std::cmp::min;
use std::env;
use std::io::{self, Write};
use std::path::PathBuf;

use addr_symbolizer::{AddrSpace, Module, PdbLookupConfig, Symbolizer};
use anyhow::Result;
use clap::Parser;
use kdmp_parser::parse::KernelDumpParser;
use kdmp_parser::virt;
use udmp_parser::UserDumpParser;

/// The command line arguments.
#[derive(Debug, Parser)]
#[command(about = "Symbolize an address from a user or kernel dump file.")]
enum CliArgs {
    User { dump: PathBuf, addr: String },
    Kernel { dump: PathBuf, addr: String },
}

/// Parse the `_NT_SYMBOL_PATH` environment variable to try the path of a symbol
/// cache.
fn sympath() -> Option<PathBuf> {
    let env = env::var("_NT_SYMBOL_PATH").ok()?;

    if !env.starts_with("srv*") {
        return None;
    }

    let sympath = env.strip_prefix("srv*").unwrap();
    let sympath = PathBuf::from(sympath.split('*').next().unwrap());

    if sympath.is_dir() {
        Some(sympath)
    } else {
        None
    }
}

fn user(dmp: &UserDumpParser, addr: u64) -> Result<()> {
    #[derive(Debug)]
    struct UserDumpAddrSpace<'dmp>(&'dmp UserDumpParser<'dmp>);
    impl AddrSpace for UserDumpAddrSpace<'_> {
        fn read_at(&mut self, addr: u64, mut buf: &mut [u8]) -> io::Result<usize> {
            let mut cur_addr = addr;
            let mut read_len = 0;
            while read_len < buf.len() {
                let Some(block) = self.0.get_mem_block(addr) else {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        format!("no mem block found for {addr:#x}"),
                    ));
                };

                let Some(data) = block.data_from(cur_addr) else {
                    panic!();
                };

                let left = buf.len() - read_len;
                let len = min(data.len(), left);
                buf.write_all(&data[..len]).unwrap();
                cur_addr += u64::try_from(len).unwrap();
                read_len += len;
            }

            Ok(read_len)
        }
    }

    let modules = dmp
        .modules()
        .values()
        .map(|module| {
            Module::new(
                module.path.file_name().unwrap().to_string_lossy(),
                module.start_addr(),
                module.end_addr(),
            )
        })
        .collect::<Vec<_>>();

    let mut wrapper = UserDumpAddrSpace(dmp);
    let mut symb = Symbolizer::new(
        PdbLookupConfig::with_msft_symsrv(sympath().expect("define a _NT_SYMBOL_PATH"))?,
        modules,
    );

    println!("{addr:#x}: {}", symb.symbolize_full(&mut wrapper, addr)?);

    Ok(())
}

fn kernel(dmp: &KernelDumpParser, addr: u64) -> Result<()> {
    #[derive(Debug)]
    struct KernelDumpAdrSpace<'dmp>(&'dmp KernelDumpParser);
    impl AddrSpace for KernelDumpAdrSpace<'_> {
        fn read_at(&mut self, addr: u64, buf: &mut [u8]) -> io::Result<usize> {
            virt::Reader::new(self.0)
                .read(addr.into(), buf)
                .map_err(|e| io::Error::new(io::ErrorKind::Unsupported, e))
        }
    }

    let mut modules = Vec::new();
    for (at, name) in dmp.user_modules().chain(dmp.kernel_modules()) {
        let (_, filename) = name.rsplit_once('\\').unwrap_or((name, name));
        modules.push(Module::new(
            filename.to_string(),
            at.start.into(),
            at.end.into(),
        ));
    }

    let mut wrapper = KernelDumpAdrSpace(dmp);
    let mut symb = Symbolizer::new(
        PdbLookupConfig::with_msft_symsrv(sympath().expect("define a _NT_SYMBOL_PATH"))?,
        modules,
    );

    println!("{addr:#x}: {}", symb.symbolize_full(&mut wrapper, addr)?);

    Ok(())
}

fn hex(x: &str) -> Result<u64> {
    let no_backtick = x.replace('`', "");
    let no_prefix = no_backtick.strip_prefix("0x").unwrap_or(x);

    Ok(u64::from_str_radix(no_prefix, 16)?)
}

fn main() -> Result<()> {
    #[cfg(debug_assertions)]
    env_logger::init();

    // Parse the CLI arguments.
    let args = CliArgs::parse();
    match args {
        CliArgs::User { dump, addr } => user(&UserDumpParser::new(dump)?, hex(&addr)?),
        CliArgs::Kernel { dump, addr } => kernel(&KernelDumpParser::new(dump)?, hex(&addr)?),
    }?;

    Ok(())
}
