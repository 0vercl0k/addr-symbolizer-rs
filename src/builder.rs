use std::fs::{self, File};
// Axel '0vercl0k' Souchet - June 7 2024
use std::path::{Path, PathBuf};

use anyhow::anyhow;
use log::{debug, info};

use crate::pdbcache::format_symcache_path;
use crate::symbolizer::{Config, PdbLookupMode};
use crate::{Guid, Module, PdbId, Result, Symbolizer};

#[derive(Default)]
pub struct NoSymcache;

pub struct Symcache(PathBuf);

/// Builder for [`Symbolizer`].
#[derive(Default, Debug)]
pub struct Builder<SC> {
    symcache: SC,
    modules: Vec<Module>,
    mode: PdbLookupMode,
}

impl<SC> Builder<SC> {
    pub fn msft_symsrv(self) -> Builder<SC> {
        self.online(vec!["https://msdl.microsoft.com/download/symbols/"])
    }

    pub fn online(mut self, symsrvs: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.mode = PdbLookupMode::Online {
            symsrvs: symsrvs.into_iter().map(Into::into).collect(),
        };

        self
    }
}

impl Builder<NoSymcache> {
    pub fn symcache(self, cache: impl AsRef<Path>) -> Result<Builder<Symcache>> {
        let cache = cache.as_ref();
        if !(cache.is_dir() && cache.exists()) {
            return Err(anyhow!("{cache:?} isn't a dir or doesn't exist").into());
        }

        let Self { modules, mode, .. } = self;

        Ok(Builder {
            symcache: Symcache(cache.to_path_buf()),
            modules,
            mode,
        })
    }
}

impl<SC> Builder<SC> {
    pub fn modules(mut self, modules: impl IntoIterator<Item = Module>) -> Self {
        self.modules = modules.into_iter().collect();

        self
    }
}

impl Builder<Symcache> {
    pub fn import_pdbs(self, dirs: impl Iterator<Item = impl AsRef<Path>>) -> Result<Self> {
        for dir in dirs {
            let dir = dir.as_ref();
            if !(dir.exists() && dir.is_dir()) {
                return Err(anyhow!(
                    "cannot import pdb from {dir:?} as it doesn't exist or isn't a directory"
                )
                .into());
            }

            for file in dir.read_dir()? {
                let path = file?.path();
                if !path.is_file() {
                    debug!("skipping {path:?} because not a file");
                    continue;
                }

                let Some(ext) = path.extension() else {
                    debug!("skipping {path:?} because doesn't have an extension");
                    continue;
                };

                if ext != "pdb" {
                    debug!("skipping {path:?} because not a pdb file");
                    continue;
                }

                let Some(filename) = path.file_name() else {
                    debug!("skipping {path:?} because no filename");
                    continue;
                };

                let mut pdb = pdb::PDB::open(File::open(&path)?)?;
                let info = pdb.pdb_information()?;
                let debug_info = pdb.debug_information()?;
                let Some(age) = debug_info.age() else {
                    continue;
                };

                let pdbid = PdbId::new(filename, Guid::from(info.guid.to_bytes_le()), age)?;
                let cached_pdb = format_symcache_path(&self.symcache.0, &pdbid);
                if cached_pdb.exists() {
                    debug!("skipping {path:?} because already in symbol cache");
                    continue;
                }

                let Some(cached_pdb_dir) = cached_pdb.parent() else {
                    return Err(anyhow!("{cached_pdb:?} has no parent").into());
                };

                info!("copying {path:?} into the symbol cache at {cached_pdb:?}");
                fs::create_dir_all(cached_pdb_dir)?;
                fs::copy(path, cached_pdb)?;
            }
        }

        Ok(self)
    }

    pub fn build(self) -> Result<Symbolizer> {
        let Self {
            symcache,
            modules,
            mode,
        } = self;

        if !symcache.0.exists() {
            return Err(anyhow!("symcache {:?} does not exist", symcache.0).into());
        }

        let config = Config {
            symcache: symcache.0,
            modules,
            mode,
        };

        Symbolizer::new(config)
    }
}
