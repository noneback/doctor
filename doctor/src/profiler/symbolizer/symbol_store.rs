use crate::profiler::symbolizer::elf::ElfMetadata;
use goblin::elf::program_header::PT_LOAD;
use goblin::elf::{Elf, ProgramHeader};
use sled::Db;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;

use super::error::SymbolizerError;
use super::symbol::Symbol;

use moka::sync::Cache;

// use rusqlite::Connection;
pub struct SymbolStore {
    cache: Cache<PathBuf, ElfMetadata>,
    db: Db,
}

impl SymbolStore {
    pub fn new(path: PathBuf) -> Result<SymbolStore, SymbolizerError> {
        Ok(Self {
            cache: Cache::new(100),
            db: sled::open(path)?,
        })
    }

    fn translate_virt_offset(_dso: &PathBuf, _offset: u64) -> Option<u64> {
        None
    }

    pub fn get_symbol(&self, dso: &PathBuf, offset: u64) -> Result<Symbol, SymbolizerError> {
        let elf = self.fetch_elf(dso)?;
        elf.find_symbol(offset)
    }

    fn fetch_elf(&self, dso: &PathBuf) -> Result<ElfMetadata, SymbolizerError> {
        self.load_elf(dso)?;
        match self.cache.get(dso) {
            Some(val) => Ok(val),
            None => Err(SymbolizerError::FetchElfFailed(dso.clone())),
        }
    }

    fn load_elf(&self, dso: &PathBuf) -> Result<(), SymbolizerError> {
        if self.cache.contains_key(dso) {
            return Ok(());
        }

        self.cache
            .insert(dso.clone(), ElfMetadata::new(dso.clone())?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetch_elf() {
        // 获取当前可执行文件路径
        println!("start");
        let ss = SymbolStore::new("/home/noneback/workspace/doctor/doctor/tests".into()).unwrap();
        let sym = ss.get_symbol(&"/root/workspace/profiler/bianque/main".into(), 0x3321b);

        println!("sym:\n {}", sym.unwrap());
    }
}
