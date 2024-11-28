use crate::profiler::symbolizer::elf::ElfMetadata;
use std::path::PathBuf;

use super::error::SymbolizerError;
use super::symbol::Symbol;

use moka::sync::Cache;

pub struct SymbolStore {
    cache: Cache<u64, ElfMetadata>, // inode -> elf
}

impl SymbolStore {
    pub fn new(path: PathBuf) -> Result<SymbolStore, SymbolizerError> {
        Ok(Self {
            cache: Cache::new(100),
        })
    }

    pub fn get_symbol(&self, dso: &PathBuf, offset: u64) -> Result<Symbol, SymbolizerError> {
        let elf = self.fetch_elf(dso)?;
        elf.find_symbol(offset)
    }

    fn fetch_elf(&self, dso: &PathBuf) -> Result<ElfMetadata, SymbolizerError> {
        let inode = self.load_elf(dso)?;
        match self.cache.get(&inode) {
            Some(val) => Ok(val),
            None => Err(SymbolizerError::FetchElfFailed(dso.clone())),
        }
    }

    fn load_elf(&self, dso: &PathBuf) -> Result<u64, SymbolizerError> {
        let inode = ElfMetadata::get_inode(dso)?;
        if !self.cache.contains_key(&inode) {
            log::info!("load elf {dso:?}, {inode}");
            self.cache.insert(inode, ElfMetadata::new(dso.clone())?);
        }

        Ok(inode)
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
