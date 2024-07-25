use goblin::elf::Elf;
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
    cache: Cache<PathBuf, BTreeSet<Symbol>>,
    db: Db,
}

impl SymbolStore {
    pub fn new(path: PathBuf) -> Result<SymbolStore, SymbolizerError> {
        Ok(Self {
            cache: Cache::new(100),
            db: sled::open(path)?,
        })
    }

    pub fn get_symbol(&self, dso: &PathBuf, offset: u64) -> Result<Symbol, SymbolizerError> {
        let syms = self.fetch_elf(dso)?;
        let target = Symbol {
            addr: offset,
            name: None,
        };

        match syms.range(..target).next_back() {
            Some(sym) => Ok(sym.clone()),
            None => Err(SymbolizerError::SymbolNotFound(dso.clone(), offset)),
        }
    }

    fn fetch_elf(&self, dso: &PathBuf) -> Result<BTreeSet<Symbol>, SymbolizerError> {
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

        let file = File::open(dso.clone())
            .map_err(|e| SymbolizerError::SymbolStoreIOFailed(dso.clone(), e))?;
        let mut reader = BufReader::new(file);
        let mut buffer = Vec::new();
        reader
            .read_to_end(&mut buffer)
            .map_err(|e| SymbolizerError::SymbolStoreIOFailed(dso.clone(), e))?;
        let elf = Elf::parse(&buffer).expect("Failed to parse ELF file");
        // static syms
        let mut syms = elf
            .syms
            .iter()
            .filter(|s| s.is_function())
            .map(|sym| {
                let addr = sym.st_value;
                match elf.dynstrtab.get_at(sym.st_name) {
                    Some(n) => Symbol {
                        addr,
                        name: Some(String::from(n)),
                    },
                    None => Symbol { addr, name: None },
                }
            })
            .collect::<BTreeSet<_>>();

        let dyn_syms = elf
            .dynsyms
            .iter()
            .filter(|s| s.is_function())
            .map(|sym| {
                let addr = sym.st_value;
                match elf.dynstrtab.get_at(sym.st_name) {
                    Some(n) => Symbol {
                        addr,
                        name: Some(String::from(n)),
                    },
                    None => Symbol { addr, name: None },
                }
            })
            .collect::<BTreeSet<_>>();
        syms.extend(dyn_syms);
        self.cache.insert(dso.clone(), syms);
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
        let sym = ss.get_symbol(&"/usr/lib/libc.so.6".into(), 0x92242);

        println!("sym:\n {}", sym.unwrap());
    }
}
