use anyhow::Error;
use goblin::elf::{Elf, Sym};
use std::clone;
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashSet};
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::{BufReader, Read};
use std::path::PathBuf;

use moka::future::Cache;

use super::error::SymbolizerError;

#[derive(PartialEq, Eq, PartialOrd, Clone)]
struct Symbol {
    pub(crate) addr: u64,
    
    
    pub(crate) name: String,
}


impl Hash for Symbol {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.addr.hash(state); // only for single dso file
    }
}

impl Ord for Symbol {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.addr.cmp(&other.addr) {
            Ordering::Equal => self.name.cmp(&other.name),
            other => other,
        }
    }
}
// use rusqlite::Connection;
pub struct SymbolStore {
    cache: Cache<PathBuf, BTreeSet<Symbol>>,
    // db: Connection,
}

impl SymbolStore {
    pub fn new(path: PathBuf) -> Result<SymbolStore, SymbolizerError> {
        // let conn = Connection::open(path)?;
        Ok(Self {
            cache: Cache::new(100),
            // db: conn,
        })
    }

    pub fn fetch_process(pid: u64) {}

    pub fn fetch_elf(&self, dso: PathBuf) -> Result<(), Error> {
        let file = File::open(dso.clone())?;
        let mut reader = BufReader::new(file);
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer)?;
        let elf = Elf::parse(&buffer).expect("Failed to parse ELF file");
        // static syms
        let mut syms = elf
            .syms
            .iter()
            .filter(|s| s.is_function())
            .map(|sym| {
                let addr = sym.st_value;
                let name = elf.strtab.get_at(sym.st_name).unwrap_or("unknow");
                Symbol { addr, String::from("test") }
            })
            .collect::<BTreeSet<_>>();

        let dyn_syms = elf
            .dynsyms
            .iter()
            .filter(|s| s.is_function())
            .map(|sym| {
                let addr = sym.st_value;
                let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("unknow");
                Symbol { addr, name }
            })
            .collect::<BTreeSet<_>>();

        syms.extend(dyn_syms);
        self.cache.insert(dso, syms);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_fetch_elf() {
        // 获取当前可执行文件路径
        println!("start");
        let ss = SymbolStore::new("./".into()).unwrap();
        ss.fetch_elf("/proc/135657/root/usr/lib64/mysql/private/libprotobuf-lite.so.3.19.4".into())
            .unwrap();
        println!("end");
    }
}
