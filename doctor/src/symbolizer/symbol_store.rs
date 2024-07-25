use goblin::elf::Elf;
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt::Display;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::{BufReader, Read};
use std::path::PathBuf;

use moka::sync::Cache;

use super::error::SymbolizerError;

#[derive(PartialEq, Eq, PartialOrd, Clone, Debug)]
struct Symbol {
    pub(crate) addr: u64,
    pub(crate) name: Option<String>,
}

impl Display for Symbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.name {
            Some(name) => write!(f, "{} (f_0x{:016X})", name, self.addr),
            None => write!(f, "Unnamed (f_0x{:016X})", self.addr),
        }
    }
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
}

impl SymbolStore {
    pub fn new(path: PathBuf) -> SymbolStore {
        Self {
            cache: Cache::new(100),
        }
    }

    pub fn get_symbol(&self, dso: &PathBuf, offset: u64) -> Option<Symbol> {
        let syms = self.fetch_elf(&dso).unwrap();
        let target = Symbol {
            addr: offset,
            name: None,
        };

        match syms.range(..target).next_back() {
            Some(s) => Some(s.clone()),
            None => None,
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
                match elf.dynstrtab.get_at(sym.st_name) {
                    Some(n) => Symbol {
                        addr: addr,
                        name: Some(String::from(n)),
                    },
                    None => Symbol {
                        addr: addr,
                        name: None,
                    },
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
                        addr: addr,
                        name: Some(String::from(n)),
                    },
                    None => Symbol {
                        addr: addr,
                        name: None,
                    },
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
        let ss = SymbolStore::new("./".into());
        let sym = ss.get_symbol(
            &"/usr/local/aegis/aegis_client/aegis_11_91/libFileQuara.so".into(),
            0x65417,
        );

        println!("sym:\n {}", sym.unwrap());
    }
}
