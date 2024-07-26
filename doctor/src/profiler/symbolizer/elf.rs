use std::{collections::BTreeSet, path::PathBuf};


use goblin::elf::ProgramHeader;

use super::{error::SymbolizerError, symbol::Symbol};

#[derive(Debug, Clone)]
pub struct ElfMetadata {
    path: PathBuf,
    syms: BTreeSet<Symbol>,
    pt_loads: Vec<ProgramHeader>,
}

impl ElfMetadata {
    pub fn new(path: PathBuf, syms: BTreeSet<Symbol>, pt_loads: Vec<ProgramHeader>) -> ElfMetadata {
        Self {
            path,
            syms,
            pt_loads,
        }
    }

    fn translate(&self, file_offset: u64) -> Option<u64> {
        self.pt_loads.iter().find_map(|h| {
            if (h.p_offset..h.p_offset + h.p_memsz).contains(&file_offset) {
                return Some(file_offset - h.p_offset + h.p_vaddr);
            }
            None
        })
    }

    pub fn find_symbol(&self, offset: u64) -> Result<Symbol, SymbolizerError> {
        match self.translate(offset) {
            Some(virt_offset) => {
                let target = Symbol {
                    addr: virt_offset,
                    name: None,
                };
                match self.syms.range(..target).next_back() {
                    Some(sym) => Ok(sym.clone()),
                    None => Err(SymbolizerError::SymbolNotFound(
                        self.path.clone(),
                        virt_offset,
                    )),
                }
            }

            None => Err(SymbolizerError::TranslateVirtOffsetFailed(
                self.path.clone(),
                offset,
            )),
        }
    }
}
