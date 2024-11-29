use std::{
    collections::BTreeSet,
    fs::{metadata, File},
    os::linux::fs::MetadataExt,
    path::PathBuf,
};
use symbolic::{
    common::Name,
    demangle::{Demangle, DemangleOptions},
};

use super::{error::SymbolizerError, symbol::Symbol};

use goblin::elf::{program_header::PT_LOAD, Elf, ProgramHeader};
use log::debug;
use memmap2::MmapOptions;
use wholesym::{SymbolManager, SymbolManagerConfig};

#[derive(Debug, Clone)]
pub struct ElfMetadata {
    path: PathBuf,
    debug_info: BTreeSet<Symbol>,
    pt_loads: Vec<ProgramHeader>,
    inode: u64,
}

impl ElfMetadata {
    pub fn load_sym_from_elf(
        path: &PathBuf,
    ) -> Result<(BTreeSet<Symbol>, Vec<ProgramHeader>), SymbolizerError> {
        let file = File::open(path.clone())
            .map_err(|e| SymbolizerError::SymbolStoreIOFailed(path.clone(), e))?;
        let mmap = unsafe {
            MmapOptions::new()
                .map(&file)
                .map_err(|e| SymbolizerError::MMapIOFailed(path.clone(), e))?
        };

        let elf = Elf::parse(&mmap).expect("Failed to parse ELF file");

        let pt_loads = elf
            .program_headers
            .clone()
            .into_iter()
            .filter(|h| h.p_type == PT_LOAD)
            .collect::<Vec<ProgramHeader>>();

        let mut debug_info = BTreeSet::new();
        tokio::task::block_in_place(|| {
            let symbol_manager = SymbolManager::with_config(SymbolManagerConfig::default());
            let symbol_map_f = symbol_manager.load_symbol_map_for_binary_at_path(path, None);
            let symbol_map = tokio::runtime::Handle::current()
                .block_on(symbol_map_f)
                .unwrap(); // TODO: deal with

            debug!("eso path: {:?}, build {}", &path, symbol_map.debug_id());
            let opt = DemangleOptions::name_only();
            symbol_map.iter_symbols().for_each(|s| {
                let demangled = Name::from(s.1).try_demangle(opt).to_string();

                debug_info.insert(Symbol {
                    addr: s.0 as u64,
                    name: Some(demangled),
                });
            });

            symbol_map.debug_id()
        });

        Ok((debug_info, pt_loads))
    }

    pub fn get_inode(path: &PathBuf) -> Result<u64, SymbolizerError> {
        let f_meta = metadata(path).map_err(SymbolizerError::GetInodeFailed)?;
        Ok(f_meta.st_ino())
    }

    pub fn new(path: PathBuf) -> Result<ElfMetadata, SymbolizerError> {
        let (debug_info, pt_loads) = ElfMetadata::load_sym_from_elf(&path)?;
        let inode = Self::get_inode(&path)?;
        Ok(Self {
            path,
            debug_info,
            pt_loads,
            inode,
        })
    }

    // translate file offset -> relative offset
    fn translate(&self, file_offset: u64) -> Option<u64> {
        if !self.pt_loads.is_empty() {
            Some(file_offset - self.pt_loads[0].p_offset)
        } else {
            None
        }
    }

    pub fn find_symbol(&self, offset: u64) -> Result<Symbol, SymbolizerError> {
        match self.translate(offset) {
            Some(relative_offset) => {
                let target = Symbol {
                    addr: relative_offset,
                    name: None,
                };
                match self.debug_info.range(..target).next_back() {
                    Some(sym) => Ok(sym.clone()),
                    None => Err(SymbolizerError::SymbolNotFound(
                        self.path.clone(),
                        relative_offset,
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

// #[cfg(test)]
// mod tests {
//     use super::*;
//     #[tokio::main]
//     #[test]
//     async fn test_sysm() {
//         let elf = ElfMetadata::new(
//             "/root/.vscode-server/bin/8b3775030ed1a69b13e4f4c628c612102e30a681/node".into(),
//         )
//         .unwrap();
//         println!(
//             "debug info {}, syms {}",
//             elf.debug_info.len(),
//             elf.syms.len()
//         );
//         let mut debug_info: Vec<_> = elf.debug_info.iter().map(|s| s).collect();
//         let mut syms: Vec<_> = elf.syms.iter().map(|s| s).collect();
//         debug_info.sort_by_key(|s| s.addr);
//         syms.sort_by_key(|s| s.addr);
//         // let mut miss = 0;

//         // elf.syms.iter().for_each(|s| {
//         //     if !debug_info.contains(s) {
//         //         miss += 1;
//         //     }
//         //     println!("sym {:?}", s);
//         // });
//         println!(
//             "debug info {:#?}, syms {:#?}",
//             &debug_info[0..10],
//             &syms[0..10]
//         );
//     }
// }
