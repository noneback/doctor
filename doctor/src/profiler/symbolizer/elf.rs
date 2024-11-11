use std::{
    collections::BTreeSet,
    error::Error,
    fs::File,
    io::{BufReader, Read},
    path::PathBuf,
};

use super::{error::SymbolizerError, symbol::Symbol};

use blazesym::symbolize::{Sym, Symbolize};
use gimli::{Dwarf, RunTimeEndian, Section, SectionId};
use goblin::{
    container::Endian,
    elf::{program_header::PT_LOAD, Elf, ProgramHeader},
};
use memmap2::{Mmap, MmapOptions};

struct DwarfInfo {}

impl DwarfInfo {
    pub fn new() -> Self {
        DwarfInfo {}
    }
}

#[derive(Debug, Clone)]
pub struct ElfMetadata {
    path: PathBuf,
    syms: BTreeSet<Symbol>,
    debug_info: BTreeSet<Symbol>, // from dwarf
    pt_loads: Vec<ProgramHeader>,
}

impl ElfMetadata {
    pub fn new(path: PathBuf) -> Result<ElfMetadata, SymbolizerError> {
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
            .map(|h| h.clone())
            .filter(|h| h.p_type == PT_LOAD)
            .collect::<Vec<ProgramHeader>>();

        // static sy: BTreeSet<Symbol>ms
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

        let endian = if elf.little_endian {
            RunTimeEndian::Little
        } else {
            RunTimeEndian::Big
        };

        let dwarf = Dwarf::load(|id| Self::load_dwarf(id, &elf, &mmap, endian))?;
        let debug_info = BTreeSet::new();

        Ok(Self {
            path,
            syms,
            debug_info,
            pt_loads,
        })
    }

    fn load_dwarf<'input, Endian: gimli::Endianity>(
        id: SectionId,
        elf: &Elf,
        mmap: &'input Mmap,
        endian: Endian,
    ) -> Result<gimli::EndianSlice<'input, Endian>, SymbolizerError> {
        let data = match elf
            .section_headers
            .iter()
            .find(|h| elf.shdr_strtab.get_at(h.sh_name).unwrap_or("") == id.name())
        {
            Some(section) => {
                let start = section.sh_offset as usize;
                let end = start + section.sh_size as usize;
                &mmap[start..end]
            }
            None => &[],
        };

        Ok(gimli::EndianSlice::new(data, endian))
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
