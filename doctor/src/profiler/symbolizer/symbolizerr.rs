use super::{error::SymbolizerError, symbol::Symbol, symbol_store::SymbolStore};

use std::path::PathBuf;
pub struct Symbolizerr {
    dss: SymbolStore,
}

impl Symbolizerr {
    pub fn new(path: PathBuf) -> Result<Symbolizerr, SymbolizerError> {
        Ok(Self {
            dss: SymbolStore::new(path)?,
        })
    }

    pub fn symbolize(&self, dso: &PathBuf, offset: u64) -> Result<Symbol, SymbolizerError> {
        self.dss.get_symbol(dso, offset)
    }
    pub fn batch_symbolize(_dso: PathBuf, _offsets: &[u64]) {}
}
