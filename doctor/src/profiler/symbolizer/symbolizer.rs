use super::{error::SymbolizerError, symbol::Symbol, symbol_store::SymbolStore};

use std::path::PathBuf;
pub struct Symbolizer {
    dss: SymbolStore,
}

impl Symbolizer {
    pub fn new(path: PathBuf) -> Result<Symbolizer, SymbolizerError> {
        Ok(Self {
            dss: SymbolStore::new(path)?,
        })
    }

    pub fn symbolize(
        &self,
        rootfs: &PathBuf,
        dso: &PathBuf,
        offset: u64,
    ) -> Result<Symbol, SymbolizerError> {
        let dso_path = rootfs.join(dso.strip_prefix("/").unwrap());

        self.dss.get_symbol(&dso_path, offset)
    }
    pub fn batch_symbolize(_dso: PathBuf, _offsets: &[u64]) {}
}
