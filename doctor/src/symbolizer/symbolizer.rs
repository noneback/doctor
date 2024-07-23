use super::symbol_store::SymbolStore;

use std::path::PathBuf;
struct Symbolizer {
    dss: SymbolStore,
}

impl Symbolizer {
    pub fn symbolize(dso: PathBuf, offset: u64) {}
    pub fn batch_symbolize(dso: PathBuf, offsets: &[u64]) {}
}
