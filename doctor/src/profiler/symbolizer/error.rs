use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SymbolizerError {
    #[error("fail to open symbol store: {0}")]
    OpenSymbolStoreDiskDBFailed(#[from] sled::Error),
    #[error("failed to fetch elf: {0}")]
    FetchElfFailed(PathBuf),
    #[error("load {0}, elf failed: {1}")]
    SymbolStoreIOFailed(PathBuf, std::io::Error),
    #[error("symbol not found in {0}, off {1}")]
    SymbolNotFound(PathBuf, u64),
}