use std::path::PathBuf;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SymbolizerError {
    #[error("fail to open symbol store: {0}")]
    OpenSymbolStoreFailed(#[from] std::io::Error),
    #[error("failed to fetch elf: {0}")]
    FetchElfFailed(PathBuf),
}
