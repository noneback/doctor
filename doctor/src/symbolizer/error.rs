use thiserror::Error;

#[derive(Error, Debug)]
pub enum SymbolizerError {
    #[error("fail to open symbol store:{0}")]
    OpenSymbolStoreFailed(#[from] std::io::Error),
}
