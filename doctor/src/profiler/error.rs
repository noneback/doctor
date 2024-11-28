use thiserror::Error;

use super::symbolizer::error::SymbolizerError;

#[derive(Error, Debug)]
pub enum TranslateError {
    #[error("data not found")]
    NotFound,
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("internal error")]
    Internal,
    #[error(transparent)]
    Io(#[from] std::io::Error), // 使用`from`属性自动从`std::io::Error`转换
    #[error("symbolize {0}")]
    Symbolize(SymbolizerError),
    #[error("anyhow {0}")]
    AnyError(#[from] anyhow::Error),
}

impl From<SymbolizerError> for TranslateError {
    fn from(err: SymbolizerError) -> Self {
        TranslateError::Symbolize(err)
    }
}
