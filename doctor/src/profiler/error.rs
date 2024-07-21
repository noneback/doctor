use thiserror::Error;

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
}
