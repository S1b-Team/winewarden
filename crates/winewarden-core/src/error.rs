use thiserror::Error;

#[derive(Debug, Error)]
pub enum WineWardenError {
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("policy violation: {0}")]
    Policy(String),
}
