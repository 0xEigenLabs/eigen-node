use std::error;
use std::fmt;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, EigenCTError>;

#[derive(Error, Debug)]
pub enum EigenCTError {
    #[error("Invalid range proof, `{0}`")]
    InvalidRangeProof(String),

    #[error("Invalid convert from string `{0}`")]
    InvalidConvertFromStr(String),

    #[error("Peseidon hash error`{0}`")]
    PoseidonHashError(String),

    #[error("sign error`{0}`")]
    SignError(String),

    #[error("The size should be `{0}`")]
    BytesLengthError(usize),

    #[error("invalid range (expected {expected:?}, found {found:?})")]
    OutOfRangeError { expected: String, found: String },
    #[error("unknown data store error")]
    Unknown,
}
