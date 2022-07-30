use std::error;
use std::fmt;

use thiserror::Error;

#[cfg(feature = "bulletproofs")]
use bulletproofs::r1cs::R1CSError;

pub type Result<T> = std::result::Result<T, EigenCTError>;

#[derive(Error, Debug)]
pub enum EigenCTError {
    #[cfg(feature = "bulletproofs")]
    #[error("Invalid range proof from BulletProof")]
    InvalidRangeProof(#[from] R1CSError),

    #[error("invalid range (expected {expected:?}, found {found:?})")]
    OutOfRangeError { expected: String, found: String },
    #[error("unknown data store error")]
    Unknown,
}
