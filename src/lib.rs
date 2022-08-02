#![feature(test)]
extern crate test;

pub mod baby_step_giant_step;
mod bit_range;
pub mod errors;
pub mod schnorr;
mod signed_integer;
pub mod twisted_elgamal;

#[cfg(feature = "bulletproofs")]
pub mod range_proof_bp;

#[cfg(not(feature = "bulletproofs"))]
pub mod range_proof_bm;

#[macro_use]
extern crate lazy_static;

mod hash;
