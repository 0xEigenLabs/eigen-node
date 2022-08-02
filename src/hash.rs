use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use ff::*;
use num_bigint::BigUint;
use num_traits::Num;
use poseidon_rs::{Fr, Poseidon};

use crate::errors::{EigenCTError, Result};

use std::convert::TryInto;

pub struct Hasher {
    h: Poseidon,
    e: Vec<Vec<u8>>,
}

///
/// The input of poseidon hash is Fr, we need convert the element in integer field Fr with
/// order 21888242871839275222246405745257275088548364400416034343698204186575808495617.
///
impl Hasher {
    pub fn new() -> Self {
        Hasher {
            h: Poseidon::new(),
            e: vec![],
        }
    }

    fn multi_round_hash(&self) -> Result<Fr> {
        let mut compressed_ristretto_to_fr: Vec<Fr> = self
            .e
            .iter()
            .map(|point| {
                let b = BigUint::from_bytes_be(&point[..]);
                Fr::from_str(&b.to_str_radix(10)).unwrap()
            })
            .collect();

        let mut digest: Fr;
        let round_size: usize = 5;
        if compressed_ristretto_to_fr.len() <= round_size {
            digest = self
                .h
                .hash(compressed_ristretto_to_fr)
                .map_err(|e| EigenCTError::PoseidonHashError(e))?;
        } else {
            let round: usize = 1 + compressed_ristretto_to_fr.len() / round_size;
            digest = self
                .h
                .hash(
                    compressed_ristretto_to_fr
                        .get(0..round_size)
                        .unwrap()
                        .to_vec(),
                )
                .map_err(|e| EigenCTError::PoseidonHashError(e))?;
            for i in 1..round {
                let begin = i * (round_size - 1) + 1;
                let mut end = begin + round_size;
                if begin >= compressed_ristretto_to_fr.len() {
                    break;
                }
                if end > compressed_ristretto_to_fr.len() {
                    end = compressed_ristretto_to_fr.len();
                }
                let mut buffer = vec![digest];
                buffer.extend(compressed_ristretto_to_fr.get(begin..end).unwrap());
                digest = self
                    .h
                    .hash(buffer)
                    .map_err(|e| EigenCTError::PoseidonHashError(e))?;
            }
        }

        Ok(digest)
    }

    pub fn update(&mut self, point: &RistrettoPoint) -> &mut Self {
        self.e.push(point.compress().as_bytes().to_vec());
        self
    }

    pub fn to_point(&self) -> Result<RistrettoPoint> {
        let digest = self.multi_round_hash()?;
        let digest_str = digest.to_string();
        let substr = &digest_str[5..(digest_str.len() - 1)];
        let mut first_part = substr.as_bytes();
        let mut v = [0u8; 64];
        v.copy_from_slice(&first_part);
        Ok(RistrettoPoint::from_uniform_bytes(&v))
    }

    pub fn to_scalar(&mut self) -> Result<Scalar> {
        let digest = self.multi_round_hash()?;
        let digest_str = digest.to_string();
        let substr = &digest_str[5..(digest_str.len() - 1)];
        let digest_to_str = substr.as_bytes();

        let mut v = [0u8; 64];
        v.copy_from_slice(digest_to_str);
        Ok(Scalar::from_bytes_mod_order_wide(&v))
    }
}

#[test]
fn test_hash() {}
