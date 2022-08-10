use ff::*;
use poseidon_rs::{Fr, Poseidon};

use crate::errors::{EigenCTError, Result};
use babyjubjub_rs::PrivateKey;
use babyjubjub_rs::{decompress_point, Point};

use crate::fr::*;
use core::cmp::min;
use num_bigint::{BigInt, Sign};

use digest::{BlockInput, FixedOutput, Update};
use generic_array::GenericArray;

pub struct Hasher {
    h: Poseidon,
    e: Vec<Vec<u8>>,
}

impl Clone for Hasher {
    fn clone(&self) -> Self {
        Hasher {
            h: Poseidon::new(),
            e: self.e.clone(),
        }
    }
}

///
/// The input of poseidon hash is Fr, we need convert the element in integer field Fr with
/// field size = 21888242871839275222246405745257275088548364400416034343698204186575808495617.
///
impl Hasher {
    pub fn new() -> Self {
        Hasher {
            h: Poseidon::new(),
            e: vec![],
        }
    }

    /// FIXME, secure prove
    fn multi_round_hash(&self) -> Result<Fr> {
        let mut point_to_fr: Vec<Fr> = self
            .e
            .iter()
            .map(|point| {
                let n = BigInt::from_bytes_le(Sign::Plus, point);
                bigint_to_fr(&n)
            })
            .collect();

        let mut digest: Fr;
        let round_size: usize = 5;
        if point_to_fr.len() <= round_size {
            digest = self
                .h
                .hash(point_to_fr)
                .map_err(|e| EigenCTError::PoseidonHashError(e))?;
        } else {
            let round: usize = 1 + point_to_fr.len() / round_size;
            digest = self
                .h
                .hash(point_to_fr.get(0..round_size).unwrap().to_vec())
                .map_err(|e| EigenCTError::PoseidonHashError(e))?;
            for i in 1..round {
                let begin = i * (round_size - 1) + 1;
                let mut end = begin + round_size;
                if begin >= point_to_fr.len() {
                    break;
                }
                if end > point_to_fr.len() {
                    end = point_to_fr.len();
                }
                let mut buffer = vec![digest];
                buffer.extend(point_to_fr.get(begin..end).unwrap());
                digest = self
                    .h
                    .hash(buffer)
                    .map_err(|e| EigenCTError::PoseidonHashError(e))?;
            }
        }

        Ok(digest)
    }

    pub fn to_point(&self) -> Result<Point> {
        let digest = self.multi_round_hash()?;
        let n = fr_to_bigint(&digest);
        Ok(bigint_to_point(&n, false))
    }

    pub fn to_scalar(&self) -> Result<BigInt> {
        let h = self.multi_round_hash()?;
        Ok(fr_to_bigint(&h))
    }
}

impl Update for Hasher {
    fn update(&mut self, data: impl AsRef<[u8]>) {
        self.e.push(data.as_ref().to_vec());
    }

    fn chain(mut self, data: impl AsRef<[u8]>) -> Self
    where
        Self: Sized,
    {
        self.e.push(data.as_ref().to_vec());
        self
    }
}

impl BlockInput for Hasher {
    type BlockSize = digest::consts::U64;
}

impl FixedOutput for Hasher {
    type OutputSize = digest::consts::U32;

    fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
        let result = self.to_scalar().unwrap();
        let mut bytes = [0u8; 32];
        let (_, big_bytes) = result.to_bytes_le();
        let len = min(bytes.len(), big_bytes.len());
        bytes[..len].copy_from_slice(&big_bytes[..len]);
        *out = *GenericArray::from_slice(&bytes[..]);
    }

    fn finalize_into_reset(&mut self, out: &mut GenericArray<u8, Self::OutputSize>) {
        let result = self.to_scalar().unwrap();
        let mut bytes = [0u8; 32];
        let (_, big_bytes) = result.to_bytes_le();
        let len = min(bytes.len(), big_bytes.len());
        bytes[..len].copy_from_slice(&big_bytes[..len]);
        *out = *GenericArray::from_slice(&bytes[..]);
        self.e.clear();
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[test]
fn test_hash() {}
