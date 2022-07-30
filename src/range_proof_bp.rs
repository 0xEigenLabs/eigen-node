#![allow(non_snake_case)]
use bulletproofs::r1cs::{ConstraintSystem, LinearCombination, R1CSError};
use core::iter;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use merlin::Transcript;

use crate::bit_range::BitRange;
use crate::signed_integer::SignedInteger;
use bulletproofs::r1cs::{Prover, R1CSProof, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};

use rand::CryptoRng;
use rand::RngCore;

#[cfg(feature = "bulletproofs")]
pub struct RangeProof {
    pub pc_gens: PedersenGens,
    pub bp_gens: BulletproofGens,
}

impl RangeProof {
    pub fn new() -> RangeProof {
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(64, 1);
        RangeProof { pc_gens, bp_gens }
    }
    fn range_proof<CS: ConstraintSystem>(
        cs: &mut CS,
        mut v: LinearCombination,
        v_assignment: Option<SignedInteger>,
        n: BitRange,
    ) -> Result<(), R1CSError> {
        let mut exp_2 = Scalar::one();
        let n_usize: usize = n.into();

        for i in 0..n_usize {
            let (a, b, o) = cs.allocate_multiplier(v_assignment.and_then(|q| {
                q.to_u64().map(|p| {
                    let bit: u64 = (p >> i) & 1;
                    ((1 - bit).into(), bit.into())
                })
            }))?;
            cs.constrain(o.into());
            cs.constrain(a + (b - 1u64));

            v = v - b * exp_2;
            exp_2 = exp_2 + exp_2;
        }
        cs.constrain(v);
        Ok(())
    }

    fn prove<R: RngCore + CryptoRng>(
        &self,
        v: SignedInteger,
        rng: &mut R,
    ) -> Result<(R1CSProof, CompressedRistretto), R1CSError> {
        let bit_width = BitRange::new(32).ok_or(R1CSError::GadgetError {
            description: "Invalid bitrange; Bitrange must be between 0 and 64".to_string(),
        })?;
        let mut prover_transcript = Transcript::new(b"range_proof");
        let mut prover = Prover::new(&self.pc_gens, &mut prover_transcript);
        let (comm, var) = prover.commit(v.into(), Scalar::random(rng));
        Self::range_proof(&mut prover, var.into(), Some(v), bit_width)?;
        let proof = prover.prove(&self.bp_gens)?;
        Ok((proof, comm))
    }

    fn verify(
        &self,
        proof: &R1CSProof,
        comm: CompressedRistretto,
    ) -> Result<(), R1CSError> {
        let bit_width = BitRange::new(32).ok_or(R1CSError::GadgetError {
            description: "Invalid bitrange; Bitrange must be between 0 and 64".to_string(),
        })?;
        let mut verifier_transcript = Transcript::new(b"range_proof");
        let mut verifier = Verifier::new(&mut verifier_transcript);
        let var = verifier.commit(comm);
        Self::range_proof(&mut verifier, var.into(), None, bit_width)?;
        Ok(verifier.verify(&proof, &self.pc_gens, &self.bp_gens)?)
    }
}
