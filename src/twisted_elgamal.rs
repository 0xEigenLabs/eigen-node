#![allow(non_snake_case)]
// https://eprint.iacr.org/2019/319
use bulletproofs::r1cs::{ConstraintSystem, LinearCombination, R1CSError};
use core::iter;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use merlin::Transcript;

use crate::bit_range::BitRange;
use crate::signed_integer::SignedInteger;
use bulletproofs::r1cs::{Prover, R1CSProof, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};

use super::baby_step_giant_step::bsgs;
use rand::CryptoRng;
use rand::RngCore;

trait TranscriptProtocol {
    fn domain_sep(&mut self);
    fn commit_scalar(&mut self, label: &'static [u8], scalar: &Scalar);
    fn commit_point(&mut self, label: &'static [u8], point: &CompressedRistretto);
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar;
    fn challenge_u8x32(&mut self, label: &'static [u8]) -> [u8; 32];
}

impl TranscriptProtocol for Transcript {
    fn domain_sep(&mut self) {
        // A proof-specific domain separation label that should
        // uniquely identify the proof statement.
        self.append_message(b"dom-sep", b"TranscriptProtocol Example");
    }

    fn commit_scalar(&mut self, label: &'static [u8], scalar: &Scalar) {
        self.append_message(label, scalar.as_bytes());
    }

    fn commit_point(&mut self, label: &'static [u8], point: &CompressedRistretto) {
        self.append_message(label, point.as_bytes());
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
        // Reduce a double-width scalar to ensure a uniform distribution
        let mut buf = [0; 64];
        self.challenge_bytes(label, &mut buf);
        Scalar::from_bytes_mod_order_wide(&buf)
    }

    fn challenge_u8x32(&mut self, label: &'static [u8]) -> [u8; 32] {
        let mut buf = [0u8; 32];
        self.challenge_bytes(label, &mut buf);
        buf
    }
}

pub struct TwistedElGamalPP {
    pub G: RistrettoPoint,
    pub H: RistrettoPoint,
    pub pc_gens: PedersenGens,
    pub bp_gens: BulletproofGens,
}

impl TwistedElGamalPP {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> TwistedElGamalPP {
        let G = RistrettoPoint::random(rng);
        let H = RistrettoPoint::random(rng);
        assert!(G.compress() != H.compress());
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(64, 1);
        TwistedElGamalPP {
            G,
            H,
            pc_gens,
            bp_gens,
        }
    }

    fn from_secret_decompressed(privkey: &Scalar) -> CompressedRistretto {
        (privkey * RISTRETTO_BASEPOINT_POINT).compress()
    }

    pub fn encrypt(
        &mut self,
        label: &'static [u8],
        value: SignedInteger,
        pk: &CompressedRistretto,
    ) -> Result<TwistedElGamalCT, R1CSError> {
        let mut transript = Transcript::new(b"TwistedElGamal");
        transript.domain_sep();
        transript.append_message(label, &pk.to_bytes());

        let mut rng = transript
            .build_rng()
            .rekey_with_witness_bytes(b"r", &pk.to_bytes())
            .finalize(&mut rand::thread_rng());

        let r = Scalar::random(&mut rng);

        let cx = r * (pk.decompress().unwrap());

        let v: Scalar = value.into();
        let cy = RistrettoPoint::optional_multiscalar_mul(
            iter::once(r).chain(iter::once(v)),
            iter::once(Some(self.G)).chain(iter::once(Some(self.H))),
        )
        .unwrap();

        let rp = self.prove_range_proof(value, &mut rng)?;

        // generate range proof
        Ok(TwistedElGamalCT {
            X: cx,
            Y: cy,
            RP: rp.0,
            comm: rp.1,
        })
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

    fn prove_range_proof<R: RngCore + CryptoRng>(
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

    fn verify_range_proof(
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

    pub fn decrypt(&self, ct: &TwistedElGamalCT, sk: Scalar) -> Result<u32, R1CSError> {
        // rG + mH = Y,  X = rxG
        // mH = Y - x^-1 * X
        let sk_inv = sk.invert(); // sk should not be zero
        let mH = RistrettoPoint::optional_multiscalar_mul(
            iter::once(Scalar::one()).chain(iter::once(-sk_inv)),
            iter::once(Some(ct.Y)).chain(iter::once(Some(ct.X))),
        )
        .unwrap();

        // range proof check
        self.verify_range_proof(&ct.RP, ct.comm)?;

        match bsgs(&mH, &self.H) {
            Some(i) => Ok(i),
            _ => Err(R1CSError::GadgetError {
                description: "Value out of 1-2^31".to_string(),
            }),
        }
    }
}

pub struct TwistedElGamalCT {
    pub X: RistrettoPoint, // pk^r, pk=g^x
    pub Y: RistrettoPoint, // g^m h^r
    pub RP: R1CSProof,
    pub comm: CompressedRistretto,
}

#[test]
fn test_twisted_elgamal() {
    let mut transript = Transcript::new(b"TwistedElGamalTest");

    let mut rng = transript
        .build_rng()
        .rekey_with_witness_bytes(b"x", b"witness")
        .finalize(&mut rand::thread_rng());
    let sk = Scalar::random(&mut rng);
    let mut te = TwistedElGamalPP::new(&mut rng);
    let pk = (sk * te.G).compress();
    let ct = te.encrypt(b"te", SignedInteger::from(10), &pk).unwrap();

    assert!(te.decrypt(&ct, sk).is_ok());
}
