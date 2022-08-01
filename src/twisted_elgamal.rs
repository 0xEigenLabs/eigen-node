// https://eprint.iacr.org/2019/319
#![allow(non_snake_case)]
use crate::errors::EigenCTError;
use crate::errors::Result;
use crate::hash::Hasher;
use crate::range_proof_bm::RangeProof;
use core::iter;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use merlin::Transcript;

use crate::signed_integer::SignedInteger;

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
}

impl TwistedElGamalPP {
    // setup
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> TwistedElGamalPP {
        let G = RistrettoPoint::random(rng);
        //let H = RistrettoPoint::hash_from_bytes::<Sha512>(G.compress().as_bytes());
        let H = Hasher::new().update(&G).to_point().unwrap();
        TwistedElGamalPP { G, H }
    }

    pub fn keygen<R: RngCore + CryptoRng>(&self, rng: &mut R) -> (Scalar, RistrettoPoint) {
        let sk = Scalar::random(rng);
        let pk = sk * self.G;
        (sk, pk)
    }

    pub fn encrypt(
        &mut self,
        label: &'static [u8],
        value: SignedInteger,
        pk: &CompressedRistretto,
    ) -> Result<TwistedElGamalCT> {
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

        // generate range proof
        let n = 32;
        let (rp, comm, blinding) =
            RangeProof::create(n, value.to_u64().unwrap(), &self.G, &self.H, &mut rng).unwrap();
        let C = rp.verify(n, &self.G, &self.H).unwrap();
        let C_hat = self.G * blinding + self.H * Scalar::from(value.to_u32().unwrap());
        assert_eq!(C.compress(), C_hat.compress());

        Ok(TwistedElGamalCT {
            X: cx,
            Y: cy,
            RP: rp,
        })
    }

    pub fn decrypt(&self, label: &'static [u8], ct: &TwistedElGamalCT, sk: Scalar) -> Result<u32> {
        let pk = sk * self.G;
        let mut transript = Transcript::new(b"TwistedElGamal");
        transript.domain_sep();
        transript.append_message(label, &pk.compress().to_bytes());

        // rG + mH = Y,  X = rxG
        // mH = Y - x^-1 * X
        let sk_inv = sk.invert(); // sk should not be zero
        let mH = RistrettoPoint::optional_multiscalar_mul(
            iter::once(Scalar::one()).chain(iter::once(-sk_inv)),
            iter::once(Some(ct.Y)).chain(iter::once(Some(ct.X))),
        )
        .unwrap();

        //range proof verification
        ct.RP.verify(32, &self.G, &self.H).ok_or_else(|| {
            EigenCTError::InvalidRangeProof("should be between 1-2^32".to_string())
        })?;

        match bsgs(&mH, &self.H) {
            Some(i) => Ok(i),
            _ => Err(EigenCTError::OutOfRangeError {
                expected: "Value out of 1-2^31".to_string(),
                found: format!("unknown"),
            }),
        }
    }
}

pub struct TwistedElGamalCT {
    pub X: RistrettoPoint, // pk^r, pk=g^x
    pub Y: RistrettoPoint, // g^m h^r
    pub RP: RangeProof,
}

#[test]
fn test_twisted_elgamal() {
    let mut transript = Transcript::new(b"TwistedElGamalTest");

    let mut rng = transript
        .build_rng()
        .rekey_with_witness_bytes(b"x", b"witness")
        .finalize(&mut rand::thread_rng());
    let mut te = TwistedElGamalPP::new(&mut rng);
    let (sk, pk) = te.keygen(&mut rng);
    let label = b"te";
    let ct = te
        .encrypt(label, SignedInteger::from(10u32), &pk.compress())
        .unwrap();

    assert!(te.decrypt(label, &ct, sk).is_ok());
}
