// https://eprint.iacr.org/2019/319
#![allow(non_snake_case)]
use crate::errors::EigenCTError;
use crate::errors::Result;
use crate::hash::Hasher;
use core::iter;
use digest::Update;
use num_bigint::RandBigInt;
use rand_core::{CryptoRng, RngCore};

use super::baby_step_giant_step::bsgs;
use num_bigint::BigInt;
use num_traits::{One, Zero};

use crate::range_proof_bm::RangeProof;

use crate::fr;

use babyjubjub_rs::{utils as bu, Point};

pub const MAX_BITS: usize = 20;

pub struct TwistedElGamalPP {
    pub G: Point,
    pub H: Point,
}

impl TwistedElGamalPP {
    // setup
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> TwistedElGamalPP {
        let G = fr::point_random(rng);
        let H = Hasher::new().chain(G.compress()).to_point().unwrap();
        TwistedElGamalPP { G, H }
    }

    pub fn keygen<R: RngCore + CryptoRng>(&self, rng: &mut R) -> (BigInt, Point) {
        let sk = fr::random(rng);
        let pk = self.G.mul_scalar(&sk);
        (sk, pk)
    }

    pub fn encrypt(&self, value: u32, pk: &Point) -> Result<TwistedElGamalCT> {
        let mut rng = rand_core::OsRng;
        let r = fr::random(&mut rng);

        let cx = pk.mul_scalar(&r);

        let v: BigInt = BigInt::from(value);

        let rG = self.G.mul_scalar(&r);
        let vH = self.H.mul_scalar(&v);

        let cy = rG.projective().add(&vH.projective()).affine();

        // generate range proof
        let n = MAX_BITS;
        let (rp, comm, blinding) =
            RangeProof::create_vartime(n, value.into(), &self.G, &self.H, &mut rng).unwrap();
        let C = rp.verify(n, &self.G, &self.H).unwrap();

        let C_hat = self
            .G
            .mul_scalar(&blinding)
            .projective()
            .add(&self.H.mul_scalar(&BigInt::from(value)).projective())
            .affine();

        assert_eq!(C.compress(), C_hat.compress());

        Ok(TwistedElGamalCT {
            X: cx,
            Y: cy,
            RP: rp,
        })
    }

    pub fn decrypt(&self, ct: &TwistedElGamalCT, sk: &BigInt) -> Result<u32> {
        let pk = self.G.mul_scalar(sk);
        // rG + mH = Y,  X = rxG
        // mH = Y - x^-1 * X
        let sk_neg_inv = fr::neginv(sk);
        let mH =
            ct.Y.projective()
                .add(&ct.X.mul_scalar(&sk_neg_inv).projective())
                .affine();

        //range proof verification
        ct.RP.verify(MAX_BITS, &self.G, &self.H).ok_or_else(|| {
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
    pub X: Point, // pk^r, pk=g^x
    pub Y: Point, // g^m h^r
    pub RP: RangeProof,
}

#[test]
fn test_twisted_elgamal() {
    let mut te = TwistedElGamalPP::new(&mut rand_core::OsRng);
    let (sk, pk) = te.keygen(&mut rand_core::OsRng);
    let value = 10u32;
    let ct = te.encrypt(value, &pk).unwrap();

    assert!(te.decrypt(&ct, &sk).unwrap() == value);
}
