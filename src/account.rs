#[allow(non_snake_case)]
use super::*;

use babyjubjub_rs::{utils, Point, PrivateKey, Signature, verify};
use num_bigint::{BigInt, RandBigInt, Sign, ToBigInt};
use crate::errors::{Result, EigenCTError};
use crate::twisted_elgamal::TwistedElGamalCT;

pub struct Account {
    pub(crate) sk: PrivateKey,
    //balance: TwistedElGamalCT,
}

impl Account {
    pub fn new<R: RandBigInt>(rng: &mut R, balance: TwistedElGamalCT) -> Account {
        let sk_raw = rng.gen_biguint(1024).to_bigint().unwrap();
        let (_, sk_raw_bytes) = sk_raw.to_bytes_be();
        Account {
            sk: PrivateKey::import(sk_raw_bytes[..32].to_vec()).unwrap(),
        }
    }

    pub fn public_key(&self) -> Point {
        self.sk.public()
    }

    pub fn sign(&self, msg: BigInt) -> Result<Signature> {
        self.sk.sign(msg).map_err(|e| EigenCTError::SignError(e))
    }

    pub fn verify(&self, sig: Signature, msg: BigInt) -> bool {
        verify(self.public_key(), sig, msg)
    }

    /*
    pub fn balance(&self) -> TwistedElGamalCT {
        self.balance
    }
    */
}
