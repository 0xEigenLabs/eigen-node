#[allow(non_snake_case)]
use super::*;

use babyjubjub_rs::{utils, Point, PrivateKey};
use num_bigint::{BigInt, RandBigInt, Sign, ToBigInt};

pub struct Account {
    pub(crate) sk: PrivateKey,
}

impl Account {
    pub fn new<R: RandBigInt>(rng: &mut R) -> Account {
        let sk_raw = rng.gen_biguint(1024).to_bigint().unwrap();
        let (_, sk_raw_bytes) = sk_raw.to_bytes_be();
        Account{sk: PrivateKey::import(sk_raw_bytes[..32].to_vec()).unwrap()}
    }

    pub fn public_key(&self) -> Point {
        self.sk.public()
    }
}
