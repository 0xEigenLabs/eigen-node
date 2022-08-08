use crate::twisted_elgamal::{TwistedElGamalCT, TwistedElGamalPP};
use babyjubjub_rs::Signature;

use crate::account::Account;

use babyjubjub_rs::Point;
use num_bigint::BigInt;

pub struct Context {
    pp: TwistedElGamalPP,
    sk: BigInt,
    pk: Point,
}

impl Context {
    pub fn new() -> Context {
        let mut rng = rand_core::OsRng;
        let pp = TwistedElGamalPP::new(&mut rng);

        let (sk, pk) = pp.keygen(&mut rng);

        Context { pp, sk, pk }
    }
}

pub struct Transaction {
    sender: Account,
    to: Point,
    value: TwistedElGamalCT,
    signature: Signature,
}

impl Transaction {
    pub fn new(ctx: Context, sender: Account, value: u32, to: Point) -> Transaction {
        let signature = sender.sign(BigInt::from(value as i64)).unwrap();

        // balance check
        let C_S = ctx.pp.encrypt(value, &ctx.pk).unwrap();
        let C_R = ctx.pp.encrypt(value, &to).unwrap();

        Transaction {
            sender,
            to,
            value: C_S,
            signature,
        }
    }

    pub fn verify() -> bool {
        // signature check
        // proof check
        true
    }
}
