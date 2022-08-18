use crate::twisted_elgamal::{TwistedElGamalCT, TwistedElGamalPP};
use babyjubjub_rs::Signature;

use crate::account::Account;
use crate::zkp::babyjubjub::*;
use crate::Sigma;
use babyjubjub_rs::Point;
use generic_array::typenum::U31;
use num_bigint::BigInt;

pub struct Context {
    pp: TwistedElGamalPP,
    sk: BigInt,
    pk: Point,
}

impl Context {
    pub fn new() -> Context {
        let mut rng = rand::thread_rng();
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

        let C_S = ctx.pp.encrypt(value, &ctx.pk).unwrap();
        let C_R = ctx.pp.encrypt(value, &to).unwrap();
        //type AndDL = AndDL<DLG<U31>, DLG<U31>>;

        // L_equal := { C_L = (pk_1^r, g^r * h^v), C_R = (pk_2^r, g^r * h^v) }
        //      imply:

        // L_range := { C_L = Dec(sk_1, C_old - C_L) \in V}

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
