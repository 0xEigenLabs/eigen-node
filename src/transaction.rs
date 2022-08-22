use crate::account::Account;
use crate::fr;
use crate::hash::Hasher;
use crate::twisted_elgamal::{TwistedElGamalCT, TwistedElGamalPP};
use babyjubjub_rs::Point;
use babyjubjub_rs::Signature;
use digest::Update;
use generic_array::typenum::U31;
use num_bigint::BigInt;
use num_bigint::ToBigInt;
use rand_chacha::ChaCha20Rng;

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
    signature: Signature,
    proof: Vec<u8>,
}

impl Transaction {
    pub fn new(ctx: Context, sender: Account, value: u32, to: Point) -> Transaction {
        // sign the message
        let msg = Hasher::new()
            .chain(sender.public_key().compress())
            .chain(to.compress())
            .chain(fr::bigint_to_point(&BigInt::from(value as u64), false).compress())
            .to_scalar()
            .unwrap();
        let signature = sender.sign(msg).unwrap();

        // L_equal := { C_S = (pk_1^r, g^r * h^v), C_R = (pk_2^r, g^r * h^v) }
        //  witness: (r, v)
        //  statement:  DL(pk_1, pk_1^r) & DL(pk_2, pk_2^r) & DL((r, v), g^r * h^v)
        let (r_s, C_S) = ctx.pp.encrypt(value, &ctx.pk).unwrap();
        let (r_r, C_R) = ctx.pp.encrypt(value, &to).unwrap();

        Transaction {
            sender,
            to,
            signature,
            proof: vec![],
        }
    }

    pub fn verify() -> bool {
        // signature check
        // proof check
        true
    }
}
