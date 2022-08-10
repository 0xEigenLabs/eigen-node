//! This module provides an implementation of the Jubjub scalar field $\mathbb{F}_r$
//! where `r = 2736030358979909402780800718157159386076813972158567259200215660948447373041`
use babyjubjub_rs::{decompress_point, utils as bu, Point, PrivateKey, B8, SUBORDER};
use core::cmp::min;
use num_bigint::{BigInt, RandBigInt, Sign, ToBigInt};
use num_traits::One;

use ff::*;
use poseidon_rs::{Fr, Poseidon};
use rand_core::{CryptoRng, RngCore};

pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> BigInt {
    let mut buf = [0u8; 32];
    rng.fill_bytes(&mut buf);
    modulus(&BigInt::from_bytes_le(Sign::Plus, &buf[..]))
}

/// b % SUBORDER, SUBORDER is sub field modulus,
pub fn modulus(b: &BigInt) -> BigInt {
    bu::modulus(b, &SUBORDER)
}

/// -1/b % SUBORDER
pub fn neginv(b: &BigInt) -> BigInt {
    modulus(&-inv(b))
}

pub fn inv(b: &BigInt) -> BigInt {
    modulus(&bu::modinv(b, &SUBORDER).unwrap())
}

pub fn neg(b: &BigInt) -> BigInt {
    modulus(&-b)
}

pub fn point_to_bigint(p: &Point) -> BigInt {
    let compress_point = p.compress();
    BigInt::from_bytes_le(Sign::Plus, &compress_point[..])
}

/// compressed = false, equals hash_to_curve
pub fn bigint_to_point(n: &BigInt, compressed: bool) -> Point {
    let (_, bn_bytes_raw) = n.to_bytes_le();
    let mut bn_bytes: [u8; 32] = [0; 32];
    let len = min(bn_bytes.len(), bn_bytes_raw.len());
    bn_bytes[..len].copy_from_slice(&bn_bytes_raw[..len]);
    if compressed {
        decompress_point(bn_bytes).unwrap()
    } else {
        let sk = PrivateKey::import(bn_bytes.to_vec()).unwrap();
        sk.public()
    }
}

pub fn G() -> Point {
    B8.clone()
}

pub fn bigint_to_fr(n: &BigInt) -> Fr {
    Fr::from_str(&n.to_string()).unwrap()
}

pub fn fr_to_bigint(r: &Fr) -> BigInt {
    BigInt::parse_bytes(to_hex(r).as_bytes(), 16).unwrap()
}

#[test]
fn test_fr_convert() {
    use num_traits::One;
    let b = random(&mut rand::thread_rng());
    let f = bigint_to_fr(&b);
    let bb = fr_to_bigint(&f);
    assert_eq!(b, bb);
}

#[test]
fn test_point_convert() {
    let p = Point::random(&mut rand::thread_rng());
    let b = point_to_bigint(&p);
    let pp = bigint_to_point(&b, true);
    assert!(p.equals(&pp));
}

#[test]
fn test_neginv() {
    let b = random(&mut rand::thread_rng());
    let ni = neginv(&b);
    let bni = modulus(&(b * ni * BigInt::from(-1i32)));
    assert_eq!(bni, BigInt::one());
}

#[test]
fn test_field_module() {
    let p = Point::random(&mut rand::thread_rng());
    let a = random(&mut rand::thread_rng());
    let a_inv = inv(&a);
    let pa = p.mul_scalar(&a_inv).mul_scalar(&a);
    assert!(pa.equals(&p));
}
