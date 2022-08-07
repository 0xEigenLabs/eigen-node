use babyjubjub_rs::{Point, PrivateKey, decompress_point, utils as bu};
use num_bigint::{RandBigInt, ToBigInt, BigInt, Sign};
use num_traits::One;

use ff::*;
use poseidon_rs::{Fr, Poseidon};
use rand_core::{CryptoRng, RngCore};

lazy_static! {
    pub static ref SUBORDER: BigInt = &BigInt::parse_bytes(
        b"21888242871839275222246405745257275088614511777268538073601725287587578984328",
        10,
    ).unwrap() >> 3;
}

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

pub fn point_random<R: RngCore + CryptoRng>(rng: &mut R) -> Point {
    let mut buf = [0u8; 32];
    rng.fill_bytes(&mut buf);
    let sk = PrivateKey::import(buf[..32].to_vec()).unwrap();
    sk.public()
}

pub fn point_to_bigint(p: &Point) -> BigInt {
	let compress_point = p.compress();
	BigInt::from_bytes_le(Sign::Plus, &compress_point[..])
}

/// compressed = false, equals hash_to_curve
pub fn bigint_to_point(n: &BigInt, compressed: bool) -> Point {
	let (_, bn_bytes_raw) = n.to_bytes_le();
	let mut bn_bytes: [u8; 32] = [0; 32];
	bn_bytes.copy_from_slice(&bn_bytes_raw);
    if compressed {
	    decompress_point(bn_bytes).unwrap()
    } else {
        let sk = PrivateKey::import(bn_bytes.to_vec()).unwrap();
        sk.public()
    }
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
    let b = random(&mut rand_core::OsRng);
    let f = bigint_to_fr(&b);
    let bb = fr_to_bigint(&f);
    assert_eq!(b, bb);
}

#[test]
fn test_point_convert() {
    let p = point_random(&mut rand_core::OsRng);
    let b = point_to_bigint(&p);
    let pp = bigint_to_point(&b, true);
    assert!(p.equals(pp));
}

#[test]
fn test_neginv() {
    let b = random(&mut rand_core::OsRng);
    let ni = neginv(&b);
    let bni = modulus(&(b * ni * BigInt::from(-1i32)));
    assert_eq!(bni, BigInt::one());
}

#[test]
fn test_field_module() {
    let p = point_random(&mut rand_core::OsRng);
    let a = random(&mut rand_core::OsRng);
    let a_inv = inv(&a);
    let pa = p.mul_scalar(&a_inv).mul_scalar(&a);
    assert!(pa.equals(p));
}
