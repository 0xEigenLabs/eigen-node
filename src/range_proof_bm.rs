// https://blockstream.com/bitcoin17-final41.pdf
// copy and modify from https://github.com/dalek-cryptography/dalek-rangeproofs/blob/develop/src/lib.rs
// It replaces the hash function by ZK friendly hash, Poseidon Hash
#![allow(non_snake_case)]
use crate::hash::Hasher;
use crate::utils::*;
use core::iter;
use num_bigint::RandBigInt;
use num_bigint::ToBigInt;
use rand_core::{CryptoRng, RngCore};
use subtle::ConditionallySelectable;

use ff::*;
use poseidon_rs::Fr;

use babyjubjub_rs::{new_key, utils as bu, Point, Q};
use num_bigint::BigInt;
use num_traits::{One, Zero};

#[inline(always)]
pub fn k_2_fold_scalar_mult(s: &[&BigInt], p: &[&Point]) -> Point {
    assert_eq!(s.len(), 2);
    let mut lh = p[0].mul_scalar(&modulus(s[0]));
    let mut rh = p[1].mul_scalar(&modulus(s[1]));
    let mult_sum = lh.projective().add(&rh.projective());
    mult_sum.affine()
}

/// ab+c (mod l)
#[inline(always)]
fn multiply_add(a: &BigInt, b: &BigInt, c: &BigInt) -> BigInt {
    modulus(&((a * b) + c))
}

#[inline(always)]
pub fn byte_is_nonzero(b: u8) -> u8 {
    let mut x = b;
    x |= x >> 4;
    x |= x >> 2;
    x |= x >> 1;
    x & 1
}

#[inline(always)]
pub fn bytes_equal_ct(a: u8, b: u8) -> u8 {
    let mut x: u8;
    x = !(a ^ b);
    x &= x >> 4;
    x &= x >> 2;
    x &= x >> 1;
    x
}

/// A Back-Maxwell rangeproof, which proves in zero knowledge that a
/// number is in a range `[0,m^n]`.  We hardcode `m = 3` as this is
/// the most efficient.
///
/// The size of the proof and the cost of verification are
/// proportional to `n`.
#[derive(Debug)]
pub struct RangeProof {
    e_0: BigInt,
    C: Vec<Point>,
    s_1: Vec<BigInt>,
    s_2: Vec<BigInt>,
}

/// The maximum allowed bound for the rangeproof.  Currently this is
/// set to 41, because we only implement conversion to base 3 digits
/// for `u64`s, and 3^41 is the least power of 3 greater than `2^64`.
pub const RANGEPROOF_MAX_N: usize = 41;

impl RangeProof {
    /// Verify the rangeproof, returning a Pedersen commitment to the
    /// in-range value if successful.
    pub fn verify(&self, n: usize, G: &Point, H: &Point) -> Option<Point> {
        // Calling verify with n out of bounds is a programming error.
        if n > RANGEPROOF_MAX_N {
            panic!(
                "Error: called create_vartime with too large bound 3^n, n = {}",
                n
            );
        }

        // If the lengths of any of the arrays don't match, the proof
        // is malformed.
        if n != self.C.len() {
            return None;
        } else if n != self.s_1.len() {
            return None;
        } else if n != self.s_2.len() {
            return None;
        }

        //let mut e_0_hash = Sha512::default();
        let mut e_0_hash = Hasher::new();
        let mut C = Point {
            x: Fr::zero(),
            y: Fr::one(),
        };
        // mi_H = m^i * H = 3^i * H in the loop below
        let mut mi_H = H.clone();

        for i in 0..n {
            let mi2_H = mi_H.projective().add(&mi_H.projective()).affine();

            let Ci_minus_miH = self.C[i]
                .projective()
                .add(&mi_H.mul_scalar(&neg(&BigInt::one())).projective())
                .affine();
            let P = k_2_fold_scalar_mult(&[&self.s_1[i], &neg(&self.e_0)], &[G, &Ci_minus_miH]);
            //let ei_1 = Scalar::hash_from_bytes::<Sha512>(P.compress().as_bytes());
            let ei_1 = Hasher::new().update(&P).to_scalar().unwrap();

            let Ci_minus_2miH = self.C[i]
                .projective()
                .add(&mi2_H.mul_scalar(&neg(&BigInt::one())).projective())
                .affine();
            let P = k_2_fold_scalar_mult(&[&self.s_2[i], &neg(&ei_1)], &[G, &Ci_minus_2miH]);
            //let ei_2 = Scalar::hash_from_bytes::<Sha512>(P.compress().as_bytes());
            let ei_2 = Hasher::new().update(&P).to_scalar().unwrap();

            let Ri = self.C[i].mul_scalar(&ei_2);
            e_0_hash.update(&Ri);
            C = C.projective().add(&self.C[i].projective()).affine();

            // Set mi_H <-- 3*m_iH, so that mi_H is always 3^i * H in the loop
            mi_H = mi_H.projective().add(&mi2_H.projective()).affine();
        }

        let e_0_hat = e_0_hash.to_scalar().unwrap();

        if e_0_hat == self.e_0 {
            return Some(C);
        } else {
            return None;
        }
    }

    /// Construct a rangeproof for `value`, in variable time.
    ///
    /// # Inputs
    ///
    /// * `n`, so that the range is `[0,3^n]` with `n < RANGEPROOF_MAX_N`;
    /// * The `value` to prove within range `[0,3^n]`;
    /// * `rng`, an implementation of `rand::Rng`, which should be
    /// cryptographically secure.
    ///
    /// # Returns
    ///
    /// If `value` is not in the range `[0,3^n]`, return None.
    ///
    /// Otherwise, returns `Some((proof, commitment, blinding))`, where:
    /// `proof` is the rangeproof, and `commitment = blinding*G + value*H`.
    ///
    /// Only the `RangeProof` should be sent to the verifier.  The
    /// commitment and blinding are for the use of the prover.
    pub fn create_vartime<T: RngCore + CryptoRng>(
        n: usize,
        value: u64,
        G: &Point,
        H: &Point,
        mut rng: &mut T,
    ) -> Option<(RangeProof, Point, BigInt)> {
        // Calling verify with n out of bounds is a programming error.
        if n > RANGEPROOF_MAX_N {
            panic!(
                "Error: called create_vartime with too large bound 3^n, n = {}",
                n
            );
        }

        // Check that value is in range: all digits above n should be 0
        let v = base3_digits(value);
        for i in n..41 {
            if v[i] != 0 {
                return None;
            }
        }

        let identity = Point {
            x: Fr::zero(),
            y: Fr::one(),
        };
        let mut R = vec![identity.clone(); n];
        let mut C = vec![identity.clone(); n];
        let mut k = vec![BigInt::zero(); n];
        let mut r = vec![BigInt::zero(); n];
        let mut s_1 = vec![BigInt::zero(); n];
        let mut s_2 = vec![BigInt::zero(); n];
        let mut e_1 = vec![BigInt::zero(); n];
        let mut e_2 = vec![BigInt::zero(); n];

        let mut mi_H = H.clone();
        for i in 0..n {
            let mi2_H = mi_H.projective().add(&mi_H.projective()).affine();
            k[i] = random(&mut rng);

            if v[i] == 0 {
                R[i] = G.mul_scalar(&k[i]);
            } else if v[i] == 1 {
                // Commitment to i-th digit is r^i G + 1 * m^i H
                r[i] = random(&mut rng);
                C[i] = (G.mul_scalar(&r[i]))
                    .projective()
                    .add(&mi_H.projective())
                    .affine();
                // Begin at index 1 in the ring, choosing random e_1
                let P = G.mul_scalar(&k[i]);
                //e_1[i] = Scalar::hash_from_bytes::<Sha512>(P.compress().as_bytes());
                e_1[i] = Hasher::new().update(&P).to_scalar().unwrap();
                // Choose random scalar for s_2
                s_2[i] = random(&mut rng);
                // Compute e_2 = Hash(s_2^i G - e_1^i (C^i - 2m^i H) )
                let Ci_minus_mi2H = C[i]
                    .projective()
                    .add(&mi2_H.mul_scalar(&neg(&BigInt::one())).projective())
                    .affine();
                let P = k_2_fold_scalar_mult(&[&s_2[i], &neg(&e_1[i])], &[G, &Ci_minus_mi2H]);
                //e_2[i] = Scalar::hash_from_bytes::<Sha512>(P.compress().as_bytes());
                e_2[i] = Hasher::new().update(&P).to_scalar().unwrap();

                R[i] = C[i].mul_scalar(&e_2[i]);
            } else if v[i] == 2 {
                // Commitment to i-th digit is r^i G + 2 * m^i H
                r[i] = random(&mut rng);
                C[i] = (G.mul_scalar(&r[i]))
                    .projective()
                    .add(&mi2_H.projective())
                    .affine();

                // Begin at index 2 in the ring, choosing random e_2
                let P = G.mul_scalar(&k[i]);
                //e_2[i] = Scalar::hash_from_bytes::<Sha512>(P.compress().as_bytes());
                e_2[i] = Hasher::new().update(&P).to_scalar().unwrap();

                R[i] = C[i].mul_scalar(&e_2[i]);
            } else {
                panic!("Invalid digit {}", v[i]);
            }

            // Set mi_H <- 3 * mi_H so that mi_H = m^i H in the loop
            mi_H = mi2_H.projective().add(&mi_H.projective()).affine();
        }

        // Compute e_0 = Hash( R^0 || ... || R^{n-1} )
        let mut e_0_hash = Hasher::new();
        for i in 0..n {
            e_0_hash.update(&R[i]);
        }
        let e_0 = e_0_hash.to_scalar().unwrap();

        let mut mi_H = H.clone();
        for i in 0..n {
            let mi2_H = mi_H.projective().add(&mi_H.projective()).affine();
            if v[i] == 0 {
                let k_1 = random(&mut rng);
                // P = k_1 * G + e_0 * mi_H
                let P = k_2_fold_scalar_mult(&[&k_1, &e_0], &[G, &mi_H]);
                //e_1[i] = Scalar::hash_from_bytes::<Sha512>(P.compress().as_bytes());
                e_1[i] = Hasher::new().update(&P).to_scalar().unwrap();

                let k_2 = random(&mut rng);
                let P = k_2_fold_scalar_mult(&[&k_2, &e_1[i]], &[G, &mi2_H]);
                //e_2[i] = Scalar::hash_from_bytes::<Sha512>(P.compress().as_bytes());
                e_2[i] = Hasher::new().update(&P).to_scalar().unwrap();

                let e_2_inv = inv(&e_2[i]);
                r[i] = modulus(&(&e_2_inv * &k[i]));
                C[i] = G.mul_scalar(&r[i]);

                s_1[i] = modulus(&(k_1 + &(&e_0 * &(&k[i] * &e_2_inv))));
                s_2[i] = modulus(&(k_2 + &(&e_1[i] * &(&k[i] * &e_2_inv))));
            } else if v[i] == 1 {
                s_1[i] = multiply_add(&e_0, &r[i], &k[i]);
            } else if v[i] == 2 {
                s_1[i] = random(&mut rng);
                // Compute e_1^i = Hash(s_1^i G - e_0^i (C^i - 1 m^i H) )
                let Ci_minus_miH = C[i]
                    .projective()
                    .add(&mi_H.mul_scalar(&neg(&BigInt::one())).projective())
                    .affine();

                let P = k_2_fold_scalar_mult(&[&s_1[i], &neg(&e_0)], &[G, &Ci_minus_miH]);

                //e_1[i] = Scalar::hash_from_bytes::<Sha512>(P.compress().as_bytes());
                e_1[i] = Hasher::new().update(&P).to_scalar().unwrap();
                s_2[i] = multiply_add(&e_1[i], &r[i], &k[i]);
            }
            // Set mi_H <-- 3*m_iH, so that mi_H is always 3^i * H in the loop
            mi_H = mi2_H.projective().add(&mi_H.projective()).affine();
        }

        let mut blinding = BigInt::zero();
        let mut commitment = Point {
            x: Fr::zero(),
            y: Fr::one(),
        };
        for i in 0..n {
            blinding += r[i].clone();
            // XXX implement AddAssign for ExtendedPoint
            commitment = commitment.projective().add(&C[i].projective()).affine();
        }

        Some((
            RangeProof {
                e_0: e_0,
                C: C,
                s_1: s_1,
                s_2: s_2,
            },
            commitment,
            blinding,
        ))
    }

    /*
        /// Construct a rangeproof for `value`, in constant time.
        ///
        /// This function is roughly three times slower (since `m = 3`) than the
        /// variable time version, for all values of `n`.
        ///
        /// # Inputs
        ///
        /// * `n`, so that the range is `[0,3^n]` with `n < RANGEPROOF_MAX_N`;
        /// * The `value` to prove within range `[0,3^n]`;
        /// * `rng`, an implementation of `rand::Rng`, which should be
        /// cryptographically secure.
        ///
        /// # Returns
        ///
        /// If `value` is not in the range `[0,3^n]`, return None.
        ///
        /// Note that this function is designed to execute in constant
        /// time for all *valid* inputs.  Passing an out-of-range `value`
        /// will cause it to return `None` early.
        ///
        /// Otherwise, returns `Some((proof, commitment, blinding))`, where:
        /// `proof` is the rangeproof, and `commitment = blinding*G + value*H`.
        ///
        /// Only the `RangeProof` should be sent to the verifier.  The
        /// commitment and blinding are for the use of the prover.
        ///
        /// # Note
        ///
        /// Even when passing a deterministic rng generated with identical seeds,
        /// e.g. two instances of `rand::chacha::ChaChaRng::new_unseeded()`, and
        /// seeking to prove the same `value`, one cannot expect the `RangeProofs`
        /// generated with `RangeProof::create_vartime()` and `RangeProof::create()`
        /// to be identical.  The values in the eventual proofs will differ, since
        /// this constant time version makes additional calls to the `rng` which
        /// are thrown away in some conditions.
        pub fn create<T: RandBigInt>(
            n: usize,
            value: u64,
            G: &Point,
            H: &Point,
            mut rng: &mut T,
        ) -> Option<(RangeProof, Point, BigInt)> {
            // Calling verify with n out of bounds is a programming error.
            if n > RANGEPROOF_MAX_N {
                panic!(
                    "Error: called create_vartime with too large bound 3^n, n = {}",
                    n
                );
            }

            // Check that value is in range: all digits above N should be 0
            let v = base3_digits(value);
            for i in n..41 {
                if v[i] != 0 {
                    return None;
                }
            }

            let identity = Point{x: Fr::zero(), y: Fr::one()};
            let mut R = vec![identity.clone(); n];
            let mut C = vec![identity.clone(); n];
            let mut k = vec![BigInt::zero(); n];
            let mut r = vec![BigInt::zero(); n];
            let mut s_1 = vec![BigInt::zero(); n];
            let mut s_2 = vec![BigInt::zero(); n];
            let mut e_1 = vec![BigInt::zero(); n];
            let mut e_2 = vec![BigInt::zero(); n];

            let mut mi_H = *H;
            let mut P: Point;

            for i in 0..n {
                debug_assert!(v[i] == 0 || v[i] == 1 || v[i] == 2);

                let mi2_H = mi_H.projective().add(mi_H.projective()).affine();

                k[i] = crate::utils::random(&mut rng);

                //let choise: subtle::Choice = byte_is_nonzero(v[i]).into();

                // Commitment to i-th digit is r^i G + (v^1 * m^i H)
                let maybe_ri: BigInt = crate::utils::random(&mut rng);
                r[i].conditional_assign(&maybe_ri, byte_is_nonzero(v[i]).into());

                let mut which_mi_H: Point = mi_H; // is a copy
                which_mi_H.conditional_assign(&mi2_H, bytes_equal_ct(v[i], 2u8).into());

                let maybe_Ci: Point = (G * r[i]) + which_mi_H;
                C[i].conditional_assign(&maybe_Ci, byte_is_nonzero(v[i]).into());

                P = &k[i] * G;

                // Begin at index 1 in the ring, choosing random e_{v^i}
                //let mut maybe_ei = Scalar::hash_from_bytes::<Sha512>(P.compress().as_bytes());
                let mut maybe_ei = Hasher::new().update(&P).to_scalar().unwrap();

                e_1[i].conditional_assign(&maybe_ei, bytes_equal_ct(v[i], 1u8).into());
                e_2[i].conditional_assign(&maybe_ei, bytes_equal_ct(v[i], 2u8).into());

                // Choose random scalar for s_2
                let maybe_s2: Scalar = crate::utils::random(&mut rng);
                s_2[i].conditional_assign(&maybe_s2, bytes_equal_ct(v[i], 1u8).into());

                // Compute e_2 = Hash(s_2^i G - e_1^i (C^i - 2m^i H) )
                P = (s_2[i] * G) - (e_1[i] * (C[i] - mi2_H));
                //maybe_ei = Scalar::hash_from_bytes::<Sha512>(P.compress().as_bytes());
                maybe_ei = Hasher::new().update(&P).to_scalar().unwrap();
                e_2[i].conditional_assign(&maybe_ei, bytes_equal_ct(v[i], 1u8).into());

                // Compute R^i = k^i G            iff  v^i == 0, otherwise
                //         R^i = e_2^i * C^i
                R[i] = &k[i] * G;

                let maybe_Ri: Point = e_2[i] * C[i];
                R[i].conditional_assign(&maybe_Ri, byte_is_nonzero(v[i]).into());

                // Multiply mi_H by m (a.k.a. m == 3)
                mi_H = mi2_H + mi_H;
            }

            // Compute e_0 = Hash( R^0 || ... || R^{n-1} )

            let mut e_0_hash = Hasher::new();
            for i in 0..n {
                e_0_hash.update(&R[i]);
            }
            let e_0 = e_0_hash.to_scalar().unwrap();

            let mut mi_H = *H;

            for i in 0..n {
                debug_assert!(v[i] == 0 || v[i] == 1 || v[i] == 2);

                let mi2_H = &mi_H + &mi_H;

                let mut k_1 = BigInt::zero();
                let maybe_k1: Scalar = crate::utils::random(&mut rng);
                k_1.conditional_assign(&maybe_k1, bytes_equal_ct(v[i], 0u8).into());

                P = (k_1 * G) + (e_0 * mi_H);
                //let maybe_e_1 = Scalar::hash_from_bytes::<Sha512>(P.compress().as_bytes());
                let maybe_e_1 = Hasher::new().update(&P).to_scalar().unwrap();
                e_1[i].conditional_assign(&maybe_e_1, bytes_equal_ct(v[i], 0u8).into());

                let mut k_2 = BigInt::zero();
                let maybe_k2: Scalar = crate::utils::random(&mut rng);
                k_2.conditional_assign(&maybe_k2, bytes_equal_ct(v[i], 0u8).into());

                P = &(&k_2 * G) + &(&e_1[i] * &mi2_H);
                //let maybe_e_2 = Scalar::hash_from_bytes::<Sha512>(P.compress().as_bytes()); // XXX API
                let maybe_e_2 = Hasher::new().update(&P).to_scalar().unwrap();
                e_2[i].conditional_assign(&maybe_e_2, bytes_equal_ct(v[i], 0u8).into());

                let e_2_inv = e_2[i].invert(); // XXX only used in v[i]==0, check what the optimiser is doing
                let maybe_r_i = e_2_inv * k[i];
                r[i].conditional_assign(&maybe_r_i, bytes_equal_ct(v[i], 0u8).into());

                let maybe_C_i = G * r[i];
                C[i].conditional_assign(&maybe_C_i, bytes_equal_ct(v[i], 0u8).into());

                let ki_e_2_inv = k[i] * e_2_inv;
                let mut maybe_s_1 = k_1 + (e_0 * ki_e_2_inv);
                s_1[i].conditional_assign(&maybe_s_1, bytes_equal_ct(v[i], 0u8).into());
                maybe_s_1 = multiply_add(&e_0, &r[i], &k[i]);
                s_1[i].conditional_assign(&maybe_s_1, bytes_equal_ct(v[i], 1u8).into());
                maybe_s_1 = rng.gen_bigint(1024).to_bigint().unwrap();
                s_1[i].conditional_assign(&maybe_s_1, bytes_equal_ct(v[i], 2u8).into());

                // Compute e_1^i = Hash(s_1^i G - e_0^i (C^i - 1 m^i H) )
                let Ci_minus_miH = C[i] - mi_H; // XXX only used in v[i]==2, check optimiser

                P = &(&s_1[i] * G) - &(&e_0 * &Ci_minus_miH);
                //let maybe_e_1 = Scalar::hash_from_bytes::<Sha512>(P.compress().as_bytes());
                let maybe_e_1 = Hasher::new().update(&P).to_scalar().unwrap();
                e_1[i].conditional_assign(&maybe_e_1, bytes_equal_ct(v[i], 2u8).into());

                let mut maybe_s_2 = k_2 + (e_1[i] * ki_e_2_inv);
                s_2[i].conditional_assign(&maybe_s_2, bytes_equal_ct(v[i], 0u8).into());
                maybe_s_2 = multiply_add(&e_1[i], &r[i], &k[i]);
                s_2[i].conditional_assign(&maybe_s_2, bytes_equal_ct(v[i], 2u8).into());

                // Set mi_H <-- 3*m_iH, so that mi_H is always 3^i * H in the loop
                mi_H = mi_H + mi2_H;
            }

            let mut blinding = BigInt::zero();
            let mut commitment = Point{x: Fr::zero(), y: Fr::one()};
            for i in 0..n {
                blinding += &r[i];
                // XXX implement AddAssign for ExtendedPoint
                commitment = &commitment + &C[i];
            }

            Some((
                RangeProof {
                    e_0: e_0,
                    C: C,
                    s_1: s_1,
                    s_2: s_2,
                },
                commitment,
                blinding,
            ))
        }
    */
}

fn base3_digits(mut x: u64) -> [u8; 41] {
    let mut digits = [0u8; 41];
    for i in 0..41 {
        let rem = x % 3;
        digits[i] = rem as u8;
        x = x / 3;
    }
    digits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base3_digits_vs_sage() {
        let values: [u64; 10] = [
            10352669767914021650,
            7804842618637096123,
            7334633556203117754,
            8160423201521470302,
            17232767106382697250,
            8845500362072010910,
            9696550650556789001,
            769845413554321661,
            3398590720602317514,
            14390516357262902374,
        ];
        let digits_sage: [[u8; 41]; 10] = [
            [
                2, 2, 0, 2, 1, 2, 2, 2, 1, 1, 2, 2, 1, 1, 1, 2, 1, 2, 0, 1, 0, 2, 2, 1, 0, 1, 2, 0,
                2, 0, 2, 2, 0, 2, 2, 2, 2, 1, 1, 2, 0,
            ],
            [
                1, 1, 2, 2, 1, 0, 1, 2, 1, 0, 0, 1, 0, 2, 2, 1, 1, 1, 2, 0, 1, 0, 0, 1, 1, 0, 2, 1,
                2, 1, 2, 2, 2, 2, 2, 2, 0, 2, 2, 1, 0,
            ],
            [
                0, 1, 1, 0, 2, 2, 1, 2, 0, 0, 0, 2, 0, 2, 1, 1, 0, 2, 1, 0, 0, 0, 2, 0, 0, 1, 2, 1,
                1, 2, 1, 0, 1, 2, 1, 2, 0, 1, 2, 1, 0,
            ],
            [
                0, 2, 0, 1, 2, 2, 0, 0, 2, 2, 2, 2, 0, 2, 2, 0, 1, 1, 1, 1, 0, 1, 0, 2, 0, 2, 1, 2,
                2, 1, 1, 2, 2, 0, 0, 1, 0, 0, 0, 2, 0,
            ],
            [
                0, 1, 2, 1, 2, 2, 0, 2, 0, 0, 2, 2, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 2, 1, 2, 2, 2,
                0, 1, 1, 2, 2, 0, 1, 2, 0, 2, 0, 1, 1,
            ],
            [
                1, 2, 0, 2, 2, 0, 2, 1, 0, 1, 2, 1, 2, 0, 0, 0, 0, 2, 2, 0, 0, 2, 2, 1, 1, 0, 2, 0,
                0, 0, 2, 1, 0, 1, 2, 2, 1, 1, 0, 2, 0,
            ],
            [
                2, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 2, 0, 0, 1, 2, 2, 0, 0, 2, 2, 1, 0, 1, 0, 2,
                1, 1, 1, 2, 0, 1, 2, 1, 1, 0, 1, 2, 0,
            ],
            [
                2, 2, 2, 1, 2, 2, 1, 2, 0, 2, 1, 0, 2, 1, 1, 2, 2, 2, 2, 0, 2, 1, 0, 1, 2, 0, 1, 2,
                0, 0, 1, 1, 1, 0, 1, 0, 2, 1, 0, 0, 0,
            ],
            [
                0, 1, 1, 2, 0, 1, 1, 1, 2, 1, 0, 0, 2, 2, 2, 0, 0, 1, 1, 1, 2, 2, 0, 0, 0, 2, 2, 1,
                0, 2, 0, 0, 1, 2, 2, 1, 1, 1, 2, 0, 0,
            ],
            [
                1, 2, 0, 0, 1, 1, 0, 1, 2, 1, 0, 1, 0, 1, 2, 2, 0, 0, 2, 1, 0, 1, 2, 2, 1, 2, 2, 0,
                1, 2, 2, 2, 1, 2, 1, 2, 2, 1, 1, 0, 1,
            ],
        ];

        for i in 0..10 {
            let digits = base3_digits(values[i]);
            for j in 0..41 {
                assert_eq!(digits[j], digits_sage[i][j]);
            }
        }
    }

    #[test]
    fn prove_and_verify_vartime() {
        let mut rng = rand_core::OsRng;
        let G = point_random(&mut rng);
        //let H = RistrettoPoint::hash_from_bytes::<Sha512>(G.compress().as_bytes());
        let H = Hasher::new().update(&G).to_point().unwrap();

        let n = 16;
        let value = 13449261;
        let (proof, commitment, blinding) =
            RangeProof::create_vartime(n, value, &G, &H, &mut rng).unwrap();

        let C_option = proof.verify(n, &G, &H);
        assert!(C_option.is_some());

        assert!(proof.verify(2, &G, &H).is_none());

        let C = C_option.unwrap();
        let C_hat = G
            .mul_scalar(&blinding)
            .projective()
            .add(&H.mul_scalar(&BigInt::from(value)).projective())
            .affine();

        assert_eq!(C.compress(), C_hat.compress());
        assert_eq!(commitment.compress(), C_hat.compress());
    }

    #[test]
    fn prove_and_verify_ct() {
        /*
        let rng = rand::thread_rng();
        let G = &point_random(&mut rng);
        //let H = RistrettoPoint::hash_from_bytes::<Sha512>(G.compress().as_bytes());
        let H = Hasher::new().update(&G).to_point().unwrap();

        let n = 16;
        let value = 13449261;
        let (proof, commitment, blinding) = RangeProof::create(n, value, &G, &H, &mut rng).unwrap();

        let C_option = proof.verify(n, &G, &H);
        assert!(C_option.is_some());

        assert!(proof.verify(2, &G, &H).is_none());

        let C = C_option.unwrap();
        let C_hat = &(G * &blinding) + &(&H * &BigInt::from(value));

        assert_eq!(C.compress(), C_hat.compress());
        assert_eq!(commitment.compress(), C_hat.compress());
        */
    }
}

#[allow(soft_unstable)]
#[cfg(all(test, feature = "bench"))]
mod bench {
    use super::*;
    use test::Bencher;

    #[bench]
    fn verify(b: &mut Bencher) {
        let mut rng = rand_core::OsRng;
        let G = &point_random(&mut rng);
        //let H = RistrettoPoint::hash_from_bytes::<Sha512>(G.compress().as_bytes());
        let H = Hasher::new().update(&G).to_point().unwrap();

        let value = 1666;
        let (proof, _, _) =
            RangeProof::create_vartime(RANGEPROOF_MAX_N, value, G, &H, &mut rng).unwrap();

        b.iter(|| proof.verify(RANGEPROOF_MAX_N, G, &H));
    }

    #[bench]
    fn prove_vartime(b: &mut Bencher) {
        let mut rng = rand_core::OsRng;

        let G = &point_random(&mut rng);
        //let H = RistrettoPoint::hash_from_bytes::<Sha512>(G.compress().as_bytes());
        let H = Hasher::new().update(&G).to_point().unwrap();

        let value = 1666;
        b.iter(|| RangeProof::create_vartime(RANGEPROOF_MAX_N, value, G, &H, &mut rng));
    }

    #[bench]
    fn prove_ct(b: &mut Bencher) {
        /*
        let rng = rand::thread_rng();
        let G = &point_random(&mut rng);
        //let H = RistrettoPoint::hash_from_bytes::<Sha512>(G.compress().as_bytes());
        let H = Hasher::new().update(&G).to_point().unwrap();

        let value = 1666;
        b.iter(|| RangeProof::create(RANGEPROOF_MAX_N, value, G, &H, &mut rng));
        */
    }

    #[bench]
    fn bench_base3_digits(b: &mut Bencher) {
        b.iter(|| base3_digits(10352669767914021650));
    }
}
