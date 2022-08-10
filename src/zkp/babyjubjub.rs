use crate::fr;
use crate::zkp::sigma::{Sigma, Writable};
use babyjubjub_rs::{utils as bu, Point};
use core::marker::PhantomData;
use digest::Update;
use generic_array::{
    typenum::{self, type_operators::IsLessOrEqual, U31},
    ArrayLength, GenericArray,
};
use num_bigint::{BigInt, Sign};
use rand_core::{CryptoRng, RngCore};

/// Proves knowledge of `x` such that `A = x * B` for some `A` and `B` included in the statement.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DL<L> {
    challenge_len: PhantomData<L>,
}

impl<L: ArrayLength<u8>> Sigma for DL<L>
where
    L: IsLessOrEqual<U31>,
    <L as IsLessOrEqual<U31>>::Output: typenum::marker_traits::NonZero,
{
    type Witness = BigInt;
    type Statement = (Point, Point);
    type AnnounceSecret = BigInt;
    type Announcement = Point;
    type Response = BigInt;
    type ChallengeLength = L;

    fn respond(
        &self,
        witness: &Self::Witness,
        _statement: &Self::Statement,
        announce_secret: Self::AnnounceSecret,
        _announce: &Self::Announcement,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
    ) -> Self::Response {
        let challenge = normalize_challenge(challenge);
        announce_secret + challenge * witness
    }

    fn announce(
        &self,
        statement: &Self::Statement,
        announce_secret: &Self::AnnounceSecret,
    ) -> Self::Announcement {
        let G = &statement.0;
        G.mul_scalar(announce_secret)
    }

    fn gen_announce_secret<Rng: CryptoRng + RngCore>(
        &self,
        _witness: &Self::Witness,
        rng: &mut Rng,
    ) -> Self::AnnounceSecret {
        fr::random(rng)
    }

    fn sample_response<Rng: CryptoRng + RngCore>(&self, rng: &mut Rng) -> Self::Response {
        fr::random(rng)
    }

    fn implied_announcement(
        &self,
        statement: &Self::Statement,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
        response: &Self::Response,
    ) -> Option<Self::Announcement> {
        let (G, X) = statement;
        let challenge = normalize_challenge(challenge);
        let neg_challenge = fr::neg(&challenge);
        Some(
            G.mul_scalar(response)
                .projective()
                .add(&X.mul_scalar(&neg_challenge).projective())
                .affine(),
        )
        //Some(response * G - challenge * X)
    }

    fn hash_statement<H: Update>(&self, hash: &mut H, statement: &Self::Statement) {
        hash.update(statement.0.compress());
        hash.update(statement.1.compress());
    }

    fn hash_announcement<H: Update>(&self, hash: &mut H, announcement: &Self::Announcement) {
        hash.update(announcement.compress())
    }

    fn hash_witness<H: Update>(&self, hash: &mut H, witness: &Self::Witness) {
        let mut bytes = [0u8; 32];
        let (_, big_bytes) = witness.to_bytes_le();
        hash.update(big_bytes)
    }
}

/// Proves knowledge of `x` such that `A = x * G` for some `A` included in the statement.
/// `G` is the standard basepoint used in the babyjubjub signature scheme and is not included in the statement.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DLG<L> {
    challenge_len: PhantomData<L>,
}

impl<L: ArrayLength<u8>> Sigma for DLG<L>
where
    L: IsLessOrEqual<U31>,
    <L as IsLessOrEqual<U31>>::Output: typenum::marker_traits::NonZero,
{
    type Witness = BigInt;
    type Statement = Point;
    type AnnounceSecret = BigInt;
    type Announcement = Point;
    type Response = BigInt;
    type ChallengeLength = L;

    fn respond(
        &self,
        witness: &Self::Witness,
        _statement: &Self::Statement,
        announce_secret: Self::AnnounceSecret,
        _announce: &Self::Announcement,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
    ) -> Self::Response {
        let challenge = normalize_challenge(challenge);
        &announce_secret + &challenge * witness
    }

    fn announce(
        &self,
        _statement: &Self::Statement,
        announce_secret: &Self::AnnounceSecret,
    ) -> Self::Announcement {
        fr::G().mul_scalar(announce_secret)
    }

    fn gen_announce_secret<Rng: CryptoRng + RngCore>(
        &self,
        _witness: &Self::Witness,
        rng: &mut Rng,
    ) -> Self::AnnounceSecret {
        fr::random(rng)
    }

    fn sample_response<Rng: CryptoRng + RngCore>(&self, rng: &mut Rng) -> Self::Response {
        fr::random(rng)
    }

    fn implied_announcement(
        &self,
        statement: &Self::Statement,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
        response: &Self::Response,
    ) -> Option<Self::Announcement> {
        let X = statement;
        let challenge = normalize_challenge(challenge);

        //  -challenge * X + response * G
        let neg_challenge = fr::neg(&challenge);
        Some(
            X.mul_scalar(&neg_challenge)
                .projective()
                .add(&fr::G().mul_scalar(response).projective())
                .affine(),
        )
        /*
        Some(EdwardsPoint::vartime_double_scalar_mul_basepoint(
            &-challenge,
            X,
            response,
        ))
            */
    }

    fn hash_statement<H: Update>(&self, hash: &mut H, statement: &Self::Statement) {
        hash.update(statement.compress());
    }

    fn hash_announcement<H: Update>(&self, hash: &mut H, announcement: &Self::Announcement) {
        hash.update(announcement.compress())
    }

    fn hash_witness<H: Update>(&self, hash: &mut H, witness: &Self::Witness) {
        let mut bytes = [0u8; 32];
        let (_, big_bytes) = witness.to_bytes_le();
        hash.update(bytes)
    }
}

fn normalize_challenge<L: ArrayLength<u8>>(challenge: &GenericArray<u8, L>) -> BigInt {
    let mut challenge_bytes = [0u8; 32];
    challenge_bytes[..challenge.len()].copy_from_slice(challenge.as_slice());
    BigInt::from_bytes_le(Sign::Plus, &challenge_bytes[..])
}

impl<L> Writable for DL<L> {
    fn write_to<W: core::fmt::Write>(&self, w: &mut W) -> core::fmt::Result {
        write!(w, "DL(babyjubjub)")
    }
}

impl<L> Writable for DLG<L> {
    fn write_to<W: core::fmt::Write>(&self, w: &mut W) -> core::fmt::Result {
        write!(w, "DLG(babyjubjub)")
    }
}

crate::impl_display!(DL<L>);
crate::impl_display!(DLG<L>);

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::hash::Hasher;
    use crate::zkp::fiat_shamir::FiatShamir;
    use ::proptest::prelude::*;
    use generic_array::typenum::U31;

    prop_compose! {
        pub fn babyjubjub_scalar()(
            bytes in any::<[u8; 32]>(),
        ) -> BigInt {
            BigInt::from_bytes_le(Sign::Plus, &bytes[..])
        }
    }

    prop_compose! {
        pub fn babyjubjub_point()(
            x in babyjubjub_scalar(),
        ) -> Point {
            fr::G().mul_scalar(&x)
        }
    }

    type Transcript = crate::zkp::transcript::HashTranscript<Hasher, rand_chacha::ChaCha20Rng>;

    proptest! {
        #[test]
        fn babyjubjub_dlg(
            x in babyjubjub_scalar(),
        ) {
            let xG = fr::G().mul_scalar(&x);
            let proof_system = FiatShamir::<DLG<U31>, Transcript>::default();
            let proof = proof_system.prove(&x, &xG, Some(&mut rand::thread_rng()));
            assert!(proof_system.verify(&xG, &proof));
        }
    }

    proptest! {
        #[test]
        fn babyjubjub_dl(
            x in babyjubjub_scalar(),
        ) {
            let G = Point::random(&mut rand::thread_rng());
            let xG = G.mul_scalar(&x);
            let proof_system = FiatShamir::<DL<U31>, Transcript>::default();
            let proof = proof_system.prove(&x, &(G.clone(), xG.clone()), Some(&mut rand::thread_rng()));
            assert!(proof_system.verify(&(G, xG), &proof));
        }
    }
}
