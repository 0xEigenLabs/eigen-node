use digest::Update;
use generic_array::GenericArray;
use rand_core::{CryptoRng, RngCore};

use crate::Sigma;

#[derive(Default, Clone, Debug, PartialEq)]
pub struct And<A, B> {
    pub lhs: A,
    pub rhs: B,
}

impl<A, B> Sigma for And<A, B>
where
    A: Sigma,
    B: Sigma<ChallengeLength = A::ChallengeLength>,
{
    type Witness = (A::Witness, B::Witness);
    type Statement = (A::Statement, B::Statement);
    type Announcement = (A::Announcement, B::Announcement);
    type AnnounceSecret = (A::AnnounceSecret, B::AnnounceSecret);
    type Response = (A::Response, B::Response);
    type ChallengeLength = A::ChallengeLength;

    fn respond(
        &self,
        witness: &Self::Witness,
        statement: &Self::Statement,
        announce_secret: Self::AnnounceSecret,
        announce: &Self::Announcement,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
    ) -> Self::Response {
        (
            self.lhs.respond(
                &witness.0,
                &statement.0,
                announce_secret.0,
                &announce.0,
                challenge,
            ),
            self.rhs.respond(
                &witness.1,
                &statement.1,
                announce_secret.1,
                &announce.1,
                challenge,
            ),
        )
    }

    fn announce(
        &self,
        statement: &Self::Statement,
        announce_secret: &Self::AnnounceSecret,
    ) -> Self::Announcement {
        (
            self.lhs.announce(&statement.0, &announce_secret.0),
            self.rhs.announce(&statement.1, &announce_secret.1),
        )
    }

    fn gen_announce_secret<Rng: CryptoRng + RngCore>(
        &self,
        witness: &Self::Witness,
        rng: &mut Rng,
    ) -> Self::AnnounceSecret {
        (
            self.lhs.gen_announce_secret(&witness.0, rng),
            self.rhs.gen_announce_secret(&witness.1, rng),
        )
    }

    fn sample_response<Rng: CryptoRng + RngCore>(&self, rng: &mut Rng) -> Self::Response {
        (self.lhs.sample_response(rng), self.rhs.sample_response(rng))
    }

    fn implied_announcement(
        &self,
        statement: &Self::Statement,
        challenge: &generic_array::GenericArray<u8, Self::ChallengeLength>,
        response: &Self::Response,
    ) -> Option<Self::Announcement> {
        let (lhs_response, rhs_response) = response;
        let (lhs_statement, rhs_statement) = statement;
        self.lhs
            .implied_announcement(lhs_statement, challenge, lhs_response)
            .and_then(|lhs_announcement| {
                self.rhs
                    .implied_announcement(&rhs_statement, challenge, rhs_response)
                    .map(|rhs_announcement| (lhs_announcement, rhs_announcement))
            })
    }

    fn hash_statement<H: Update>(&self, hash: &mut H, statement: &Self::Statement) {
        self.lhs.hash_statement(hash, &statement.0);
        self.rhs.hash_statement(hash, &statement.1);
    }

    fn hash_announcement<H: Update>(&self, hash: &mut H, announcement: &Self::Announcement) {
        self.lhs.hash_announcement(hash, &announcement.0);
        self.rhs.hash_announcement(hash, &announcement.1)
    }

    fn hash_witness<H: Update>(&self, hash: &mut H, witness: &Self::Witness) {
        self.lhs.hash_witness(hash, &witness.0);
        self.rhs.hash_witness(hash, &witness.1);
    }
}

impl<A: crate::Writable, B: crate::Writable> crate::Writable for And<A, B> {
    fn write_to<W: core::fmt::Write>(&self, w: &mut W) -> core::fmt::Result {
        write!(w, "and(")?;
        self.lhs.write_to(w)?;
        write!(w, ",")?;
        self.rhs.write_to(w)?;
        write!(w, ")")
    }
}

crate::impl_display!(And<A,B>);

#[cfg(test)]
mod test {
    mod babyjubjub {
        use crate::fr::G;
        use crate::hash::Hasher;
        use crate::{And, FiatShamir, HashTranscript};
        use ::proptest::prelude::*;
        use rand_chacha::ChaCha20Rng;
        use crate::zkp::babyjubjub;
        use num_bigint::BigInt;
        use crate::zkp::babyjubjub::test::babyjubjub_scalar;

        proptest! {
            #[test]
            fn and_dlg(
                x in babyjubjub_scalar(),
                y in babyjubjub_scalar(),
            ) {
                use generic_array::typenum::U31;

                type AndDL = And<babyjubjub::DLG<U31>, babyjubjub::DLG<U31>>;
                let xG = G().mul_scalar(&x);
                let yG = G().mul_scalar(&y);
                let statement = (xG, yG);

                let proof_system = crate::FiatShamir::<AndDL, HashTranscript<Hasher, ChaCha20Rng>>::default();
                let proof = proof_system.prove(&(x, y), &statement, Some(&mut rand::thread_rng()));
                assert!(proof_system.verify(&statement, &proof));
            }
        }
    }
}
