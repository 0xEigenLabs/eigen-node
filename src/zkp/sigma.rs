use core::fmt::Debug;
pub use generic_array::{self, typenum};
use generic_array::{ArrayLength, GenericArray};
use rand_core::{CryptoRng, RngCore};
use digest::Update;

pub trait Writable {
    fn write_to<W: core::fmt::Write>(&self, w: &mut W) -> core::fmt::Result;
}

impl Writable for str {
    fn write_to<W: core::fmt::Write>(&self, w: &mut W) -> core::fmt::Result {
        write!(w, "{}", self)
    }
}

pub trait Sigma: Writable {
    /// The witness for the relation.
    type Witness: Debug;
    /// The elements of the statement the prover is proving.
    type Statement: Debug;
    /// The type for the secret the prover creates when generating the proof.
    type AnnounceSecret: Debug;
    /// The type for the public announcement the prover sends in the first round of the protocol.
    type Announcement: core::cmp::Eq + Debug;
    /// The type for the response the prover sends in the last round of the protocol.
    type Response: Debug;
    /// The length as a [`typenum`]
    ///
    /// [`typenum`]: crate::typenum
    type ChallengeLength: ArrayLength<u8>;

    /// Generates the prover's announcement message.
    fn announce(
        &self,
        statement: &Self::Statement,
        announce_secret: &Self::AnnounceSecret,
    ) -> Self::Announcement;
    /// Generates the secret data to create the announcement
    fn gen_announce_secret<Rng: CryptoRng + RngCore>(
        &self,
        witness: &Self::Witness,
        rng: &mut Rng,
    ) -> Self::AnnounceSecret;
    /// Uniformly samples a response from the response space of the Sigma protocol.
    fn sample_response<Rng: CryptoRng + RngCore>(&self, rng: &mut Rng) -> Self::Response;

    /// Generates the prover's response for the verifier's challenge.
    fn respond(
        &self,
        witness: &Self::Witness,
        statement: &Self::Statement,
        announce_secret: Self::AnnounceSecret,
        announce: &Self::Announcement,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
    ) -> Self::Response;
    /// Computes what the announcement must be for the `response` to be valid.
    fn implied_announcement(
        &self,
        statement: &Self::Statement,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
        response: &Self::Response,
    ) -> Option<Self::Announcement>;

    /// Hashes the statement.
    fn hash_statement<H: Update>(&self, hash: &mut H, statement: &Self::Statement);
    /// Hashes the announcement.
    fn hash_announcement<H: Update>(&self, hash: &mut H, announcement: &Self::Announcement);
    /// Hashes the witness.
    fn hash_witness<H: Update>(&self, hash: &mut H, witness: &Self::Witness);
}

#[macro_export]
#[doc(hidden)]
macro_rules! impl_display {
    ($name:ident<$($tp:ident),+>) => {
        impl<$($tp),+> core::fmt::Display for $name<$($tp),+>
            where $name<$($tp),+>: $crate::Sigma
        {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                use $crate::Writable;
                self.write_to(f)
            }
        }
    }
}
