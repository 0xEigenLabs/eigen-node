// ZKP for L_transfer(A: from, B: to, amount: u32)
use crate::zkp::sigma::Sigma;
use digest::Update;

#[derive(Default, Clone, Debug, PartialEq)]
pub struct Transfer<A, B> {
    lhs: A,
    rhs: B,
}

impl<A, B> Transfer<A, B> {
    pub fn new(lhs: A, rhs: B) -> Self {
        Self { lhs, rhs }
    }
}

/*
impl <A, B> Sigma for Transfer<A, B>
where
    A: Sigma,
    B: Sigma<
        ChallengeLength = A::ChallengeLength,
        Witness = A::Witness,
        Response = A::Response,
        AnnounceSecret = A::AnnounceSecret,
    >,
{
    type Witness = A::Witness;
    type Statement = (A::Statement, B::Statement);
    type AnnounceSecret = A::AnnounceSecret;
    type Announcement = (A::Announcement, B::Announcement);
    type Response = A::Response;
    type ChallengeLength = A::ChallengeLength;

    fn respond(&self,
        witness: &Self::Witness,
        statement: &Self::Statement,
        announce_secret: &Self::AnnounceSecret,
        announcement: &Self::Announcement,
        challenge: &generic_array::GenericArray<u8, Self::ChallengeLength>,
    ) -> Self::Response {

    }
}
*/

impl<A: crate::Writable, B: crate::Writable> crate::Writable for Transfer<A, B> {
    fn write_to<W: core::fmt::Write>(&self, w: &mut W) -> core::fmt::Result {
        write!(w, "eq(")?;
        self.lhs.write_to(w)?;
        write!(w, ",")?;
        self.rhs.write_to(w)?;
        write!(w, ")")
    }
}
