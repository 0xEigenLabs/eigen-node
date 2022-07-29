use core::iter;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity, VartimeMultiscalarMul};
use merlin::Transcript;

trait TranscriptProtocol {
    fn domain_sep(&mut self);
    fn commit_scalar(&mut self, label: &'static [u8], scalar: &Scalar);
    fn commit_point(&mut self, label: &'static [u8], point: &CompressedRistretto);
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar;
    fn challenge_u8x32(&mut self, label: &'static [u8]) -> [u8; 32];
}

impl TranscriptProtocol for Transcript {
    fn domain_sep(&mut self) {
        // A proof-specific domain separation label that should
        // uniquely identify the proof statement.
        self.append_message(b"dom-sep", b"TranscriptProtocol Example");
    }

    fn commit_scalar(&mut self, label: &'static [u8], scalar: &Scalar) {
        self.append_message(label, scalar.as_bytes());
    }

    fn commit_point(&mut self, label: &'static [u8], point: &CompressedRistretto) {
        self.append_message(label, point.as_bytes());
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
        // Reduce a double-width scalar to ensure a uniform distribution
        let mut buf = [0; 64];
        self.challenge_bytes(label, &mut buf);
        Scalar::from_bytes_mod_order_wide(&buf)
    }

    fn challenge_u8x32(&mut self, label: &'static [u8]) -> [u8; 32] {
        let mut buf = [0u8; 32];
        self.challenge_bytes(label, &mut buf);
        buf
    }
}

#[derive(Copy, Clone)]
pub struct Signature {
    pub s: Scalar,
    pub R: CompressedRistretto,
}

impl Signature {
    pub fn new(s: Scalar, R: CompressedRistretto) -> Signature {
        Signature { s, R }
    }
    fn from_secret_decompressed(privkey: &Scalar) -> CompressedRistretto {
        (privkey * RISTRETTO_BASEPOINT_POINT).compress()
    }

    pub fn sign(label: &'static [u8], message: &[u8], privkey: &Scalar) -> Signature {
        let mut transript = Transcript::new(b"sign");
        transript.domain_sep();
        transript.append_message(label, message);
        let X = Self::from_secret_decompressed(&privkey);
        let mut rng = transript
            .build_rng()
            .rekey_with_witness_bytes(b"x", &privkey.to_bytes())
            .finalize(&mut rand::thread_rng());

        let r = Scalar::random(&mut rng);
        let R = (RISTRETTO_BASEPOINT_POINT * r).compress();

        let c = {
            transript.commit_point(b"X", &X);
            transript.commit_point(b"R", &R);
            transript.challenge_scalar(b"c")
        };
        let s = r + c * privkey;
        Signature { s, R }
    }

    pub fn verify(
        &self,
        label: &'static [u8],
        message: &[u8],
        pubkey: &CompressedRistretto,
    ) -> bool {
        let mut transript = Transcript::new(b"sign");
        transript.domain_sep();
        transript.append_message(label, message);
        let c = {
            transript.commit_point(b"X", pubkey);
            transript.commit_point(b"R", &self.R);
            transript.challenge_scalar(b"c")
        };

        // `s * G = R + c * pubkey`
        let result = RistrettoPoint::optional_multiscalar_mul(
            iter::once(-self.s).chain(iter::once(Scalar::one()).chain(iter::once(c))),
            iter::once(Some(RISTRETTO_BASEPOINT_POINT))
                .chain(iter::once(self.R.decompress()).chain(iter::once(pubkey.decompress()))),
        )
        .unwrap();

        result.is_identity()
    }
}

#[test]
fn test_signature() {
    let label = b"abc";
    let mut t = Transcript::new(b"key");
    let witness1 = b"witness data 1";

    let mut r = t
        .build_rng()
        .rekey_with_witness_bytes(b"witness", witness1)
        .finalize(&mut rand::thread_rng());

    let sk = Scalar::random(&mut r);
    let pk = sk * RISTRETTO_BASEPOINT_POINT;

    let msg = "hello, world".as_bytes();
    let sig = Signature::sign(b"schnorr", &msg, &sk);

    assert!(sig.verify(b"schnorr", &msg, &pk.compress()));
}
