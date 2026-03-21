use blind_rsa_signatures::{
    BlindSignature, BlindingResult, DefaultRng, KeyPair, MessageRandomizer, PSS, Randomized,
    SecretKey, Sha384, Signature,
};

pub use blind_rsa_signatures::PublicKey;

pub type BrssPublicKey = PublicKey<Sha384, PSS, Randomized>;
pub type BrssSecretKey = SecretKey<Sha384, PSS, Randomized>;
pub type BrssKeyPair = KeyPair<Sha384, PSS, Randomized>;

/// Key size for RSA blind signatures (2048-bit minimum per RFC 9474).
const KEY_BITS: usize = 2048;

#[derive(Debug, thiserror::Error)]
pub enum BlindSigError {
    #[error("key generation failed: {0}")]
    KeyGeneration(#[source] blind_rsa_signatures::Error),
    #[error("blinding failed: {0}")]
    Blinding(#[source] blind_rsa_signatures::Error),
    #[error("blind signing failed: {0}")]
    BlindSigning(#[source] blind_rsa_signatures::Error),
    #[error("finalization failed: {0}")]
    Finalization(#[source] blind_rsa_signatures::Error),
    #[error("verification failed: {0}")]
    Verification(#[source] blind_rsa_signatures::Error),
}

/// Generate an RSA key pair for blind signature operations.
pub fn generate_keypair() -> Result<BrssKeyPair, BlindSigError> {
    BrssKeyPair::generate(&mut DefaultRng, KEY_BITS).map_err(BlindSigError::KeyGeneration)
}

/// Client: blind a message for signing by the Token Issuer.
/// Returns the blinding result containing the blinded message and the secret blinding factor.
pub fn blind(pk: &BrssPublicKey, msg: &[u8]) -> Result<BlindingResult, BlindSigError> {
    pk.blind(&mut DefaultRng, msg)
        .map_err(BlindSigError::Blinding)
}

/// Token Issuer: sign a blinded message without seeing the original content.
pub fn blind_sign(
    sk: &BrssSecretKey,
    blinded_msg: &blind_rsa_signatures::BlindMessage,
) -> Result<BlindSignature, BlindSigError> {
    sk.blind_sign(blinded_msg)
        .map_err(BlindSigError::BlindSigning)
}

/// Client: unblind the signature and verify it against the public key.
/// Returns the final signature that can be verified by the Response Collector.
pub fn finalize(
    pk: &BrssPublicKey,
    blind_sig: &BlindSignature,
    blinding_result: &BlindingResult,
    msg: &[u8],
) -> Result<Signature, BlindSigError> {
    pk.finalize(blind_sig, blinding_result, msg)
        .map_err(BlindSigError::Finalization)
}

/// Response Collector: verify a signature against the public key.
pub fn verify(
    pk: &BrssPublicKey,
    sig: &Signature,
    msg_randomizer: Option<MessageRandomizer>,
    msg: &[u8],
) -> Result<(), BlindSigError> {
    pk.verify(sig, msg_randomizer, msg)
        .map_err(BlindSigError::Verification)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_blind_signature_round_trip() {
        // 1. Server generates keypair
        let kp = generate_keypair().unwrap();
        let pk = &kp.pk;
        let sk = &kp.sk;

        // 2. Client blinds a message
        let msg = b"test token payload";
        let blinding_result = blind(pk, msg).unwrap();

        // 3. Server signs the blinded message (never sees the original)
        let blind_sig = blind_sign(sk, &blinding_result.blind_message).unwrap();

        // 4. Client unblinds and verifies
        let sig = finalize(pk, &blind_sig, &blinding_result, msg).unwrap();

        // 5. Anyone can verify with the public key
        verify(pk, &sig, blinding_result.msg_randomizer, msg).unwrap();
    }

    #[test]
    fn wrong_message_fails_verification() {
        let kp = generate_keypair().unwrap();
        let msg = b"real message";
        let blinding_result = blind(&kp.pk, msg).unwrap();
        let blind_sig = blind_sign(&kp.sk, &blinding_result.blind_message).unwrap();
        let sig = finalize(&kp.pk, &blind_sig, &blinding_result, msg).unwrap();

        let result = verify(
            &kp.pk,
            &sig,
            blinding_result.msg_randomizer,
            b"wrong message",
        );
        assert!(result.is_err());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let kp1 = generate_keypair().unwrap();
        let kp2 = generate_keypair().unwrap();

        let msg = b"test message";
        let blinding_result = blind(&kp1.pk, msg).unwrap();
        let blind_sig = blind_sign(&kp1.sk, &blinding_result.blind_message).unwrap();
        let sig = finalize(&kp1.pk, &blind_sig, &blinding_result, msg).unwrap();

        let result = verify(&kp2.pk, &sig, blinding_result.msg_randomizer, msg);
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(5))] // RSA keygen is slow

        #[test]
        fn blind_sign_verify_roundtrip(msg in prop::collection::vec(any::<u8>(), 1..256)) {
            let kp = generate_keypair().unwrap();
            let blinding_result = blind(&kp.pk, &msg).unwrap();
            let blind_sig = blind_sign(&kp.sk, &blinding_result.blind_message).unwrap();
            let sig = finalize(&kp.pk, &blind_sig, &blinding_result, &msg).unwrap();
            verify(&kp.pk, &sig, blinding_result.msg_randomizer, &msg).unwrap();
        }

        #[test]
        fn different_blinding_factors_produce_different_blinded_messages(
            msg in prop::collection::vec(any::<u8>(), 1..256)
        ) {
            let kp = generate_keypair().unwrap();
            let result1 = blind(&kp.pk, &msg).unwrap();
            let result2 = blind(&kp.pk, &msg).unwrap();
            // Same message, different random blinding factors -> different blinded messages
            prop_assert_ne!(result1.blind_message.0, result2.blind_message.0);
        }

        #[test]
        fn random_signature_fails_verification(
            msg in prop::collection::vec(any::<u8>(), 1..256),
            fake_sig_bytes in prop::collection::vec(any::<u8>(), 256..257)
        ) {
            let kp = generate_keypair().unwrap();
            let blinding_result = blind(&kp.pk, &msg).unwrap();
            let fake_sig = Signature(fake_sig_bytes);
            let result = verify(&kp.pk, &fake_sig, blinding_result.msg_randomizer, &msg);
            prop_assert!(result.is_err());
        }
    }
}
