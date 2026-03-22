use pulse_crypto::blind_sig;
use pulse_server::key_store::load_or_generate_keypair;

#[test]
fn generate_and_reload_keypair() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("test-key.pem");

    // First call generates a new keypair and saves it
    let kp1 = load_or_generate_keypair(&key_path).unwrap();
    assert!(key_path.exists(), "key file should be created");

    // Second call loads the existing keypair
    let kp2 = load_or_generate_keypair(&key_path).unwrap();

    // Keys should be identical
    assert_eq!(kp1.sk, kp2.sk, "secret keys should match after reload");
    assert_eq!(kp1.pk, kp2.pk, "public keys should match after reload");
}

#[test]
fn loaded_key_produces_valid_signatures() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("test-key.pem");

    // Generate and save
    let _ = load_or_generate_keypair(&key_path).unwrap();

    // Load from disk
    let kp = load_or_generate_keypair(&key_path).unwrap();

    // Sign and verify with the loaded key
    let msg = b"test-token-payload";
    let blinding_result = blind_sig::blind(&kp.pk, msg).unwrap();
    let blind_sig = kp.sk.blind_sign(&blinding_result.blind_message.0).unwrap();
    let sig = blind_sig::finalize(&kp.pk, &blind_sig, &blinding_result, msg).unwrap();
    let verify = blind_sig::verify(&kp.pk, &sig, blinding_result.msg_randomizer, msg);
    assert!(verify.is_ok(), "signature from loaded key should verify");
}

#[cfg(unix)]
#[test]
fn key_file_has_restricted_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("test-key.pem");

    let _ = load_or_generate_keypair(&key_path).unwrap();

    let perms = std::fs::metadata(&key_path).unwrap().permissions();
    assert_eq!(
        perms.mode() & 0o777,
        0o600,
        "key file should have 0600 permissions"
    );
}
