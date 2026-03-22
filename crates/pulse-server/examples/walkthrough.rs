//! Developer walkthrough: Pulse blind signature protocol.
//!
//! Run with: cargo run -p pulse-server --example walkthrough
//!
//! Narrates the full verified-anonymous response lifecycle step by step,
//! showing what each trust zone sees (and cannot see). No running server
//! required — everything executes in-memory.

use std::sync::Arc;

use pulse_crypto::blind_sig;
use pulse_crypto::{BlindSignature, aead};
use pulse_identity::{EmployeeId, TokenIssuer};
use pulse_protocol::messages::{ResponseSubmit, TokenRequest};
use pulse_protocol::token::{AttestationClass, TokenPayload};
use pulse_protocol::{
    BlindedToken, EncryptedBlob, KeyVersion, Nonce, QuestionBatchId, SignatureBytes, TenantId,
    UnixTimestamp,
};
use pulse_signal::{InMemoryLedger, InMemoryStore, ResponseCollector};
use uuid::Uuid;

/// Show first and last 4 bytes of a byte slice as hex.
fn hex_preview(bytes: &[u8]) -> String {
    if bytes.len() <= 8 {
        return hex::encode(bytes);
    }
    format!(
        "{}...{}",
        hex::encode(&bytes[..4]),
        hex::encode(&bytes[bytes.len() - 4..])
    )
}

fn main() {
    println!(
        "\
========================================================
  Pulse Blind Signature Protocol — Developer Walkthrough
========================================================"
    );
    println!();
    println!("This example walks through the complete verified-anonymous");
    println!("response lifecycle, step by step. No server required —");
    println!("everything runs in-memory.");
    println!();
    println!("Key concept: TWO trust zones that never share identity data.");
    println!("  Identity zone — knows WHO (employee ID, auth session)");
    println!("  Signal zone   — knows WHAT (encrypted response, no identity)");
    println!();
    println!("The ONLY shared artifact: the Token Issuer's public verification key.");

    // ── SETUP ──────────────────────────────────────────────────

    println!();
    println!("--------------------------------------------------------");
    println!("  SETUP");
    println!("--------------------------------------------------------");
    println!();

    println!("Generating RSA-2048 blind signature keypair (RFC 9474)...");
    let kp = blind_sig::generate_keypair().expect("keygen failed");
    let pk = kp.pk.clone();
    println!("  Key version: 1");
    println!();

    let ledger = Arc::new(InMemoryLedger::new());
    let store: Arc<dyn pulse_signal::ResponseStore> = Arc::new(InMemoryStore::new());
    let issuer = TokenIssuer::new(kp.sk, KeyVersion(1));
    let collector = ResponseCollector::new(kp.pk, ledger, store.clone());
    println!("Created Identity zone (TokenIssuer)");
    println!("Created Signal zone (ResponseCollector + InMemoryLedger + InMemoryStore)");
    println!();

    let batch_id = QuestionBatchId::from_uuid(Uuid::new_v4());
    let tenant_id = TenantId::from_uuid(Uuid::new_v4());
    let encryption_key = aead::generate_key();
    println!("  Batch ID:  {batch_id}");
    println!("  Tenant ID: {tenant_id}");

    // ── PHASE 1: Identity-Aware Channel ────────────────────────

    println!();
    println!(
        "\
========================================================
  PHASE 1: Identity-Aware Channel (Client <-> Identity Zone)
========================================================"
    );
    println!();
    println!("The client is authenticated. The Identity zone knows this");
    println!("is \"employee-42\".");

    // Step 1: Create token
    println!();
    println!("--- Step 1: Client creates a token payload ---");
    println!();

    let token = TokenPayload {
        nonce: Nonce::random(),
        question_batch_id: batch_id,
        tenant_id,
        expiry: UnixTimestamp(u64::MAX),
        segment_vector: vec!["engineering".into()],
        attestation_class: AttestationClass::Personal,
        key_version: KeyVersion(1),
    };
    let token_bytes = token.to_bytes();

    println!("  TokenPayload {{");
    println!(
        "    nonce:              {}  (32 bytes, random)",
        hex_preview(&token.nonce.0)
    );
    println!("    question_batch_id:  {batch_id}");
    println!("    tenant_id:          {tenant_id}");
    println!("    expiry:             <far future>");
    println!("    segment_vector:     [\"engineering\"]");
    println!("    attestation_class:  Personal");
    println!("    key_version:        1");
    println!("  }}");
    println!("  Serialized: {} bytes", token_bytes.0.len());

    // Step 2: Blind the token
    println!();
    println!("--- Step 2: Client blinds the token ---");
    println!();

    let blinding_result = blind_sig::blind(&pk, &token_bytes.0).expect("blinding failed");

    println!("  The client applies a random blinding factor so the Token");
    println!("  Issuer cannot see the actual token content.");
    println!();
    println!(
        "  Blinded token: {}  ({} bytes)",
        hex_preview(&blinding_result.blind_message.0),
        blinding_result.blind_message.0.len()
    );
    println!("  (The original token is now hidden from the Identity zone)");

    // Step 3: Token Issuer signs
    println!();
    println!("--- Step 3: Token Issuer signs the blinded token ---");
    println!();

    let token_request = TokenRequest {
        blinded_token: BlindedToken(blinding_result.blind_message.0.clone()),
        question_batch_id: batch_id,
    };
    let employee = EmployeeId("employee-42".into());
    let token_response = issuer
        .sign_token(&employee, &token_request)
        .expect("signing failed");

    println!("  [IDENTITY ZONE] TokenIssuer.sign_token(\"employee-42\", ...)");
    println!();
    println!("  What the Identity zone sees:");
    println!("    Employee ID:    \"employee-42\"              <-- knows WHO");
    println!(
        "    Blinded token:  {}   <-- opaque blob",
        hex_preview(&blinding_result.blind_message.0)
    );
    println!("    Batch ID:       {batch_id}");
    println!();
    println!("  What the Identity zone CANNOT see:");
    println!("    Token nonce, tenant_id, segments, expiry  <-- hidden by blinding");
    println!();
    println!(
        "  Blind signature:  {}  ({} bytes)",
        hex_preview(&token_response.blind_signature.0),
        token_response.blind_signature.0.len()
    );

    // Check issuance log
    let log = issuer.issuance_log();
    println!();
    println!("  Issuance log now records:");
    println!("    employee_id = \"{}\"", log[0].employee_id.0);
    println!("    batch_id    = {}", log[0].question_batch_id);
    println!("    (NO token value — only the blinded version was seen)");

    // ── CLIENT-SIDE ────────────────────────────────────────────

    println!();
    println!(
        "\
========================================================
  CLIENT-SIDE (between zones — not visible to either)
========================================================"
    );

    // Step 4: Unblind
    println!();
    println!("--- Step 4: Client unblinds the signature ---");
    println!();

    let blind_sig_val = BlindSignature(token_response.blind_signature.0.clone());
    let sig = blind_sig::finalize(&pk, &blind_sig_val, &blinding_result, &token_bytes.0)
        .expect("unblinding failed");

    println!("  The client removes the blinding factor, producing a valid");
    println!("  signature over the ORIGINAL token that the Issuer never saw.");
    println!();
    println!(
        "  Unblinded signature: {}  ({} bytes)",
        hex_preview(&sig.0),
        sig.0.len()
    );

    // Verify client-side
    let verify_result =
        blind_sig::verify(&pk, &sig, blinding_result.msg_randomizer, &token_bytes.0);
    assert!(verify_result.is_ok(), "client-side verification failed");
    println!();
    println!("  Client-side verification: VALID");

    // Step 5: Encrypt response
    println!();
    println!("--- Step 5: Client encrypts the response ---");
    println!();

    let response_plaintext = b"4";
    let encrypted_response =
        aead::encrypt(&encryption_key, response_plaintext).expect("encryption failed");

    println!("  Response plaintext: \"4\" (rating on a 5-point scale)");
    println!("  Encryption:         AES-256-GCM (random nonce)");
    println!(
        "  Encrypted blob:     {}  ({} bytes)",
        hex_preview(&encrypted_response),
        encrypted_response.len()
    );
    println!();
    println!("  The encryption key stays with the client. Neither zone can");
    println!("  read the response content without it.");

    // ── PHASE 2: Anonymous Channel ─────────────────────────────

    println!();
    println!(
        "\
========================================================
  PHASE 2: Anonymous Channel (Client -> Signal Zone)
========================================================"
    );
    println!();
    println!("The client submits via an anonymous channel. NO authentication.");
    println!("NO session. NO cookies. The Signal zone has no idea who this is.");

    // Step 6: Build submission
    println!();
    println!("--- Step 6: Client submits anonymous response ---");
    println!();

    let submit = ResponseSubmit {
        token: token_bytes.clone(),
        signature: SignatureBytes(sig.0.clone()),
        msg_randomizer: blinding_result.msg_randomizer.map(|r| r.0),
        key_version: KeyVersion(1),
        question_batch_id: batch_id,
        tenant_id,
        response_blob: EncryptedBlob(encrypted_response.clone()),
    };

    println!("  ResponseSubmit {{");
    println!("    token:             {} bytes", submit.token.0.len());
    println!("    signature:         {} bytes", submit.signature.0.len());
    println!("    key_version:       1");
    println!("    question_batch_id: {batch_id}");
    println!("    tenant_id:         {tenant_id}");
    println!(
        "    response_blob:     {} bytes (encrypted)",
        submit.response_blob.0.len()
    );
    println!("  }}");

    // Step 7: Signal zone validates
    println!();
    println!("--- Step 7: Signal zone validates and accepts ---");
    println!();
    println!("  [SIGNAL ZONE] ResponseCollector.accept(...)");
    println!();

    collector
        .accept(&submit)
        .expect("response rejected unexpectedly");

    println!("  What the Signal zone checks:");
    println!("    Token deserialized:  YES");
    println!("    Batch ID matches:    YES");
    println!("    Tenant ID matches:   YES");
    println!("    Signature valid:     YES (verified against Issuer's public key)");
    println!("    Token already used:  NO  (first time in spent-token ledger)");
    println!();
    println!("  What the Signal zone CANNOT see:");
    println!("    Employee ID:         <not in ResponseSubmit — enforced by types>");
    println!("    Response plaintext:  <encrypted, key held by client>");
    println!();
    println!("  Result: ACCEPTED");
    println!("  Stored responses: {}", store.count());

    // ── VERIFICATION: Privacy Properties ───────────────────────

    println!();
    println!(
        "\
========================================================
  VERIFICATION: Privacy Properties
========================================================"
    );

    // Check 1: Identity zone
    println!();
    println!("--- Check 1: Identity zone never saw the real token ---");
    println!();

    let log = issuer.issuance_log();
    println!("  Issuance log entries: {}", log.len());
    println!(
        "  Entry: employee_id=\"{}\", batch={}",
        log[0].employee_id.0, log[0].question_batch_id
    );
    println!("  Contains unblinded token? NO");
    println!("  Contains response content? NO");

    // Check 2: Signal zone
    println!();
    println!("--- Check 2: Signal zone never saw the employee identity ---");
    println!();

    let stored = store.list();
    assert_eq!(stored.len(), 1);
    let stored_response = &stored[0];

    println!("  Stored responses: {}", stored.len());
    println!(
        "  Response fields: encrypted_blob ({} bytes), question_batch_id, received_at",
        stored_response.encrypted_blob.0.len()
    );
    println!("  Contains employee_id? NO (not in StoredResponse — enforced by types)");
    println!();

    let decrypted = aead::decrypt(&encryption_key, &stored_response.encrypted_blob.0)
        .expect("decryption failed");
    assert_eq!(decrypted, b"4");
    println!(
        "  Decrypting stored blob with client's key: \"{}\"",
        String::from_utf8_lossy(&decrypted)
    );

    // ── SECURITY: Replay Prevention ────────────────────────────

    println!();
    println!(
        "\
========================================================
  SECURITY: Replay Prevention
========================================================"
    );
    println!();
    println!("--- Submitting the same token again ---");
    println!();

    let replay_result = collector.accept(&submit);
    assert!(replay_result.is_err());
    println!("  ResponseCollector.accept(same_submission)...");
    println!("  Result: REJECTED ({})", replay_result.unwrap_err());
    println!();
    println!("  The spent-token ledger prevents double-voting. Even though");
    println!("  the signature is valid, the token hash is already recorded.");

    // ── SECURITY: Forged Signature ─────────────────────────────

    println!();
    println!(
        "\
========================================================
  SECURITY: Forged Signature Rejection
========================================================"
    );
    println!();
    println!("--- Submitting a response with a fake signature ---");
    println!();

    let forged_token = TokenPayload {
        nonce: Nonce::random(),
        question_batch_id: batch_id,
        tenant_id,
        expiry: UnixTimestamp(u64::MAX),
        segment_vector: vec!["engineering".into()],
        attestation_class: AttestationClass::Personal,
        key_version: KeyVersion(1),
    };
    let forged_token_bytes = forged_token.to_bytes();

    let forged_submit = ResponseSubmit {
        token: forged_token_bytes,
        signature: SignatureBytes(vec![0xDE; 256]),
        msg_randomizer: None,
        key_version: KeyVersion(1),
        question_batch_id: batch_id,
        tenant_id,
        response_blob: EncryptedBlob(vec![0x00]),
    };

    println!(
        "  Forged signature: {} (256 bytes of 0xDE)",
        hex_preview(&forged_submit.signature.0)
    );
    println!();

    let forge_result = collector.accept(&forged_submit);
    assert!(forge_result.is_err());
    println!("  ResponseCollector.accept(forged_submission)...");
    println!("  Result: REJECTED ({})", forge_result.unwrap_err());
    println!();
    println!("  Without the Token Issuer's secret key, an attacker cannot");
    println!("  produce a valid blind signature. Ballot stuffing is impossible.");

    // ── SUMMARY ────────────────────────────────────────────────

    println!();
    println!(
        "\
========================================================
  SUMMARY
========================================================

  The blind signature protocol guarantees:

  1. VERIFIED:    Every response carries a signature from the Token
                  Issuer, proving the respondent was authorized.

  2. ANONYMOUS:   The Token Issuer signed a blinded token — it cannot
                  link the signature to the response. The Signal zone
                  sees only anonymous tokens, never employee IDs.

  3. UNLINKABLE:  Even if both zones collude, they cannot correlate
                  \"employee-42 got a token\" with \"this response was
                  submitted\" — the blinding factor breaks the link.

  4. REPLAY-PROOF: Each token can only be spent once, preventing
                   double-voting.

  Run the full test suite to verify all 25 properties:
    cargo test

========================================================"
    );
}
