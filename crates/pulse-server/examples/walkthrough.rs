//! Developer walkthrough: Pulse blind signature protocol.
//!
//! Run with: cargo run -p pulse-server --example walkthrough
//!
//! Narrates the full verified-anonymous response lifecycle step by step,
//! showing what each trust zone sees (and cannot see). No running server
//! required — everything executes in-memory.

use std::sync::Arc;

use pulse_crypto::blind_sig;
use pulse_crypto::{BlindSignature, aead, pseudonym};
use pulse_identity::{
    EmployeeId, FrequencyPolicy, InMemorySamplingEngine, QuestionBatch, SamplingEngine, TokenIssuer,
};
use pulse_protocol::epoch::EpochConfig;
use pulse_protocol::messages::{
    ResponseData, ResponsePayload, ResponseSubmit, ResponseType, TokenRequest,
};
use pulse_protocol::token::{AttestationClass, TokenPayload};
use pulse_protocol::{
    BlindedToken, EncryptedBlob, KeyVersion, Nonce, Pseudonym, QuestionBatchId, QuestionText,
    SegmentLabel, SignatureBytes, TenantId, UnixTimestamp,
};
use pulse_server::analytics::AnalyticsEngine;
use pulse_server::cmk::CmkProvider;
use pulse_server::dek_store::{DekDomain, DekStore, InMemoryDekStore};
use pulse_server::dev_cmk::DevCmkProvider;
use pulse_server::dev_tenant_keys::InMemoryTenantKeyStore;
use pulse_server::encrypting_store::EncryptingResponseStore;
use pulse_signal::{InMemoryLedger, InMemoryStore, ResponseCollector, ResponseStore};

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
    let key_store = Arc::new(InMemoryTenantKeyStore::new());
    println!("  Key version: 1");
    println!();

    let batch_id = QuestionBatchId::new();
    let tenant_id = TenantId::new();
    key_store.register_tenant(tenant_id, kp.sk, kp.pk, KeyVersion(1));
    let encryption_key = aead::generate_key();
    println!("  Batch ID:  {batch_id}");
    println!("  Tenant ID: {tenant_id}");

    // ── SAMPLING ENGINE ──────────────────────────────────────────

    println!();
    println!(
        "\
========================================================
  SAMPLING ENGINE (Identity Zone — decides WHO gets WHAT)
========================================================"
    );
    println!();
    println!("The Sampling Engine manages the workforce roster, question");
    println!("assignments, frequency caps, and k-anonymity coarsening.");
    println!();

    println!("--- Building org hierarchy ---");
    println!();
    println!("  company");
    println!("    engineering");
    println!("      backend   (alice, bob, charlie, dave, eve)     — 5 people");
    println!("      frontend  (frank, grace)                       — 2 people");
    println!("    sales       (hank, iris, jack)                   — 3 people");
    println!();

    let mut engine = InMemorySamplingEngine::new(
        5, // k-anonymity threshold
        FrequencyPolicy {
            max_tokens_per_employee_per_batch: 1,
        },
    );
    engine.add_segment("company".into(), None);
    engine.add_segment("engineering".into(), Some("company".into()));
    engine.add_segment("backend".into(), Some("engineering".into()));
    engine.add_segment("frontend".into(), Some("engineering".into()));
    engine.add_segment("sales".into(), Some("company".into()));

    for name in ["alice", "bob", "charlie", "dave", "eve"] {
        engine.add_employee(EmployeeId(name.into()), vec!["backend".into()]);
    }
    for name in ["frank", "grace"] {
        engine.add_employee(EmployeeId(name.into()), vec!["frontend".into()]);
    }
    for name in ["hank", "iris", "jack"] {
        engine.add_employee(EmployeeId(name.into()), vec!["sales".into()]);
    }

    engine.add_batch(QuestionBatch {
        id: batch_id,
        question_text: QuestionText::from("How are you feeling about work today?"),
        response_type: ResponseType::Scale5,
        expiry: UnixTimestamp(u64::MAX),
    });
    engine.assign_all(&batch_id);

    println!("  k-anonymity threshold: 5");
    println!("  Frequency cap: 1 token per employee per batch");
    println!("  Question assigned to all 10 employees");

    // ── K-ANONYMITY COARSENING ────────────────────────────────────

    println!();
    println!("--- K-anonymity coarsening demo ---");
    println!();
    println!("  When an employee requests their questions, the Sampling Engine");
    println!(
        "  coarsens their segment labels so no group smaller than k={} is",
        5
    );
    println!("  identifiable in the response data.");
    println!();

    let alice_assignments = engine.assignments_for(&EmployeeId("alice".into()));
    let frank_assignments = engine.assignments_for(&EmployeeId("frank".into()));
    let hank_assignments = engine.assignments_for(&EmployeeId("hank".into()));

    println!(
        "  alice (backend, 5 people):   segments = {:?}",
        alice_assignments[0]
            .coarsened_segments
            .iter()
            .map(|s| &s.0)
            .collect::<Vec<_>>()
    );
    println!(
        "  frank (frontend, 2 people):  segments = {:?}  <-- coarsened up!",
        frank_assignments[0]
            .coarsened_segments
            .iter()
            .map(|s| &s.0)
            .collect::<Vec<_>>()
    );
    println!(
        "  hank  (sales, 3 people):     segments = {:?}  <-- coarsened up!",
        hank_assignments[0]
            .coarsened_segments
            .iter()
            .map(|s| &s.0)
            .collect::<Vec<_>>()
    );
    println!();
    println!("  backend (5 >= k=5): keeps \"backend\"");
    println!("  frontend (2 < k=5): walks up to \"engineering\" (7 people)");
    println!("  sales (3 < k=5):    walks up to \"company\" (10 people)");
    println!();
    println!("  The Signal zone NEVER receives \"frontend\" or \"sales\" —");
    println!("  k-anonymity is enforced at the data level, not the UI level.");

    // ── Wire up the TokenIssuer with the Sampling Engine ──────────

    let sampling_engine: Arc<dyn SamplingEngine> = Arc::new(engine);
    let issuer = TokenIssuer::with_sampling(key_store.clone(), sampling_engine.clone());
    let ledger = Arc::new(InMemoryLedger::new());
    let store: Arc<dyn pulse_signal::ResponseStore> = Arc::new(InMemoryStore::new());
    let collector = ResponseCollector::new(key_store, ledger, store.clone());

    println!();
    println!("Created Identity zone (TokenIssuer + SamplingEngine)");
    println!("Created Signal zone (ResponseCollector + InMemoryLedger + InMemoryStore)");

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
    println!("is \"alice\" (backend team).");
    println!();
    println!("A TOKEN is a cryptographic authorization claim that the client");
    println!("builds locally. It bundles the question batch ID, coarsened");
    println!("segments, expiry, and a random nonce. The client will ask the");
    println!("Token Issuer to BLIND-SIGN it — meaning the Issuer signs the");
    println!("token without seeing its contents. Later, the client submits");
    println!("the token + signature anonymously to the Signal zone, which");
    println!("can verify the signature (proving authorization) without");
    println!("knowing who the signer authorized.");
    println!();
    println!("The client received question + coarsened segment_vector from");
    println!("GET /question. Now it constructs a token with those segments.");

    // Step 1: Create token
    println!();
    println!("--- Step 1: Client creates a token payload ---");
    println!();

    let segment_vector = alice_assignments[0].coarsened_segments.clone();
    let token = TokenPayload {
        nonce: Nonce::random(),
        question_batch_id: batch_id,
        tenant_id,
        expiry: UnixTimestamp(u64::MAX),
        segment_vector: segment_vector.clone(),
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
    println!(
        "    segment_vector:     {:?}  (from Sampling Engine)",
        segment_vector.iter().map(|s| &s.0).collect::<Vec<_>>()
    );
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

    // Step 3: Token Issuer signs (with Sampling Engine authorization)
    println!();
    println!("--- Step 3: Token Issuer signs the blinded token ---");
    println!();

    let token_request = TokenRequest {
        blinded_token: BlindedToken(blinding_result.blind_message.0.clone()),
        question_batch_id: batch_id,
    };
    let employee = EmployeeId("alice".into());
    let token_response = issuer
        .sign_token(&tenant_id, &employee, &token_request)
        .expect("signing failed");

    println!("  [IDENTITY ZONE] TokenIssuer.sign_token(\"alice\", ...)");
    println!();
    println!("  Sampling Engine checks:");
    println!("    Employee assigned to batch?  YES");
    println!("    Frequency cap exceeded?      NO  (0 of 1 issued)");
    println!("    Batch expired?               NO");
    println!("    -> AUTHORIZED (issuance recorded: alice now at 1/1)");
    println!();
    println!("  What the Identity zone sees:");
    println!("    Employee ID:    \"alice\"                    <-- knows WHO");
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

    // ── FREQUENCY CAP ENFORCEMENT ─────────────────────────────────

    println!();
    println!(
        "\
========================================================
  SECURITY: Frequency Cap Enforcement
========================================================"
    );
    println!();
    println!("--- Alice requests a second token for the same batch ---");
    println!();

    let token2 = TokenPayload {
        nonce: Nonce::random(),
        question_batch_id: batch_id,
        tenant_id,
        expiry: UnixTimestamp(u64::MAX),
        segment_vector: segment_vector.clone(),
        attestation_class: AttestationClass::Personal,
        key_version: KeyVersion(1),
    };
    let token_bytes2 = token2.to_bytes();
    let blinding2 = blind_sig::blind(&pk, &token_bytes2.0).expect("blinding failed");
    let request2 = TokenRequest {
        blinded_token: BlindedToken(blinding2.blind_message.0.clone()),
        question_batch_id: batch_id,
    };

    let denial = issuer.sign_token(&tenant_id, &EmployeeId("alice".into()), &request2);
    assert!(denial.is_err());
    println!("  [IDENTITY ZONE] TokenIssuer.sign_token(\"alice\", ...)");
    println!();
    println!("  Sampling Engine checks:");
    println!("    Frequency cap exceeded?  YES (1 of 1 already issued)");
    println!("    -> DENIED: {}", denial.unwrap_err());
    println!();
    println!("  The Sampling Engine prevents alice from getting a second");
    println!("  token for the same batch. This is enforced BEFORE signing,");
    println!("  so no blind signature is produced.");

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
    println!("      ^ The UNBLINDED TokenPayload from Step 1 (serialized).");
    println!("        Contains batch_id, segments, expiry, nonce.");
    println!("        This is the first time the Signal zone sees the real token.");
    println!("    signature:         {} bytes", submit.signature.0.len());
    println!("      ^ The UNBLINDED signature from Step 4. Proves the Token");
    println!("        Issuer authorized this token — without revealing WHO.");
    println!("    msg_randomizer:    (from blinding process, needed for verification)");
    println!("    key_version:       1  (which signing key to verify against)");
    println!("    question_batch_id: {batch_id}");
    println!("    tenant_id:         {tenant_id}");
    println!("      ^ Echoed from the token for quick validation before full");
    println!("        deserialization.");
    println!(
        "    response_blob:     {} bytes (encrypted)",
        submit.response_blob.0.len()
    );
    println!("      ^ Encrypted response from Step 5. The Signal zone stores");
    println!("        this as opaque bytes — it cannot read the content.");
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

    // ── ENVELOPE ENCRYPTION ─────────────────────────────────

    println!();
    println!(
        "\
========================================================
  MULTI-TENANCY: Envelope Encryption
========================================================"
    );
    println!();
    println!("Pulse uses two-tier envelope encryption so the platform");
    println!("operator never sees plaintext data.");
    println!();

    let cmk: Arc<dyn CmkProvider> = Arc::new(DevCmkProvider::new());
    let dek_store: Arc<dyn DekStore> = Arc::new(InMemoryDekStore::new());

    // Generate and wrap a DEK for this tenant
    let dek = aead::generate_key();
    let wrapped_dek = cmk.wrap_dek(&tenant_id, &dek).expect("wrap failed");
    dek_store.store_wrapped_dek(&tenant_id, DekDomain::Responses, wrapped_dek);

    println!("  Generated DEK-responses for tenant {tenant_id}");
    println!("  Wrapped DEK under CMK (tenant-held master key)");
    println!("  Only the wrapped DEK is stored — plaintext DEK discarded");
    println!();

    // Create an encrypting store that wraps the base store
    let base_store: Arc<dyn ResponseStore> = Arc::new(InMemoryStore::new());
    let encrypting_store =
        EncryptingResponseStore::new(base_store.clone(), dek_store.clone(), cmk.clone());

    // Store a response through the encrypting store
    let test_blob = EncryptedBlob(b"sensitive-response-data".to_vec());
    encrypting_store.store(pulse_signal::StoredResponse {
        encrypted_blob: test_blob.clone(),
        question_batch_id: batch_id,
        tenant_id,
        received_at: UnixTimestamp::now(),
    });

    // The base store holds DIFFERENT bytes (doubly encrypted)
    let raw = base_store.list();
    assert_ne!(raw[0].encrypted_blob.0, test_blob.0);
    println!("  Stored response through EncryptingResponseStore");
    println!(
        "  Inner store blob: {} bytes (doubly encrypted)",
        raw[0].encrypted_blob.0.len()
    );
    println!("  Original blob:    {} bytes", test_blob.0.len());
    println!("  Operator sees only ciphertext — zero knowledge");
    println!();

    // Reading through the encrypting store decrypts transparently
    let decrypted_list = encrypting_store.list();
    assert_eq!(decrypted_list[0].encrypted_blob.0, test_blob.0);
    println!("  Reading through EncryptingResponseStore: original blob recovered");

    // ── CRYPTO-SHREDDING ──────────────────────────────────────

    println!();
    println!(
        "\
========================================================
  MULTI-TENANCY: Crypto-Shredding
========================================================"
    );
    println!();
    println!("--- Tenant deletes their CMK (or we delete wrapped DEKs) ---");
    println!();

    dek_store.delete_tenant(&tenant_id);
    println!("  Deleted wrapped DEKs for tenant {tenant_id}");
    println!();

    let shredded = encrypting_store.list();
    // The blob is returned as-is (still encrypted) — graceful degradation
    assert_eq!(shredded[0].encrypted_blob.0, raw[0].encrypted_blob.0);
    println!("  Attempting to read stored response...");
    println!("  DEK unwrap failed — blob returned still encrypted");
    println!("  Data is cryptographic garbage without the DEK");
    println!();
    println!("  This is crypto-shredding: delete the key, and all data");
    println!("  encrypted under it becomes permanently irrecoverable.");

    // ── ANALYTICS ENGINE ──────────────────────────────────────

    println!();
    println!(
        "\
========================================================
  ANALYTICS: Pseudonyms and Longitudinal Tracking
========================================================"
    );
    println!();
    println!("Pulse supports longitudinal sentiment tracking via stable");
    println!("anonymous pseudonyms. The client derives a pseudonym from a");
    println!("local secret, embeds it in the encrypted response payload,");
    println!("and the Analytics Engine aggregates by segment + pseudonym.");
    println!();

    // Set up analytics infrastructure
    let analytics_cmk: Arc<dyn CmkProvider> = Arc::new(DevCmkProvider::new());
    let analytics_dek_store: Arc<dyn DekStore> = Arc::new(InMemoryDekStore::new());
    let analytics_tenant_id = TenantId::new();

    let analytics_dek = aead::generate_key();
    let wrapped_analytics = analytics_cmk
        .wrap_dek(&analytics_tenant_id, &analytics_dek)
        .expect("wrap failed");
    analytics_dek_store.store_wrapped_dek(
        &analytics_tenant_id,
        DekDomain::Analytics,
        wrapped_analytics,
    );

    println!("--- Pseudonym derivation (client-side) ---");
    println!();

    let employee_secret = pseudonym::generate_employee_secret();
    let epoch_config = EpochConfig::default();
    let epoch_id = epoch_config.current_epoch();
    let pseudonym_bytes = pseudonym::derive_pseudonym(
        &employee_secret,
        analytics_tenant_id.0.as_bytes(),
        epoch_id.0.as_bytes(),
    );

    println!(
        "  employee_secret:  {} (32 bytes, client-only)",
        hex_preview(&employee_secret)
    );
    println!("  epoch_id:         {epoch_id}");
    println!(
        "  pseudonym:        {} (HMAC-SHA256 output)",
        hex_preview(&pseudonym_bytes)
    );
    println!();
    println!("  The pseudonym is deterministic: same secret + tenant + epoch");
    println!("  always produces the same value. Different epochs produce");
    println!("  different pseudonyms (epoch rotation bounds correlation).");
    println!();

    // Create response payloads from multiple "employees"
    let analytics_store: Arc<dyn ResponseStore> = Arc::new(InMemoryStore::new());

    let analytics_batch = QuestionBatchId::new();
    for i in 0u8..5 {
        let secret = [i + 1; 32]; // different secret per "employee"
        let pseudo = pseudonym::derive_pseudonym(
            &secret,
            analytics_tenant_id.0.as_bytes(),
            epoch_id.0.as_bytes(),
        );
        let payload = ResponsePayload {
            pseudonym: Pseudonym(pseudo),
            epoch_id: epoch_id.clone(),
            response_type: ResponseType::Scale5,
            response_data: ResponseData::Scale5(i + 2), // scores: 2,3,4,5,6→clamped
            segment_vector: vec![SegmentLabel::from("engineering")],
        };
        let json = serde_json::to_vec(&payload).unwrap();
        let encrypted = aead::encrypt(&analytics_dek, &json).unwrap();

        analytics_store.store(pulse_signal::StoredResponse {
            encrypted_blob: EncryptedBlob(encrypted),
            question_batch_id: analytics_batch,
            tenant_id: analytics_tenant_id,
            received_at: UnixTimestamp::now(),
        });
    }

    println!("  Stored 5 encrypted response payloads (5 different pseudonyms)");
    println!();

    println!("--- Analytics Engine aggregation ---");
    println!();

    let engine = AnalyticsEngine::new(analytics_store, analytics_dek_store, analytics_cmk, 3);
    let aggregation = engine
        .aggregate_batch(&analytics_batch, &analytics_tenant_id)
        .expect("aggregation failed");

    println!("  BatchAggregation {{");
    println!("    total_responses:  {}", aggregation.total_responses);
    println!("    total_decrypted:  {}", aggregation.total_decrypted);
    println!("    total_failed:     {}", aggregation.total_failed);
    println!("    segments:");
    for seg in &aggregation.segments {
        println!("      {} {{", seg.segment_label.0);
        println!("        response_count:     {}", seg.response_count);
        println!("        unique_pseudonyms:  {}", seg.unique_pseudonyms);
        println!("        suppressed:         {}", seg.suppressed);
        if let Some(avg) = seg.average_score {
            println!("        average_score:      {avg:.1}");
        }
        println!("      }}");
    }
    println!("  }}");
    println!();
    println!("  The Analytics Engine decrypted all 5 blobs, grouped by segment,");
    println!("  and computed the average score. With k=3 and 5 unique pseudonyms,");
    println!("  the engineering segment is NOT suppressed.");

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

  5. FREQUENCY-CAPPED: The Sampling Engine limits token issuance per
                       employee per batch, preventing over-polling.

  6. K-ANONYMOUS: Segment labels are coarsened at issuance time so
                  no group smaller than k is identifiable in responses.

  7. TENANT-ISOLATED: Per-tenant blind-sig keypairs prevent cross-tenant
                      token reuse. Envelope encryption under tenant DEKs
                      ensures operator zero-knowledge.

  8. CRYPTO-SHREDDABLE: Deleting a tenant's keys makes all their data
                        permanently irrecoverable by design.

  9. LONGITUDINAL:  Stable pseudonyms enable tracking sentiment trends
                    over time without revealing identity.

 10. EPOCH-ROTATED: Pseudonyms change each epoch, bounding the window
                    for longitudinal correlation and reducing
                    re-identification risk.

  Run the full test suite to verify all properties:
    cargo test

========================================================"
    );
}
