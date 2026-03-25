//! End-to-end HTTP test exercising the full anonymous response flow
//! across both Identity and Signal zones using the real route handlers,
//! including analytics aggregation of response payloads.

use std::sync::Arc;

use axum::{
    Router,
    routing::{get, post},
};
use serde_json::Value;
use tokio::net::TcpListener;

use pulse_crypto::{aead, blind_sig};
use pulse_identity::{InMemorySessionStore, QuestionBatch, SamplingEngine, TokenIssuer};
use pulse_protocol::epoch::EpochConfig;
use pulse_protocol::messages::{
    QuestionDelivery, ResponseData, ResponsePayload, ResponseSubmit, ResponseType, TokenRequest,
    TokenResponse,
};
use pulse_protocol::token::{AttestationClass, TokenPayload};
use pulse_protocol::{
    BlindedToken, EncryptedBlob, KeyVersion, Nonce, Pseudonym, QuestionBatchId, QuestionText,
    SegmentLabel, SignatureBytes, TenantId, UnixTimestamp,
};
use pulse_signal::{InMemoryLedger, InMemoryStore, ResponseCollector};

use pulse_server::analytics::AnalyticsEngine;
use pulse_server::cmk::CmkProvider;
use pulse_server::dek_store::{DekDomain, DekStore, InMemoryDekStore};
use pulse_server::dev_auth::DevAuthenticator;
use pulse_server::dev_cmk::DevCmkProvider;
use pulse_server::dev_sampling::DevSamplingEngine;
use pulse_server::dev_tenant_keys::InMemoryTenantKeyStore;
use pulse_server::{IdentityState, SignalState, analytics_routes, identity_routes, signal_routes};

struct TestServers {
    identity_url: String,
    signal_url: String,
    batch_id: QuestionBatchId,
    tenant_id: TenantId,
    pk: pulse_crypto::BrssPublicKey,
    analytics_dek: [u8; 32],
}

async fn start_test_servers() -> TestServers {
    let kp = blind_sig::generate_keypair().unwrap();
    let pk = kp.pk.clone();
    let tenant_id = TenantId::new();
    let key_store = Arc::new(InMemoryTenantKeyStore::new());
    key_store.register_tenant(tenant_id, kp.sk, kp.pk, KeyVersion(1));

    let ledger = Arc::new(InMemoryLedger::new());
    let store: Arc<dyn pulse_signal::ResponseStore> = Arc::new(InMemoryStore::new());

    let batch_id = QuestionBatchId::new();
    let batch = QuestionBatch {
        id: batch_id,
        question_text: QuestionText::from("How are you feeling about work today?"),
        response_type: ResponseType::Scale5,
        expiry: UnixTimestamp(u64::MAX),
    };
    let sampling_engine: Arc<dyn SamplingEngine> = Arc::new(DevSamplingEngine::new(batch, 1));

    // Provision analytics DEK for the tenant
    let cmk = Arc::new(DevCmkProvider::new());
    let dek_store = Arc::new(InMemoryDekStore::new());
    let analytics_dek = aead::generate_key();
    let wrapped = cmk.wrap_dek(&tenant_id, &analytics_dek).unwrap();
    dek_store.store_wrapped_dek(&tenant_id, DekDomain::Analytics, wrapped);

    let analytics = AnalyticsEngine::new(store.clone(), dek_store, cmk, 1);

    let identity_state = Arc::new(IdentityState {
        issuer: TokenIssuer::with_sampling(key_store.clone(), sampling_engine.clone()),
        authenticator: Arc::new(DevAuthenticator),
        session_store: Arc::new(InMemorySessionStore::new()),
        sampling_engine,
        tenant_id,
    });

    let signal_state = Arc::new(SignalState {
        collector: ResponseCollector::new(key_store, ledger, store.clone()),
        store,
        analytics: Some(analytics),
    });

    let identity_router = Router::new()
        .route("/auth", post(identity_routes::auth))
        .route("/question", get(identity_routes::get_questions))
        .route("/token/sign", post(identity_routes::sign_token))
        .with_state(identity_state);

    let signal_router = Router::new()
        .route("/response", post(signal_routes::submit_response))
        .route("/debug/responses", get(signal_routes::debug_responses))
        .route(
            "/analytics/batch/{batch_id}",
            get(analytics_routes::aggregate_batch),
        )
        .with_state(signal_state);

    // Bind to port 0 for random available ports
    let identity_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let signal_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

    let identity_addr = identity_listener.local_addr().unwrap();
    let signal_addr = signal_listener.local_addr().unwrap();

    tokio::spawn(axum::serve(identity_listener, identity_router).into_future());
    tokio::spawn(axum::serve(signal_listener, signal_router).into_future());

    TestServers {
        identity_url: format!("http://{identity_addr}"),
        signal_url: format!("http://{signal_addr}"),
        batch_id,
        tenant_id,
        pk,
        analytics_dek,
    }
}

#[tokio::test]
async fn full_http_flow() {
    let servers = start_test_servers().await;
    let client = reqwest::Client::new();

    // 1. Authenticate to get a session token
    let auth_resp: Value = client
        .post(format!("{}/auth", servers.identity_url))
        .json(&serde_json::json!({"api_key": "employee-42"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let session_token = auth_resp["session_token"].as_str().unwrap();

    // 2. Get questions from Identity zone (requires auth) — binary response
    let question_bytes = client
        .get(format!("{}/question", servers.identity_url))
        .header("Authorization", format!("Bearer {session_token}"))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let questions: Vec<QuestionDelivery> = postcard::from_bytes(&question_bytes).unwrap();
    assert_eq!(questions.len(), 1);
    assert_eq!(questions[0].question_batch_id, servers.batch_id);
    assert!(!questions[0].segment_vector.is_empty());

    // 3. Create and blind a token
    let token = TokenPayload {
        nonce: Nonce::random(),
        question_batch_id: servers.batch_id,
        tenant_id: servers.tenant_id,
        expiry: UnixTimestamp(u64::MAX),
        segment_vector: vec!["engineering".into()],
        attestation_class: AttestationClass::Personal,
        key_version: KeyVersion(1),
    };
    let token_bytes = token.to_bytes();

    let blinding_result = blind_sig::blind(&servers.pk, &token_bytes.0).unwrap();

    // 4. Request blind signature from Identity zone — binary request/response
    let token_request = TokenRequest {
        blinded_token: BlindedToken(blinding_result.blind_message.0.clone()),
        question_batch_id: servers.batch_id,
    };
    let sign_resp_bytes = client
        .post(format!("{}/token/sign", servers.identity_url))
        .header("Authorization", format!("Bearer {session_token}"))
        .body(postcard::to_allocvec(&token_request).unwrap())
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let token_response: TokenResponse = postcard::from_bytes(&sign_resp_bytes).unwrap();

    // 5. Unblind the signature
    let blind_sig_val = pulse_crypto::BlindSignature(token_response.blind_signature.0.clone());
    let sig = blind_sig::finalize(
        &servers.pk,
        &blind_sig_val,
        &blinding_result,
        &token_bytes.0,
    )
    .unwrap();

    // 6. Derive pseudonym and encrypt response payload
    let employee_secret = pulse_crypto::pseudonym::generate_employee_secret();
    let epoch_config = EpochConfig::default();
    let epoch_id = epoch_config.current_epoch();
    let pseudonym_bytes = pulse_crypto::pseudonym::derive_pseudonym(
        &employee_secret,
        servers.tenant_id.0.as_bytes(),
        epoch_id.0.as_bytes(),
    );
    let payload = ResponsePayload {
        pseudonym: Pseudonym(pseudonym_bytes),
        epoch_id,
        response_type: ResponseType::Scale5,
        response_data: ResponseData::Scale5(4),
        segment_vector: vec![SegmentLabel::from("engineering")],
    };
    let payload_bytes = postcard::to_allocvec(&payload).unwrap();
    let encrypted_response = aead::encrypt(&servers.analytics_dek, &payload_bytes).unwrap();

    // 7. Submit to Signal zone (different URL, NO auth) — binary request
    let submit = ResponseSubmit {
        token: token_bytes.clone(),
        signature: SignatureBytes(sig.0.clone()),
        msg_randomizer: blinding_result.msg_randomizer.map(|r| r.0),
        key_version: KeyVersion(1),
        question_batch_id: servers.batch_id,
        tenant_id: servers.tenant_id,
        response_blob: EncryptedBlob(encrypted_response.clone()),
    };
    let submit_resp = client
        .post(format!("{}/response", servers.signal_url))
        .body(postcard::to_allocvec(&submit).unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(submit_resp.status(), 200);

    // 8. Verify response is stored
    let debug: Value = client
        .get(format!("{}/debug/responses", servers.signal_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(debug["count"], 1);

    // 9. Query analytics endpoint
    let analytics: Value = client
        .get(format!(
            "{}/analytics/batch/{}?tenant_id={}",
            servers.signal_url, servers.batch_id.0, servers.tenant_id.0
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(analytics["total_responses"], 1);
    assert_eq!(analytics["total_decrypted"], 1);
    assert_eq!(analytics["total_failed"], 0);
    let segments = analytics["segments"].as_array().unwrap();
    assert_eq!(segments.len(), 1);
    assert_eq!(segments[0]["segment_label"], "engineering");
    assert_eq!(segments[0]["unique_pseudonyms"], 1);

    // 10. Duplicate submission should fail with 422 and structured error
    let dup_resp = client
        .post(format!("{}/response", servers.signal_url))
        .body(postcard::to_allocvec(&submit).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(dup_resp.status(), 422);
    let dup_body: Value = dup_resp.json().await.unwrap();
    assert_eq!(dup_body["code"], "RESPONSE_TOKEN_ALREADY_SPENT");
}

#[tokio::test]
async fn questions_include_segment_vector() {
    let servers = start_test_servers().await;
    let client = reqwest::Client::new();

    // Authenticate
    let auth_resp: Value = client
        .post(format!("{}/auth", servers.identity_url))
        .json(&serde_json::json!({"api_key": "employee-99"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let session_token = auth_resp["session_token"].as_str().unwrap();

    // Get questions — should include segment_vector (binary response)
    let question_bytes = client
        .get(format!("{}/question", servers.identity_url))
        .header("Authorization", format!("Bearer {session_token}"))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let questions: Vec<QuestionDelivery> = postcard::from_bytes(&question_bytes).unwrap();

    assert_eq!(questions.len(), 1);
    assert_eq!(questions[0].question_batch_id, servers.batch_id);
    assert!(!questions[0].segment_vector.is_empty());
    assert_eq!(
        questions[0].segment_vector[0],
        SegmentLabel::from("company")
    );
}

#[tokio::test]
async fn sign_denied_frequency_cap() {
    let servers = start_test_servers().await;
    let client = reqwest::Client::new();

    // Authenticate
    let auth_resp: Value = client
        .post(format!("{}/auth", servers.identity_url))
        .json(&serde_json::json!({"api_key": "employee-cap-test"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let session_token = auth_resp["session_token"].as_str().unwrap();

    // First signing request — should succeed (binary request)
    let token1 = TokenPayload {
        nonce: Nonce::random(),
        question_batch_id: servers.batch_id,
        tenant_id: servers.tenant_id,
        expiry: UnixTimestamp(u64::MAX),
        segment_vector: vec!["company".into()],
        attestation_class: AttestationClass::Personal,
        key_version: KeyVersion(1),
    };
    let token_bytes1 = token1.to_bytes();
    let blinding1 = blind_sig::blind(&servers.pk, &token_bytes1.0).unwrap();

    let req1 = TokenRequest {
        blinded_token: BlindedToken(blinding1.blind_message.0.clone()),
        question_batch_id: servers.batch_id,
    };
    let resp1 = client
        .post(format!("{}/token/sign", servers.identity_url))
        .header("Authorization", format!("Bearer {session_token}"))
        .body(postcard::to_allocvec(&req1).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(resp1.status(), 200);

    // Second signing request — should be denied (frequency cap = 1)
    let token2 = TokenPayload {
        nonce: Nonce::random(),
        question_batch_id: servers.batch_id,
        tenant_id: servers.tenant_id,
        expiry: UnixTimestamp(u64::MAX),
        segment_vector: vec!["company".into()],
        attestation_class: AttestationClass::Personal,
        key_version: KeyVersion(1),
    };
    let token_bytes2 = token2.to_bytes();
    let blinding2 = blind_sig::blind(&servers.pk, &token_bytes2.0).unwrap();

    let req2 = TokenRequest {
        blinded_token: BlindedToken(blinding2.blind_message.0.clone()),
        question_batch_id: servers.batch_id,
    };
    let resp2 = client
        .post(format!("{}/token/sign", servers.identity_url))
        .header("Authorization", format!("Bearer {session_token}"))
        .body(postcard::to_allocvec(&req2).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(resp2.status(), 403);
    let body: Value = resp2.json().await.unwrap();
    assert_eq!(body["code"], "TOKEN_DENIED_FREQUENCY_CAP");
}
