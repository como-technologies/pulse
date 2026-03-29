//! End-to-end HTTP test exercising the full anonymous response flow
//! across both Identity and Signal zones using the real route handlers,
//! including analytics aggregation of response payloads.

use pulse_test_harness::start_test_servers;

use pulse_crypto::{aead, blind_sig};
use pulse_protocol::epoch::EpochConfig;
use pulse_protocol::messages::{
    QuestionDelivery, ResponseData, ResponsePayload, ResponseSubmit, ResponseType, TokenRequest,
    TokenResponse,
};
use pulse_protocol::token::{AttestationClass, TokenPayload};
use pulse_protocol::{
    BlindedToken, EncryptedBlob, KeyVersion, Nonce, Pseudonym, SegmentLabel, SignatureBytes,
    UnixTimestamp,
};
use serde_json::Value;

#[tokio::test]
async fn full_http_flow() {
    let servers = start_test_servers(true).await;
    let analytics_dek = servers.analytics_dek.unwrap();
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
    let encrypted_response = aead::encrypt(&analytics_dek, &payload_bytes).unwrap();

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
    let servers = start_test_servers(false).await;
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
    let servers = start_test_servers(false).await;
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
