//! Integration test: full protocol flow using PulseClient against real HTTP servers.

mod common;

use pulse_client::{
    PulseClient, ReqwestTransport, current_epoch, derive_pseudonym, encrypt_response,
    generate_employee_secret,
};
use pulse_protocol::KeyVersion;
use pulse_protocol::messages::{ResponseData, ResponseType};
use pulse_protocol::token::AttestationClass;

#[tokio::test]
async fn full_flow_via_pulse_client() {
    let servers = common::start_test_servers(true).await;
    let analytics_dek = servers.analytics_dek.unwrap();

    let client = PulseClient::with_config(
        ReqwestTransport::new(),
        servers.identity_url.clone(),
        servers.signal_url.clone(),
        servers.pk.clone(),
        servers.tenant_id,
        KeyVersion(1),
    );

    // Phase 1: Authenticate
    let session = client.authenticate("employee-42").await.unwrap();

    // Phase 1: Fetch questions
    let questions = client.fetch_questions(&session).await.unwrap();
    assert_eq!(questions.len(), 1);
    assert_eq!(questions[0].question_batch_id, servers.batch_id);

    // Phase 1: Blind token
    let blinded = client
        .blind_token(&questions[0], AttestationClass::Personal)
        .unwrap();

    // Phase 1: Request signature
    let signed = client.request_signature(&session, blinded).await.unwrap();

    // Phase 1: Finalize (unblind)
    let ready = client.finalize_token(signed).unwrap();

    // Phase 2: Build encrypted response
    let employee_secret = generate_employee_secret();
    let epoch_id = current_epoch();
    let pseudonym = derive_pseudonym(&employee_secret, &servers.tenant_id, &epoch_id);

    let blob = encrypt_response(
        &analytics_dek,
        pseudonym,
        epoch_id,
        ResponseType::Scale5,
        ResponseData::Scale5(4),
        ready.token_payload().segment_vector.clone(),
    )
    .unwrap();

    // Phase 2: Submit anonymously
    client.submit_response(&ready, blob).await.unwrap();
}

#[tokio::test]
async fn duplicate_submission_rejected() {
    let servers = common::start_test_servers(false).await;

    let client = PulseClient::with_config(
        ReqwestTransport::new(),
        servers.identity_url.clone(),
        servers.signal_url.clone(),
        servers.pk.clone(),
        servers.tenant_id,
        KeyVersion(1),
    );

    let session = client.authenticate("employee-dup").await.unwrap();
    let questions = client.fetch_questions(&session).await.unwrap();
    let blinded = client
        .blind_token(&questions[0], AttestationClass::Personal)
        .unwrap();
    let signed = client.request_signature(&session, blinded).await.unwrap();
    let ready = client.finalize_token(signed).unwrap();

    let employee_secret = generate_employee_secret();
    let epoch_id = current_epoch();
    let pseudonym = derive_pseudonym(&employee_secret, &servers.tenant_id, &epoch_id);

    let dek = pulse_crypto::aead::generate_key();
    let blob = encrypt_response(
        &dek,
        pseudonym,
        epoch_id.clone(),
        ResponseType::Scale5,
        ResponseData::Scale5(3),
        ready.token_payload().segment_vector.clone(),
    )
    .unwrap();

    // First submission succeeds
    client.submit_response(&ready, blob).await.unwrap();

    // Second submission with same token should fail
    let blob2 = encrypt_response(
        &dek,
        pseudonym,
        epoch_id,
        ResponseType::Scale5,
        ResponseData::Scale5(3),
        ready.token_payload().segment_vector.clone(),
    )
    .unwrap();

    let result = client.submit_response(&ready, blob2).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        pulse_client::ClientError::ResponseRejected { code, .. } => {
            assert_eq!(code, "RESPONSE_TOKEN_ALREADY_SPENT");
        }
        other => panic!("expected ResponseRejected, got: {other}"),
    }
}

#[tokio::test]
async fn frequency_cap_enforced() {
    let servers = common::start_test_servers(false).await;

    let client = PulseClient::with_config(
        ReqwestTransport::new(),
        servers.identity_url.clone(),
        servers.signal_url.clone(),
        servers.pk.clone(),
        servers.tenant_id,
        KeyVersion(1),
    );

    let session = client.authenticate("employee-cap").await.unwrap();
    let questions = client.fetch_questions(&session).await.unwrap();

    // First token request succeeds
    let blinded1 = client
        .blind_token(&questions[0], AttestationClass::Personal)
        .unwrap();
    let _signed1 = client.request_signature(&session, blinded1).await.unwrap();

    // Second token request should be denied (frequency cap = 1)
    let blinded2 = client
        .blind_token(&questions[0], AttestationClass::Personal)
        .unwrap();
    let result = client.request_signature(&session, blinded2).await;
    let err = result.err().expect("expected token denial");
    match err {
        pulse_client::ClientError::TokenDenied { code, .. } => {
            assert_eq!(code, "TOKEN_DENIED_FREQUENCY_CAP");
        }
        other => panic!("expected TokenDenied, got: {other}"),
    }
}
