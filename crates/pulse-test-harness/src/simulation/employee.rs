use std::time::{Duration, Instant};

use pulse_client::transport::HttpTransport;
use pulse_client::{
    ConnectedClient, current_epoch, derive_pseudonym, encrypt_response, generate_employee_secret,
};
use pulse_protocol::messages::ResponseData;
use pulse_protocol::token::AttestationClass;
use pulse_protocol::{QuestionBatchId, TenantId};

/// The answers one simulated employee will give, keyed by question batch.
///
/// Sampled by the runner *before* tasks are spawned, in deterministic order,
/// so concurrency and completion order cannot influence a seeded run.
pub type ResponsePlan = Vec<(QuestionBatchId, ResponseData)>;

/// A simulated employee with credentials and a persistent secret.
pub struct SimulatedEmployee {
    pub employee_id: String,
    pub employee_secret: [u8; 32],
}

impl SimulatedEmployee {
    /// Create a new simulated employee with a random secret.
    pub fn new(employee_id: String) -> Self {
        Self {
            employee_id,
            employee_secret: generate_employee_secret(),
        }
    }
}

/// Which step of the protocol flow failed.
#[derive(Debug, Clone, serde::Serialize)]
pub enum FlowStep {
    Authenticate,
    FetchQuestions,
    BlindToken,
    RequestSignature,
    FinalizeToken,
    EncryptResponse,
    SubmitResponse,
}

/// Outcome of a single protocol flow.
#[derive(Debug, serde::Serialize)]
pub enum FlowOutcome {
    Success,
    Failed { step: FlowStep, error: String },
}

/// Per-operation timing for a single protocol flow.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FlowTimings {
    pub authenticate: Duration,
    pub fetch_questions: Duration,
    pub blind_and_sign: Duration,
    pub encrypt_and_submit: Duration,
    pub total: Duration,
}

/// Result of a single employee's protocol flow.
#[derive(Debug, serde::Serialize)]
pub struct FlowResult {
    pub employee_id: String,
    pub tenant_name: String,
    pub outcome: FlowOutcome,
    pub timings: FlowTimings,
}

impl SimulatedEmployee {
    /// Run the complete protocol flow: authenticate once, then answer every
    /// assigned question with its planned response (one token per batch).
    pub async fn run_flow<T: HttpTransport>(
        &self,
        client: ConnectedClient<T>,
        plan: &ResponsePlan,
        tenant_id: TenantId,
        analytics_dek: Option<&[u8; 32]>,
        tenant_name: &str,
    ) -> FlowResult {
        let flow_start = Instant::now();
        let mut timings = FlowTimings {
            authenticate: Duration::ZERO,
            fetch_questions: Duration::ZERO,
            blind_and_sign: Duration::ZERO,
            encrypt_and_submit: Duration::ZERO,
            total: Duration::ZERO,
        };

        macro_rules! timed {
            ($step:expr, $field:ident, $op:expr) => {{
                let start = Instant::now();
                match $op {
                    Ok(val) => {
                        timings.$field += start.elapsed();
                        val
                    }
                    Err(e) => {
                        timings.$field += start.elapsed();
                        timings.total = flow_start.elapsed();
                        return FlowResult {
                            employee_id: self.employee_id.clone(),
                            tenant_name: tenant_name.to_string(),
                            outcome: FlowOutcome::Failed {
                                step: $step,
                                error: e.to_string(),
                            },
                            timings,
                        };
                    }
                }
            }};
        }

        // Phase 1: Authenticate
        let session = timed!(
            FlowStep::Authenticate,
            authenticate,
            client.authenticate(&self.employee_id).await
        );

        // Phase 1: Fetch questions
        let questions = timed!(
            FlowStep::FetchQuestions,
            fetch_questions,
            client.fetch_questions(&session).await
        );

        // Stable pseudonym across all of this employee's answers
        let epoch_id = current_epoch();
        let pseudonym = derive_pseudonym(&self.employee_secret, &tenant_id, &epoch_id);

        // Use analytics DEK if available, otherwise generate a throwaway key
        let dek = analytics_dek
            .copied()
            .unwrap_or_else(pulse_crypto::aead::generate_key);

        // Answer every assigned question: blind, sign, finalize, encrypt, submit
        for question in &questions {
            let response_data = plan
                .iter()
                .find(|(batch_id, _)| *batch_id == question.question_batch_id)
                .map(|(_, data)| data.clone());
            let response_data = timed!(
                FlowStep::EncryptResponse,
                encrypt_and_submit,
                response_data.ok_or_else(|| format!(
                    "no planned response for batch {}",
                    question.question_batch_id
                ))
            );

            let blinded = timed!(
                FlowStep::BlindToken,
                blind_and_sign,
                client.blind_token(question, AttestationClass::Personal)
            );

            let signed = timed!(
                FlowStep::RequestSignature,
                blind_and_sign,
                client.request_signature(&session, blinded).await
            );

            let ready = timed!(
                FlowStep::FinalizeToken,
                blind_and_sign,
                client.finalize_token(signed)
            );

            let blob = timed!(
                FlowStep::EncryptResponse,
                encrypt_and_submit,
                encrypt_response(
                    &dek,
                    pseudonym,
                    epoch_id.clone(),
                    question.response_type.clone(),
                    response_data,
                    ready.token_payload().segment_vector.clone(),
                )
            );

            timed!(
                FlowStep::SubmitResponse,
                encrypt_and_submit,
                client.submit_response(&ready, blob).await
            );
        }

        timings.total = flow_start.elapsed();

        FlowResult {
            employee_id: self.employee_id.clone(),
            tenant_name: tenant_name.to_string(),
            outcome: FlowOutcome::Success,
            timings,
        }
    }
}
