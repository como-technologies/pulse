use std::collections::HashMap;
use std::sync::Mutex;

use pulse_identity::{EmployeeId, QuestionBatch, SamplingDecision, SamplingEngine, SamplingError};
use pulse_protocol::{QuestionBatchId, SegmentLabel};

/// Dev-only sampling engine that accepts any employee.
///
/// Returns a fixed question batch with a default segment for all employees,
/// skipping roster and assignment checks. Frequency caps are still enforced.
///
/// Selected via `PULSE_SAMPLING_PROVIDER=dev`. Not for production use.
pub struct DevSamplingEngine {
    batch: QuestionBatch,
    max_tokens_per_batch: u32,
    issuance_counts: Mutex<HashMap<(String, QuestionBatchId), u32>>,
}

impl DevSamplingEngine {
    pub fn new(batch: QuestionBatch, max_tokens_per_batch: u32) -> Self {
        Self {
            batch,
            max_tokens_per_batch,
            issuance_counts: Mutex::new(HashMap::new()),
        }
    }

    pub fn question_batch_id(&self) -> QuestionBatchId {
        self.batch.id
    }
}

impl SamplingEngine for DevSamplingEngine {
    fn assignments_for(&self, _employee_id: &EmployeeId) -> Vec<SamplingDecision> {
        tracing::info!("dev sampling: returning default assignment for any employee");
        vec![SamplingDecision {
            question_batch_id: self.batch.id,
            question_text: self.batch.question_text.clone(),
            response_type: self.batch.response_type.clone(),
            expiry: self.batch.expiry,
            coarsened_segments: vec![SegmentLabel::from("company")],
        }]
    }

    #[tracing::instrument(
        name = "DevSamplingEngine::authorize_and_record_issuance",
        skip(self),
        fields(question_batch_id = %question_batch_id)
    )]
    fn authorize_and_record_issuance(
        &self,
        employee_id: &EmployeeId,
        question_batch_id: &QuestionBatchId,
    ) -> Result<(), SamplingError> {
        // Dev mode skips roster/assignment checks but still enforces frequency caps
        let mut counts = self
            .issuance_counts
            .lock()
            .expect("dev sampling issuance counts lock poisoned");

        let key = (employee_id.0.clone(), *question_batch_id);
        let issued = counts.get(&key).copied().unwrap_or(0);
        if issued >= self.max_tokens_per_batch {
            tracing::warn!("dev sampling: frequency cap exceeded");
            return Err(SamplingError::FrequencyCapExceeded);
        }

        counts.insert(key, issued + 1);
        tracing::info!("dev sampling: issuance authorized");
        Ok(())
    }
}
