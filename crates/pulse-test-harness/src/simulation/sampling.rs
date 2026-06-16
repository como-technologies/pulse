//! Simulation sampling engine: multiple question batches per tenant.
//!
//! The dev provider in `pulse-server` serves exactly one batch; the dogfood
//! survey needs one batch per retro question, so the harness brings its own
//! `SamplingEngine`. Accepts any employee (no roster) but still enforces
//! per-batch frequency caps.

use std::collections::HashMap;
use std::sync::Mutex;

use pulse_identity::{EmployeeId, QuestionBatch, SamplingDecision, SamplingEngine, SamplingError};
use pulse_protocol::{QuestionBatchId, SegmentLabel};

/// One provisioned batch plus the segment labels every respondent reports.
pub struct SimBatch {
    pub batch: QuestionBatch,
    pub segment_labels: Vec<SegmentLabel>,
}

/// Multi-batch sampling engine for the simulation harness.
pub struct SimSamplingEngine {
    batches: Vec<SimBatch>,
    max_tokens_per_batch: u32,
    issuance_counts: Mutex<HashMap<(String, QuestionBatchId), u32>>,
}

impl SimSamplingEngine {
    pub fn new(batches: Vec<SimBatch>, max_tokens_per_batch: u32) -> Self {
        Self {
            batches,
            max_tokens_per_batch,
            issuance_counts: Mutex::new(HashMap::new()),
        }
    }
}

impl SamplingEngine for SimSamplingEngine {
    fn assignments_for(&self, _employee_id: &EmployeeId) -> Vec<SamplingDecision> {
        self.batches
            .iter()
            .map(|b| SamplingDecision {
                question_batch_id: b.batch.id,
                question_text: b.batch.question_text.clone(),
                response_type: b.batch.response_type.clone(),
                expiry: b.batch.expiry,
                coarsened_segments: b.segment_labels.clone(),
            })
            .collect()
    }

    fn authorize_and_record_issuance(
        &self,
        employee_id: &EmployeeId,
        question_batch_id: &QuestionBatchId,
    ) -> Result<(), SamplingError> {
        if !self
            .batches
            .iter()
            .any(|b| b.batch.id == *question_batch_id)
        {
            return Err(SamplingError::NotAssigned);
        }

        let mut counts = self
            .issuance_counts
            .lock()
            .expect("sim sampling issuance counts lock poisoned");

        let key = (employee_id.0.clone(), *question_batch_id);
        let issued = counts.get(&key).copied().unwrap_or(0);
        if issued >= self.max_tokens_per_batch {
            return Err(SamplingError::FrequencyCapExceeded);
        }

        counts.insert(key, issued + 1);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pulse_protocol::messages::ResponseType;
    use pulse_protocol::{QuestionText, UnixTimestamp};

    fn make_batch(text: &str, segment: &str) -> SimBatch {
        SimBatch {
            batch: QuestionBatch {
                id: QuestionBatchId::new(),
                question_text: QuestionText::from(text),
                response_type: ResponseType::Scale5,
                expiry: UnixTimestamp(u64::MAX),
            },
            segment_labels: vec![SegmentLabel::from(segment)],
        }
    }

    #[test]
    fn assigns_every_batch_with_its_own_segments() {
        let engine = SimSamplingEngine::new(
            vec![make_batch("Q1?", "company"), make_batch("Q2?", "team")],
            1,
        );
        let decisions = engine.assignments_for(&EmployeeId("emp-0".into()));
        assert_eq!(decisions.len(), 2);
        assert_eq!(decisions[0].question_text.0, "Q1?");
        assert_eq!(decisions[0].coarsened_segments, vec!["company".into()]);
        assert_eq!(decisions[1].question_text.0, "Q2?");
        assert_eq!(decisions[1].coarsened_segments, vec!["team".into()]);
    }

    #[test]
    fn enforces_frequency_cap_per_batch_independently() {
        let batches = vec![make_batch("Q1?", "company"), make_batch("Q2?", "company")];
        let first_id = batches[0].batch.id;
        let second_id = batches[1].batch.id;
        let engine = SimSamplingEngine::new(batches, 1);
        let emp = EmployeeId("emp-0".into());

        assert!(
            engine
                .authorize_and_record_issuance(&emp, &first_id)
                .is_ok()
        );
        assert!(matches!(
            engine.authorize_and_record_issuance(&emp, &first_id),
            Err(SamplingError::FrequencyCapExceeded)
        ));
        // The second batch has its own counter.
        assert!(
            engine
                .authorize_and_record_issuance(&emp, &second_id)
                .is_ok()
        );
    }

    #[test]
    fn rejects_unknown_batch() {
        let engine = SimSamplingEngine::new(vec![make_batch("Q1?", "company")], 1);
        assert!(matches!(
            engine.authorize_and_record_issuance(
                &EmployeeId("emp-0".into()),
                &QuestionBatchId::new()
            ),
            Err(SamplingError::NotAssigned)
        ));
    }
}
