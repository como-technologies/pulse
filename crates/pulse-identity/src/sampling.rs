use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use pulse_protocol::messages::ResponseType;
use pulse_protocol::{QuestionBatchId, QuestionText, SegmentLabel, UnixTimestamp};

use crate::EmployeeId;

// ── Domain types ──

/// A node in the organizational segment hierarchy.
/// Each node has a label and an optional parent, forming a forest of trees.
#[derive(Debug, Clone)]
pub struct SegmentNode {
    pub label: SegmentLabel,
    pub parent: Option<SegmentLabel>,
}

/// A question batch that can be assigned to employees.
#[derive(Debug, Clone)]
pub struct QuestionBatch {
    pub id: QuestionBatchId,
    pub question_text: QuestionText,
    pub response_type: ResponseType,
    pub expiry: UnixTimestamp,
}

/// The Sampling Engine's decision for a specific employee question assignment.
#[derive(Debug, Clone)]
pub struct SamplingDecision {
    pub question_batch_id: QuestionBatchId,
    pub question_text: QuestionText,
    pub response_type: ResponseType,
    pub expiry: UnixTimestamp,
    pub coarsened_segments: Vec<SegmentLabel>,
}

/// Frequency cap policy.
#[derive(Debug, Clone)]
pub struct FrequencyPolicy {
    pub max_tokens_per_employee_per_batch: u32,
}

// ── Error ──

#[derive(Debug, thiserror::Error)]
pub enum SamplingError {
    #[error("employee not assigned to batch")]
    NotAssigned,
    #[error("frequency cap exceeded")]
    FrequencyCapExceeded,
    #[error("batch expired")]
    BatchExpired,
}

// ── Trait ──

// ANCHOR: sampling_engine_trait
/// Sampling Engine — decides who gets which questions.
///
/// Lives in the Identity zone. Knows WHO is assigned to WHAT question.
/// Produces coarsened segment vectors for k-anonymity.
/// Enforces frequency caps on token issuance.
pub trait SamplingEngine: Send + Sync {
    /// Get question assignments for an employee (used by `GET /question`).
    /// Returns batches with coarsened segment vectors.
    /// Excludes expired batches and batches where the frequency cap is hit.
    fn assignments_for(&self, employee_id: &EmployeeId) -> Vec<SamplingDecision>;

    /// Atomically authorize issuance AND record it (used by `POST /token/sign`).
    ///
    /// Checks: assignment exists, frequency cap, batch not expired.
    /// On `Ok`, the issuance count is incremented. The check and increment
    /// are atomic to prevent TOCTOU double-issuance.
    fn authorize_and_record_issuance(
        &self,
        employee_id: &EmployeeId,
        question_batch_id: &QuestionBatchId,
    ) -> Result<(), SamplingError>;
}
// ANCHOR_END: sampling_engine_trait

// ── K-Anonymity Coarsening ──

/// Coarsen an employee's leaf segments for k-anonymity.
///
/// For each leaf segment, walks up the hierarchy until finding a segment
/// whose subtree contains at least `k` roster employees. Returns the
/// coarsened labels.
fn coarsen_segments(
    employee_segments: &[SegmentLabel],
    hierarchy: &HashMap<SegmentLabel, Option<SegmentLabel>>,
    roster: &HashMap<EmployeeId, Vec<SegmentLabel>>,
    k: usize,
) -> Vec<SegmentLabel> {
    employee_segments
        .iter()
        .map(|seg| coarsen_one(seg, hierarchy, roster, k))
        .collect()
}

/// Coarsen a single segment label by walking up the hierarchy.
fn coarsen_one(
    segment: &SegmentLabel,
    hierarchy: &HashMap<SegmentLabel, Option<SegmentLabel>>,
    roster: &HashMap<EmployeeId, Vec<SegmentLabel>>,
    k: usize,
) -> SegmentLabel {
    let mut current = segment.clone();
    loop {
        let count = count_employees_under(&current, hierarchy, roster);
        if count >= k {
            return current;
        }
        // Walk up to parent
        match hierarchy.get(&current).and_then(|p| p.clone()) {
            Some(parent) => current = parent,
            None => return current, // root reached, use it even if < k
        }
    }
}

/// Count the number of roster employees whose segments include `target`
/// or any descendant of `target` in the hierarchy.
fn count_employees_under(
    target: &SegmentLabel,
    hierarchy: &HashMap<SegmentLabel, Option<SegmentLabel>>,
    roster: &HashMap<EmployeeId, Vec<SegmentLabel>>,
) -> usize {
    let descendants = collect_descendants(target, hierarchy);
    roster
        .values()
        .filter(|segments| segments.iter().any(|s| descendants.contains(s)))
        .count()
}

/// Collect a segment and all its descendants in the hierarchy.
fn collect_descendants(
    target: &SegmentLabel,
    hierarchy: &HashMap<SegmentLabel, Option<SegmentLabel>>,
) -> HashSet<SegmentLabel> {
    let mut result = HashSet::new();
    result.insert(target.clone());
    // Find all segments whose ancestor chain includes target
    for label in hierarchy.keys() {
        if label == target {
            continue;
        }
        let mut current = label.clone();
        loop {
            if current == *target {
                result.insert(label.clone());
                break;
            }
            match hierarchy.get(&current).and_then(|p| p.clone()) {
                Some(parent) => current = parent,
                None => break,
            }
        }
    }
    result
}

// ── In-Memory Implementation ──

/// In-memory `SamplingEngine` with explicit roster/hierarchy/batch setup.
///
/// Used in tests and as the foundation for production-path implementations.
/// Requires explicit population via builder methods — no auto-enrollment.
pub struct InMemorySamplingEngine {
    /// Segment hierarchy: label -> optional parent label
    hierarchy: HashMap<SegmentLabel, Option<SegmentLabel>>,
    /// Roster: employee_id -> leaf segments
    roster: HashMap<EmployeeId, Vec<SegmentLabel>>,
    /// Active question batches
    batches: HashMap<QuestionBatchId, QuestionBatch>,
    /// Assignments: set of (employee_id, question_batch_id)
    assignments: HashSet<(EmployeeId, QuestionBatchId)>,
    /// Issuance counts: (employee_id, question_batch_id) -> count
    /// Behind a Mutex for interior mutability in the trait methods.
    issuance_counts: Mutex<HashMap<(EmployeeId, QuestionBatchId), u32>>,
    /// K-anonymity threshold
    k_threshold: usize,
    /// Frequency cap policy
    frequency_policy: FrequencyPolicy,
}

impl InMemorySamplingEngine {
    pub fn new(k_threshold: usize, frequency_policy: FrequencyPolicy) -> Self {
        Self {
            hierarchy: HashMap::new(),
            roster: HashMap::new(),
            batches: HashMap::new(),
            assignments: HashSet::new(),
            issuance_counts: Mutex::new(HashMap::new()),
            k_threshold,
            frequency_policy,
        }
    }

    /// Register a segment in the hierarchy.
    pub fn add_segment(&mut self, label: SegmentLabel, parent: Option<SegmentLabel>) {
        self.hierarchy.insert(label, parent);
    }

    /// Register an employee in the roster with their leaf segments.
    pub fn add_employee(&mut self, employee_id: EmployeeId, segments: Vec<SegmentLabel>) {
        self.roster.insert(employee_id, segments);
    }

    /// Register a question batch.
    pub fn add_batch(&mut self, batch: QuestionBatch) {
        self.batches.insert(batch.id, batch);
    }

    /// Assign an employee to a question batch.
    pub fn assign(&mut self, employee_id: &EmployeeId, question_batch_id: &QuestionBatchId) {
        self.assignments
            .insert((employee_id.clone(), *question_batch_id));
    }

    /// Assign every rostered employee to a question batch.
    pub fn assign_all(&mut self, question_batch_id: &QuestionBatchId) {
        let employee_ids: Vec<_> = self.roster.keys().cloned().collect();
        for eid in employee_ids {
            self.assignments.insert((eid, *question_batch_id));
        }
    }
}

impl SamplingEngine for InMemorySamplingEngine {
    fn assignments_for(&self, employee_id: &EmployeeId) -> Vec<SamplingDecision> {
        let counts = self
            .issuance_counts
            .lock()
            .expect("issuance counts lock poisoned");
        let now = UnixTimestamp::now();
        let employee_segments = self.roster.get(employee_id);

        self.assignments
            .iter()
            .filter(|(eid, _)| eid == employee_id)
            .filter_map(|(_, batch_id)| {
                let batch = self.batches.get(batch_id)?;

                // Exclude expired batches
                if batch.expiry.0 <= now.0 {
                    return None;
                }

                // Exclude frequency-capped batches
                let key = (employee_id.clone(), *batch_id);
                let issued = counts.get(&key).copied().unwrap_or(0);
                if issued >= self.frequency_policy.max_tokens_per_employee_per_batch {
                    return None;
                }

                let coarsened = match employee_segments {
                    Some(segs) => {
                        coarsen_segments(segs, &self.hierarchy, &self.roster, self.k_threshold)
                    }
                    None => vec![],
                };

                Some(SamplingDecision {
                    question_batch_id: *batch_id,
                    question_text: batch.question_text.clone(),
                    response_type: batch.response_type.clone(),
                    expiry: batch.expiry,
                    coarsened_segments: coarsened,
                })
            })
            .collect()
    }

    #[tracing::instrument(
        name = "InMemorySamplingEngine::authorize_and_record_issuance",
        skip(self),
        fields(question_batch_id = %question_batch_id)
    )]
    fn authorize_and_record_issuance(
        &self,
        employee_id: &EmployeeId,
        question_batch_id: &QuestionBatchId,
    ) -> Result<(), SamplingError> {
        // Check batch exists and is not expired
        let batch = self
            .batches
            .get(question_batch_id)
            .ok_or(SamplingError::NotAssigned)?;

        if batch.expiry.0 <= UnixTimestamp::now().0 {
            tracing::warn!("batch expired");
            return Err(SamplingError::BatchExpired);
        }

        // Check assignment exists
        let key = (employee_id.clone(), *question_batch_id);
        if !self.assignments.contains(&key) {
            tracing::warn!("employee not assigned to batch");
            return Err(SamplingError::NotAssigned);
        }

        // Atomically check frequency cap and record issuance
        let mut counts = self
            .issuance_counts
            .lock()
            .expect("issuance counts lock poisoned");

        let issued = counts.get(&key).copied().unwrap_or(0);
        if issued >= self.frequency_policy.max_tokens_per_employee_per_batch {
            tracing::warn!("frequency cap exceeded");
            return Err(SamplingError::FrequencyCapExceeded);
        }

        counts.insert(key, issued + 1);
        tracing::info!("issuance authorized and recorded");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_batch(id: QuestionBatchId) -> QuestionBatch {
        QuestionBatch {
            id,
            question_text: QuestionText::from("How are you?"),
            response_type: ResponseType::Scale5,
            expiry: UnixTimestamp(u64::MAX),
        }
    }

    fn make_expired_batch(id: QuestionBatchId) -> QuestionBatch {
        QuestionBatch {
            id,
            question_text: QuestionText::from("How are you?"),
            response_type: ResponseType::Scale5,
            expiry: UnixTimestamp(0),
        }
    }

    fn setup_hierarchy() -> InMemorySamplingEngine {
        // company
        //   engineering
        //     backend (alice, bob, charlie, dave, eve)
        //     frontend (frank, grace)
        //   sales (hank, iris, jack)
        let mut engine = InMemorySamplingEngine::new(
            5,
            FrequencyPolicy {
                max_tokens_per_employee_per_batch: 1,
            },
        );
        engine.add_segment("company".into(), None);
        engine.add_segment("engineering".into(), Some("company".into()));
        engine.add_segment("backend".into(), Some("engineering".into()));
        engine.add_segment("frontend".into(), Some("engineering".into()));
        engine.add_segment("sales".into(), Some("company".into()));

        for name in &["alice", "bob", "charlie", "dave", "eve"] {
            engine.add_employee(EmployeeId(name.to_string()), vec!["backend".into()]);
        }
        for name in &["frank", "grace"] {
            engine.add_employee(EmployeeId(name.to_string()), vec!["frontend".into()]);
        }
        for name in &["hank", "iris", "jack"] {
            engine.add_employee(EmployeeId(name.to_string()), vec!["sales".into()]);
        }

        engine
    }

    // ── Coarsening tests ──

    #[test]
    fn coarsen_large_segment_keeps_label() {
        let engine = setup_hierarchy();
        // backend has 5 people, k=5 → keeps "backend"
        let result = coarsen_segments(
            &[SegmentLabel::from("backend")],
            &engine.hierarchy,
            &engine.roster,
            5,
        );
        assert_eq!(result, vec![SegmentLabel::from("backend")]);
    }

    #[test]
    fn coarsen_small_segment_walks_up() {
        let engine = setup_hierarchy();
        // sales has 3 people, k=5 → walks up to "company" (10 people)
        let result = coarsen_segments(
            &[SegmentLabel::from("sales")],
            &engine.hierarchy,
            &engine.roster,
            5,
        );
        assert_eq!(result, vec![SegmentLabel::from("company")]);
    }

    #[test]
    fn coarsen_walks_multiple_levels() {
        let engine = setup_hierarchy();
        // frontend has 2 people, k=5 → walks to "engineering" (7 people)
        let result = coarsen_segments(
            &[SegmentLabel::from("frontend")],
            &engine.hierarchy,
            &engine.roster,
            5,
        );
        assert_eq!(result, vec![SegmentLabel::from("engineering")]);
    }

    #[test]
    fn coarsen_root_used_when_all_small() {
        let engine = setup_hierarchy();
        // k=100 → even company (10 people) is too small, but root is returned anyway
        let result = coarsen_segments(
            &[SegmentLabel::from("backend")],
            &engine.hierarchy,
            &engine.roster,
            100,
        );
        assert_eq!(result, vec![SegmentLabel::from("company")]);
    }

    #[test]
    fn coarsen_multiple_segments_independently() {
        let engine = setup_hierarchy();
        // Employee in both backend (5, ok at k=5) and frontend (2, walks up)
        let result = coarsen_segments(
            &[
                SegmentLabel::from("backend"),
                SegmentLabel::from("frontend"),
            ],
            &engine.hierarchy,
            &engine.roster,
            5,
        );
        assert_eq!(
            result,
            vec![
                SegmentLabel::from("backend"),
                SegmentLabel::from("engineering")
            ]
        );
    }

    // ── Frequency cap tests ──

    #[test]
    fn frequency_cap_allows_first_issuance() {
        let mut engine = setup_hierarchy();
        let batch_id = QuestionBatchId::new();
        engine.add_batch(make_batch(batch_id));
        let alice = EmployeeId("alice".into());
        engine.assign(&alice, &batch_id);

        assert!(
            engine
                .authorize_and_record_issuance(&alice, &batch_id)
                .is_ok()
        );
    }

    #[test]
    fn frequency_cap_blocks_second_issuance() {
        let mut engine = setup_hierarchy();
        let batch_id = QuestionBatchId::new();
        engine.add_batch(make_batch(batch_id));
        let alice = EmployeeId("alice".into());
        engine.assign(&alice, &batch_id);

        engine
            .authorize_and_record_issuance(&alice, &batch_id)
            .unwrap();
        let err = engine
            .authorize_and_record_issuance(&alice, &batch_id)
            .unwrap_err();
        assert!(matches!(err, SamplingError::FrequencyCapExceeded));
    }

    // ── Authorization tests ──

    #[test]
    fn authorize_unassigned_employee_denied() {
        let mut engine = setup_hierarchy();
        let batch_id = QuestionBatchId::new();
        engine.add_batch(make_batch(batch_id));
        // alice is in roster but NOT assigned to this batch
        let alice = EmployeeId("alice".into());

        let err = engine
            .authorize_and_record_issuance(&alice, &batch_id)
            .unwrap_err();
        assert!(matches!(err, SamplingError::NotAssigned));
    }

    #[test]
    fn authorize_expired_batch_denied() {
        let mut engine = setup_hierarchy();
        let batch_id = QuestionBatchId::new();
        engine.add_batch(make_expired_batch(batch_id));
        let alice = EmployeeId("alice".into());
        engine.assign(&alice, &batch_id);

        let err = engine
            .authorize_and_record_issuance(&alice, &batch_id)
            .unwrap_err();
        assert!(matches!(err, SamplingError::BatchExpired));
    }

    // ── Assignment query tests ──

    #[test]
    fn assignments_returns_assigned_batches() {
        let mut engine = setup_hierarchy();
        let batch_id = QuestionBatchId::new();
        engine.add_batch(make_batch(batch_id));
        let alice = EmployeeId("alice".into());
        engine.assign(&alice, &batch_id);

        let assignments = engine.assignments_for(&alice);
        assert_eq!(assignments.len(), 1);
        assert_eq!(assignments[0].question_batch_id, batch_id);
    }

    #[test]
    fn assignments_exclude_already_issued() {
        let mut engine = setup_hierarchy();
        let batch_id = QuestionBatchId::new();
        engine.add_batch(make_batch(batch_id));
        let alice = EmployeeId("alice".into());
        engine.assign(&alice, &batch_id);

        engine
            .authorize_and_record_issuance(&alice, &batch_id)
            .unwrap();
        let assignments = engine.assignments_for(&alice);
        assert!(assignments.is_empty());
    }

    #[test]
    fn assignments_exclude_expired_batches() {
        let mut engine = setup_hierarchy();
        let batch_id = QuestionBatchId::new();
        engine.add_batch(make_expired_batch(batch_id));
        let alice = EmployeeId("alice".into());
        engine.assign(&alice, &batch_id);

        let assignments = engine.assignments_for(&alice);
        assert!(assignments.is_empty());
    }

    #[test]
    fn assignments_include_coarsened_segments() {
        let mut engine = setup_hierarchy();
        let batch_id = QuestionBatchId::new();
        engine.add_batch(make_batch(batch_id));
        // frank is in frontend (2 people), k=5 → coarsened to "engineering"
        let frank = EmployeeId("frank".into());
        engine.assign(&frank, &batch_id);

        let assignments = engine.assignments_for(&frank);
        assert_eq!(assignments.len(), 1);
        assert_eq!(
            assignments[0].coarsened_segments,
            vec![SegmentLabel::from("engineering")]
        );
    }

    #[test]
    fn assign_all_assigns_every_rostered_employee() {
        let mut engine = setup_hierarchy();
        let batch_id = QuestionBatchId::new();
        engine.add_batch(make_batch(batch_id));
        engine.assign_all(&batch_id);

        // All 10 employees should have the assignment
        for name in &[
            "alice", "bob", "charlie", "dave", "eve", "frank", "grace", "hank", "iris", "jack",
        ] {
            let assignments = engine.assignments_for(&EmployeeId(name.to_string()));
            assert_eq!(assignments.len(), 1, "expected 1 assignment for {name}");
        }
    }
}
