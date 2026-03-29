use pulse_protocol::messages::ResponseType;
use pulse_protocol::{QuestionText, SegmentLabel};

/// Configuration for a question batch in the simulation.
pub struct QuestionBatchSetup {
    pub question_text: QuestionText,
    pub response_type: ResponseType,
    pub segment_labels: Vec<SegmentLabel>,
}

/// Configuration for a simulated tenant (company).
pub struct TenantSetup {
    pub name: String,
    pub employee_count: usize,
    pub question_batches: Vec<QuestionBatchSetup>,
    pub max_tokens_per_batch: u32,
}

/// Top-level simulation configuration.
pub struct SimulationConfig {
    pub tenants: Vec<TenantSetup>,
    /// Maximum number of simultaneous protocol flows.
    pub concurrency: usize,
    /// Provision analytics infrastructure for post-run verification.
    pub with_analytics: bool,
}
