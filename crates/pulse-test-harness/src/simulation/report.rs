use std::time::Duration;

use serde::Serialize;

use pulse_server::analytics::BatchAggregation;

use super::employee::{FlowOutcome, FlowResult, FlowTimings};

/// Percentile statistics for a timing measurement.
#[derive(Debug, Clone, Serialize)]
pub struct PercentileStats {
    pub p50: Duration,
    pub p90: Duration,
    pub p99: Duration,
    pub max: Duration,
}

/// Aggregate timing statistics across all flows.
#[derive(Debug, Clone, Serialize)]
pub struct AggregateTimings {
    pub authenticate: PercentileStats,
    pub fetch_questions: PercentileStats,
    pub blind_and_sign: PercentileStats,
    pub encrypt_and_submit: PercentileStats,
    pub total_flow: PercentileStats,
}

/// Per-tenant simulation results.
#[derive(Debug, Serialize)]
pub struct TenantReport {
    pub tenant_name: String,
    pub total_flows: usize,
    pub successful: usize,
    pub failed: usize,
    /// Wall-clock percentiles; `None` in deterministic Measure artifacts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timing: Option<AggregateTimings>,
}

/// One question batch's k-anonymous aggregate, embedded in the report.
#[derive(Debug, Serialize)]
pub struct BatchReport {
    pub tenant_name: String,
    pub question_text: String,
    pub aggregation: BatchAggregation,
}

/// Complete simulation results — serializes as the Measure artifact
/// (`pulse.measure-report/v1`).
#[derive(Debug, Serialize)]
pub struct SimulationReport {
    /// Artifact schema identifier.
    pub schema: &'static str,
    /// Honesty label: this is synthetic demo data, never a real survey.
    pub data_source: &'static str,
    /// RNG seed when the run was deterministic.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
    pub total_flows: usize,
    pub successful: usize,
    pub failed: usize,
    pub errors: Vec<FlowResult>,
    /// Wall-clock percentiles; `None` in deterministic Measure artifacts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timing: Option<AggregateTimings>,
    pub per_tenant: Vec<TenantReport>,
    /// Per-batch k-anonymous aggregations fetched from `/analytics/batch/{id}`.
    pub batches: Vec<BatchReport>,
    /// Wall-clock duration; `None` in deterministic Measure artifacts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<Duration>,
}

impl SimulationReport {
    /// Schema identifier for the serialized Measure artifact.
    pub const SCHEMA: &'static str = "pulse.measure-report/v1";

    /// Honesty label for the `data_source` field. Seeded runs additionally
    /// carry the `seed` field.
    pub const DATA_SOURCE: &'static str =
        "simulated respondents — synthetic demo data, not a real survey";

    /// Build a report from collected flow results.
    pub fn from_results(
        results: Vec<FlowResult>,
        duration: Duration,
        tenant_names: &[String],
    ) -> Self {
        let total_flows = results.len();
        let successful = results
            .iter()
            .filter(|r| matches!(r.outcome, FlowOutcome::Success))
            .count();
        let failed = total_flows - successful;

        let all_timings: Vec<&FlowTimings> = results
            .iter()
            .filter(|r| matches!(r.outcome, FlowOutcome::Success))
            .map(|r| &r.timings)
            .collect();

        let timing = compute_aggregate(&all_timings);

        let per_tenant = tenant_names
            .iter()
            .map(|name| {
                let tenant_results: Vec<&FlowResult> =
                    results.iter().filter(|r| &r.tenant_name == name).collect();
                let tenant_total = tenant_results.len();
                let tenant_successful = tenant_results
                    .iter()
                    .filter(|r| matches!(r.outcome, FlowOutcome::Success))
                    .count();
                let tenant_timings: Vec<&FlowTimings> = tenant_results
                    .iter()
                    .filter(|r| matches!(r.outcome, FlowOutcome::Success))
                    .map(|r| &r.timings)
                    .collect();

                TenantReport {
                    tenant_name: name.clone(),
                    total_flows: tenant_total,
                    successful: tenant_successful,
                    failed: tenant_total - tenant_successful,
                    timing: Some(compute_aggregate(&tenant_timings)),
                }
            })
            .collect();

        let errors = results
            .into_iter()
            .filter(|r| matches!(r.outcome, FlowOutcome::Failed { .. }))
            .collect();

        Self {
            schema: Self::SCHEMA,
            data_source: Self::DATA_SOURCE,
            seed: None,
            total_flows,
            successful,
            failed,
            errors,
            timing: Some(timing),
            per_tenant,
            batches: Vec::new(),
            duration: Some(duration),
        }
    }

    /// Strip wall-clock fields so the serialized artifact is deterministic.
    ///
    /// Used for seeded runs: same seed must yield a byte-identical report,
    /// and wall-clock timing is the only nondeterministic content.
    #[must_use]
    pub fn without_timings(mut self) -> Self {
        self.timing = None;
        self.duration = None;
        for tenant in &mut self.per_tenant {
            tenant.timing = None;
        }
        self
    }

    /// Print a human-readable summary to stdout.
    pub fn print_summary(&self) {
        println!("\n{}", "=".repeat(60));
        println!("  Pulse Protocol Simulation Report");
        println!("{}\n", "=".repeat(60));

        println!(
            "  Total flows: {}  |  Passed: {}  |  Failed: {}",
            self.total_flows, self.successful, self.failed
        );
        if let Some(duration) = self.duration {
            println!("  Wall-clock time: {duration:.2?}\n");
        }

        if self.successful > 0
            && let Some(timing) = &self.timing
        {
            println!("  Aggregate Timings (successful flows):");
            print_percentiles("    authenticate", &timing.authenticate);
            print_percentiles("    fetch_questions", &timing.fetch_questions);
            print_percentiles("    blind_and_sign", &timing.blind_and_sign);
            print_percentiles("    encrypt_submit", &timing.encrypt_and_submit);
            print_percentiles("    total_flow", &timing.total_flow);
        }

        for tenant in &self.per_tenant {
            println!(
                "\n  Tenant '{}': {} flows ({} passed, {} failed)",
                tenant.tenant_name, tenant.total_flows, tenant.successful, tenant.failed
            );
            if tenant.successful > 0
                && let Some(timing) = &tenant.timing
            {
                print_percentiles("    total_flow", &timing.total_flow);
            }
        }

        if !self.errors.is_empty() {
            println!("\n  First {} errors:", self.errors.len().min(10));
            for (i, err) in self.errors.iter().take(10).enumerate() {
                if let FlowOutcome::Failed { step, error } = &err.outcome {
                    println!(
                        "    {}. [{}] employee={} step={:?}: {}",
                        i + 1,
                        err.tenant_name,
                        err.employee_id,
                        step,
                        error,
                    );
                }
            }
        }

        println!();
    }
}

fn print_percentiles(label: &str, stats: &PercentileStats) {
    println!(
        "{label:<20} p50={:<8.2?} p90={:<8.2?} p99={:<8.2?} max={:.2?}",
        stats.p50, stats.p90, stats.p99, stats.max
    );
}

fn compute_aggregate(timings: &[&FlowTimings]) -> AggregateTimings {
    AggregateTimings {
        authenticate: percentiles_of(timings, |t| t.authenticate),
        fetch_questions: percentiles_of(timings, |t| t.fetch_questions),
        blind_and_sign: percentiles_of(timings, |t| t.blind_and_sign),
        encrypt_and_submit: percentiles_of(timings, |t| t.encrypt_and_submit),
        total_flow: percentiles_of(timings, |t| t.total),
    }
}

fn percentiles_of(timings: &[&FlowTimings], f: fn(&FlowTimings) -> Duration) -> PercentileStats {
    if timings.is_empty() {
        return PercentileStats {
            p50: Duration::ZERO,
            p90: Duration::ZERO,
            p99: Duration::ZERO,
            max: Duration::ZERO,
        };
    }

    let mut values: Vec<Duration> = timings.iter().map(|t| f(t)).collect();
    values.sort();

    let n = values.len();
    PercentileStats {
        p50: values[n * 50 / 100],
        p90: values[n * 90 / 100],
        p99: values[(n * 99 / 100).min(n - 1)],
        max: values[n - 1],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pulse_protocol::{QuestionBatchId, SegmentLabel, TenantId};
    use pulse_server::analytics::{BatchAggregation, SegmentAggregation};

    fn sample_aggregation() -> BatchAggregation {
        BatchAggregation {
            question_batch_id: QuestionBatchId::new(),
            tenant_id: TenantId::new(),
            total_responses: 10,
            total_decrypted: 10,
            total_failed: 0,
            segments: vec![SegmentAggregation {
                segment_label: SegmentLabel::from("company"),
                response_count: 10,
                unique_pseudonyms: 10,
                average_score: Some(3.8),
                suppressed: false,
            }],
        }
    }

    fn sample_report() -> SimulationReport {
        let mut report = SimulationReport::from_results(
            vec![],
            Duration::from_millis(5),
            &["dogfood".to_string()],
        );
        report.seed = Some(42);
        report.batches.push(BatchReport {
            tenant_name: "dogfood".to_string(),
            question_text: "How did the iteration go?".to_string(),
            aggregation: sample_aggregation(),
        });
        report
    }

    #[test]
    fn report_json_embeds_aggregation_with_average_score_and_suppressed() {
        let json = serde_json::to_value(sample_report()).unwrap();
        let agg = &json["batches"][0]["aggregation"];
        assert_eq!(agg["total_responses"], 10);
        assert_eq!(agg["segments"][0]["average_score"], 3.8);
        assert_eq!(agg["segments"][0]["suppressed"], false);
        assert_eq!(
            json["batches"][0]["question_text"],
            "How did the iteration go?"
        );
    }

    #[test]
    fn report_json_declares_schema_and_simulated_data_source() {
        let json = serde_json::to_value(sample_report()).unwrap();
        assert_eq!(json["schema"], SimulationReport::SCHEMA);
        assert_eq!(json["schema"], "pulse.measure-report/v1");
        let data_source = json["data_source"].as_str().unwrap();
        assert!(
            data_source.contains("simulated"),
            "data_source must label the artifact as simulated, got: {data_source}"
        );
    }

    #[test]
    fn deterministic_artifact_omits_wall_clock_fields() {
        let json = serde_json::to_value(sample_report().without_timings()).unwrap();
        assert!(json.get("timing").is_none());
        assert!(json.get("duration").is_none());
        assert!(json["per_tenant"][0].get("timing").is_none());
        assert_eq!(json["seed"], 42);
    }

    #[test]
    fn unseeded_report_includes_timing_and_omits_seed() {
        let mut report = sample_report();
        report.seed = None;
        let json = serde_json::to_value(&report).unwrap();
        assert!(json.get("timing").is_some());
        assert!(json.get("duration").is_some());
        assert!(json.get("seed").is_none());
    }
}
