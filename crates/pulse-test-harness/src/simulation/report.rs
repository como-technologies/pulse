use std::time::Duration;

use super::employee::{FlowOutcome, FlowResult, FlowTimings};

/// Percentile statistics for a timing measurement.
#[derive(Debug, Clone)]
pub struct PercentileStats {
    pub p50: Duration,
    pub p90: Duration,
    pub p99: Duration,
    pub max: Duration,
}

/// Aggregate timing statistics across all flows.
#[derive(Debug, Clone)]
pub struct AggregateTimings {
    pub authenticate: PercentileStats,
    pub fetch_questions: PercentileStats,
    pub blind_and_sign: PercentileStats,
    pub encrypt_and_submit: PercentileStats,
    pub total_flow: PercentileStats,
}

/// Per-tenant simulation results.
#[derive(Debug)]
pub struct TenantReport {
    pub tenant_name: String,
    pub total_flows: usize,
    pub successful: usize,
    pub failed: usize,
    pub timing: AggregateTimings,
}

/// Complete simulation results.
#[derive(Debug)]
pub struct SimulationReport {
    pub total_flows: usize,
    pub successful: usize,
    pub failed: usize,
    pub errors: Vec<FlowResult>,
    pub timing: AggregateTimings,
    pub per_tenant: Vec<TenantReport>,
    pub duration: Duration,
}

impl SimulationReport {
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
                    timing: compute_aggregate(&tenant_timings),
                }
            })
            .collect();

        let errors = results
            .into_iter()
            .filter(|r| matches!(r.outcome, FlowOutcome::Failed { .. }))
            .collect();

        Self {
            total_flows,
            successful,
            failed,
            errors,
            timing,
            per_tenant,
            duration,
        }
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
        println!("  Wall-clock time: {:.2?}\n", self.duration);

        if self.successful > 0 {
            println!("  Aggregate Timings (successful flows):");
            print_percentiles("    authenticate", &self.timing.authenticate);
            print_percentiles("    fetch_questions", &self.timing.fetch_questions);
            print_percentiles("    blind_and_sign", &self.timing.blind_and_sign);
            print_percentiles("    encrypt_submit", &self.timing.encrypt_and_submit);
            print_percentiles("    total_flow", &self.timing.total_flow);
        }

        for tenant in &self.per_tenant {
            println!(
                "\n  Tenant '{}': {} flows ({} passed, {} failed)",
                tenant.tenant_name, tenant.total_flows, tenant.successful, tenant.failed
            );
            if tenant.successful > 0 {
                print_percentiles("    total_flow", &tenant.timing.total_flow);
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
