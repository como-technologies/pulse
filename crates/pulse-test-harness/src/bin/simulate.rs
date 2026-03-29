//! CLI binary for running Pulse protocol simulations.
//!
//! Usage:
//!   cargo run -p pulse-test-harness --bin pulse-simulate
//!   cargo run -p pulse-test-harness --bin pulse-simulate -- --employees 100 --concurrency 50
//!   cargo run -p pulse-test-harness --bin pulse-simulate -- --stress

use pulse_protocol::messages::ResponseType;
use pulse_protocol::{QuestionText, SegmentLabel};

use pulse_test_harness::simulation::{
    QuestionBatchSetup, SimulationCluster, SimulationConfig, SimulationRunner, TenantSetup,
};

fn parse_args() -> SimulationConfig {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--stress") {
        return SimulationConfig {
            tenants: vec![
                make_tenant("Acme Corp", 500),
                make_tenant("Widgets Inc", 500),
                make_tenant("Gadgets Ltd", 500),
            ],
            concurrency: 200,
            with_analytics: true,
        };
    }

    let employees = find_arg(&args, "--employees").unwrap_or(10);
    let concurrency = find_arg(&args, "--concurrency").unwrap_or(10);
    let tenants_count = find_arg(&args, "--tenants").unwrap_or(1);

    let tenants = (0..tenants_count)
        .map(|i| make_tenant(&format!("Tenant-{i}"), employees))
        .collect();

    SimulationConfig {
        tenants,
        concurrency,
        with_analytics: true,
    }
}

fn make_tenant(name: &str, employee_count: usize) -> TenantSetup {
    TenantSetup {
        name: name.to_string(),
        employee_count,
        question_batches: vec![QuestionBatchSetup {
            question_text: QuestionText::from("How are you feeling about work today?"),
            response_type: ResponseType::Scale5,
            segment_labels: vec![SegmentLabel::from("company")],
        }],
        max_tokens_per_batch: 1,
    }
}

fn find_arg(args: &[String], flag: &str) -> Option<usize> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("pulse=info")
        .init();

    let config = parse_args();
    let total_employees: usize = config.tenants.iter().map(|t| t.employee_count).sum();

    println!(
        "Starting simulation: {} tenant(s), {} total employees, concurrency {}",
        config.tenants.len(),
        total_employees,
        config.concurrency,
    );

    let cluster = SimulationCluster::start(&config).await;
    let runner = SimulationRunner::new(cluster, config.concurrency);
    let report = runner.run().await;
    report.print_summary();

    std::process::exit(if report.failed == 0 { 0 } else { 1 });
}
