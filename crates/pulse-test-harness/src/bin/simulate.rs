//! CLI binary for running Pulse protocol simulations.
//!
//! Usage:
//!   cargo run -p pulse-test-harness --features reqwest-transport --bin pulse-simulate
//!   cargo run -p pulse-test-harness --features reqwest-transport --bin pulse-simulate -- \
//!       --employees 100 --concurrency 50
//!   cargo run -p pulse-test-harness --features reqwest-transport --bin pulse-simulate -- --stress
//!   cargo run -p pulse-test-harness --features reqwest-transport --bin pulse-simulate -- \
//!       --batch-file dogfood/iteration-retro.toml --seed 42 --k-threshold 5 \
//!       --json --out out/pulse-report.json

use pulse_protocol::messages::ResponseType;
use pulse_protocol::{QuestionText, SegmentLabel};

use pulse_test_harness::simulation::{
    QuestionBatchSetup, ResponseDistribution, SimulationCluster, SimulationConfig,
    SimulationRunner, SurveyFile, TenantSetup,
};

/// Where the report goes after the run.
struct OutputOptions {
    /// Print the report as JSON to stdout instead of the human summary.
    json: bool,
    /// Write the report as JSON to this path.
    out: Option<std::path::PathBuf>,
}

fn parse_args() -> (SimulationConfig, OutputOptions) {
    let args: Vec<String> = std::env::args().collect();

    let output = OutputOptions {
        json: args.iter().any(|a| a == "--json"),
        out: find_string_arg(&args, "--out").map(std::path::PathBuf::from),
    };

    let seed = find_string_arg(&args, "--seed").map(|v| {
        v.parse::<u64>().unwrap_or_else(|_| {
            eprintln!("error: --seed must be a u64, got {v:?}");
            std::process::exit(2);
        })
    });
    let k_threshold = find_arg(&args, "--k-threshold").unwrap_or(1);
    let employees = find_arg(&args, "--employees").unwrap_or(10);
    let concurrency = find_arg(&args, "--concurrency").unwrap_or(10);

    if let Some(path) = find_string_arg(&args, "--batch-file") {
        let survey = SurveyFile::load(std::path::Path::new(&path)).unwrap_or_else(|e| {
            eprintln!("error: {e}");
            std::process::exit(2);
        });
        let config = SimulationConfig {
            tenants: vec![survey.to_tenant_setup(employees, 1)],
            concurrency,
            with_analytics: true,
            k_threshold,
            seed,
        };
        return (config, output);
    }

    if args.iter().any(|a| a == "--stress") {
        let config = SimulationConfig {
            tenants: vec![
                make_tenant("Acme Corp", 500),
                make_tenant("Widgets Inc", 500),
                make_tenant("Gadgets Ltd", 500),
            ],
            concurrency: 200,
            with_analytics: true,
            k_threshold,
            seed,
        };
        return (config, output);
    }

    let tenants_count = find_arg(&args, "--tenants").unwrap_or(1);

    let tenants = (0..tenants_count)
        .map(|i| make_tenant(&format!("Tenant-{i}"), employees))
        .collect();

    let config = SimulationConfig {
        tenants,
        concurrency,
        with_analytics: true,
        k_threshold,
        seed,
    };
    (config, output)
}

fn make_tenant(name: &str, employee_count: usize) -> TenantSetup {
    TenantSetup {
        name: name.to_string(),
        employee_count,
        question_batches: vec![QuestionBatchSetup {
            question_text: QuestionText::from("How are you feeling about work today?"),
            response_type: ResponseType::Scale5,
            segment_labels: vec![SegmentLabel::from("company")],
            distribution: ResponseDistribution::ConstantScale5(4),
        }],
        max_tokens_per_batch: 1,
    }
}

fn find_arg(args: &[String], flag: &str) -> Option<usize> {
    find_string_arg(args, flag).and_then(|v| v.parse().ok())
}

fn find_string_arg(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("pulse=info")
        .with_writer(std::io::stderr)
        .init();

    let (config, output) = parse_args();
    let total_employees: usize = config.tenants.iter().map(|t| t.employee_count).sum();

    eprintln!(
        "Starting simulation: {} tenant(s), {} total employees, concurrency {}",
        config.tenants.len(),
        total_employees,
        config.concurrency,
    );

    let cluster = SimulationCluster::start(&config).await;
    let runner = SimulationRunner::new(cluster, config.concurrency, config.seed);
    let report = runner.run().await;
    let failed = report.failed;

    // Seeded runs produce the deterministic Measure artifact: wall-clock
    // fields are stripped so the same seed serializes byte-identically.
    let report = if config.seed.is_some() {
        report.without_timings()
    } else {
        report
    };

    let json = serde_json::to_string_pretty(&report).expect("report must serialize") + "\n";

    if let Some(path) = &output.out {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).expect("failed to create output directory");
        }
        std::fs::write(path, &json).expect("failed to write report");
        eprintln!("Report written to {}", path.display());
    }

    if output.json {
        print!("{json}");
    } else {
        report.print_summary();
    }

    std::process::exit(if failed == 0 { 0 } else { 1 });
}
