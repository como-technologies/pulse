//! Integration tests for seeded determinism and k-anonymity suppression (M-p4).
//!
//! Runs the full multi-zone cluster over real HTTP with a survey loaded from
//! TOML, seeded respondent sampling, and a configurable k threshold.

#![cfg(feature = "reqwest-transport")]

use pulse_test_harness::simulation::{
    SimulationCluster, SimulationConfig, SimulationReport, SimulationRunner, SurveyFile,
};

const RETRO_TOML: &str = r#"
name = "iteration-retro"

[[questions]]
text = "How confident are you that this iteration improved the portfolio?"
response_type = "scale5"
segments = ["company"]
weights = [0, 1, 2, 4, 3]

[[questions]]
text = "How sustainable is the current iteration pace?"
response_type = "scale5"
segments = ["company"]
weights = [1, 2, 3, 3, 1]
"#;

fn survey_config(employees: usize, k_threshold: usize, seed: u64) -> SimulationConfig {
    let survey = SurveyFile::parse(RETRO_TOML).unwrap();
    SimulationConfig {
        tenants: vec![survey.to_tenant_setup(employees, 1)],
        concurrency: employees,
        with_analytics: true,
        k_threshold,
        seed: Some(seed),
    }
}

async fn run(config: &SimulationConfig) -> SimulationReport {
    let cluster = SimulationCluster::start(config).await;
    let runner = SimulationRunner::new(cluster, config.concurrency, config.seed);
    runner.run().await
}

#[tokio::test]
async fn identical_seeds_yield_byte_identical_artifacts() {
    let config = survey_config(10, 5, 42);

    let first = run(&config).await;
    let second = run(&config).await;
    assert_eq!(first.failed, 0);
    assert_eq!(second.failed, 0);

    let first_json = serde_json::to_string_pretty(&first.without_timings()).unwrap();
    let second_json = serde_json::to_string_pretty(&second.without_timings()).unwrap();
    assert_eq!(
        first_json, second_json,
        "same seed must serialize byte-identically"
    );
}

#[tokio::test]
async fn different_seeds_yield_different_aggregates() {
    let first = run(&survey_config(10, 5, 42)).await;
    let second = run(&survey_config(10, 5, 1337)).await;

    let first_json = serde_json::to_string_pretty(&first.without_timings()).unwrap();
    let second_json = serde_json::to_string_pretty(&second.without_timings()).unwrap();
    assert_ne!(
        first_json, second_json,
        "different seeds must not collide (IDs differ at minimum)"
    );
}

#[tokio::test]
async fn k_suppression_triggers_when_respondents_below_threshold() {
    let report = run(&survey_config(3, 5, 7)).await;
    assert_eq!(report.failed, 0);
    assert_eq!(report.batches.len(), 2);

    for batch in &report.batches {
        assert_eq!(batch.aggregation.total_responses, 3);
        for segment in &batch.aggregation.segments {
            assert_eq!(segment.unique_pseudonyms, 3);
            assert!(
                segment.suppressed,
                "3 respondents < k=5 must suppress segment {:?}",
                segment.segment_label
            );
            assert_eq!(
                segment.average_score, None,
                "suppressed segments must not publish a score"
            );
        }
    }
}

#[tokio::test]
async fn k_threshold_met_publishes_average_score() {
    let report = run(&survey_config(10, 5, 7)).await;
    assert_eq!(report.failed, 0);
    assert_eq!(report.batches.len(), 2);

    for batch in &report.batches {
        assert_eq!(batch.aggregation.total_responses, 10);
        for segment in &batch.aggregation.segments {
            assert_eq!(segment.unique_pseudonyms, 10);
            assert!(
                !segment.suppressed,
                "10 respondents >= k=5 must not suppress segment {:?}",
                segment.segment_label
            );
            let score = segment
                .average_score
                .expect("unsuppressed segment must publish a score");
            assert!(
                (1.0..=5.0).contains(&score),
                "Scale5 average must be in range, got {score}"
            );
        }
    }
}
