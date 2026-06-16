//! Integration tests for the machine-readable Measure artifact (M-p3).
//!
//! Runs the full multi-zone cluster over real HTTP and asserts the report
//! embeds per-batch `BatchAggregation` fetched from `/analytics/batch/{id}`.

#![cfg(feature = "reqwest-transport")]

use pulse_protocol::QuestionText;
use pulse_protocol::messages::ResponseType;
use pulse_test_harness::simulation::{
    QuestionBatchSetup, ResponseDistribution, SimulationCluster, SimulationConfig,
    SimulationRunner, TenantSetup,
};

fn config(employees: usize) -> SimulationConfig {
    SimulationConfig {
        tenants: vec![TenantSetup {
            name: "dogfood".to_string(),
            employee_count: employees,
            question_batches: vec![QuestionBatchSetup {
                question_text: QuestionText::from("How are you feeling about work today?"),
                response_type: ResponseType::Scale5,
                segment_labels: vec!["company".into()],
                distribution: ResponseDistribution::ConstantScale5(4),
            }],
            max_tokens_per_batch: 1,
        }],
        concurrency: employees,
        with_analytics: true,
        k_threshold: 1,
        seed: None,
    }
}

#[tokio::test]
async fn report_embeds_batch_aggregation_fetched_over_http() {
    let config = config(4);
    let cluster = SimulationCluster::start(&config).await;
    let runner = SimulationRunner::new(cluster, config.concurrency, config.seed);
    let report = runner.run().await;

    assert_eq!(report.failed, 0, "all flows must succeed");
    assert_eq!(report.batches.len(), 1, "one batch aggregation embedded");

    let batch = &report.batches[0];
    assert_eq!(batch.tenant_name, "dogfood");
    assert_eq!(batch.question_text, "How are you feeling about work today?");
    assert_eq!(batch.aggregation.total_responses, 4);
    assert_eq!(batch.aggregation.total_decrypted, 4);

    // The serialized artifact must expose average_score and suppressed.
    let json = serde_json::to_value(&report).unwrap();
    let segment = &json["batches"][0]["aggregation"]["segments"][0];
    assert!(
        segment.get("average_score").is_some(),
        "segment must contain average_score: {segment}"
    );
    assert!(
        segment.get("suppressed").is_some(),
        "segment must contain suppressed: {segment}"
    );
}
