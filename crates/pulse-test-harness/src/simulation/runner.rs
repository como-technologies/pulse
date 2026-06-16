use super::cluster::SimulationCluster;

/// Salt so respondent sampling and cluster ID generation use distinct
/// deterministic streams derived from the same user-facing seed.
const SAMPLING_SEED_SALT: u64 = 0x9E37_79B9_7F4A_7C15;

/// Orchestrates concurrent protocol flows across all tenants.
#[allow(dead_code)] // Fields read inside #[cfg(feature = "reqwest-transport")]
pub struct SimulationRunner {
    cluster: SimulationCluster,
    concurrency: usize,
    seed: Option<u64>,
}

impl SimulationRunner {
    pub fn new(cluster: SimulationCluster, concurrency: usize, seed: Option<u64>) -> Self {
        Self {
            cluster,
            concurrency,
            seed,
        }
    }

    /// Run all employees across all tenants concurrently.
    #[cfg(feature = "reqwest-transport")]
    pub async fn run(&self) -> super::report::SimulationReport {
        use std::time::Instant;

        use tokio::sync::{Semaphore, mpsc};

        use pulse_client::{ConnectedClient, ReqwestTransport};

        use super::cluster::make_rng;
        use super::employee::{FlowResult, ResponsePlan, SimulatedEmployee};
        use super::report::SimulationReport;

        let start = Instant::now();
        let semaphore = std::sync::Arc::new(Semaphore::new(self.concurrency));
        let (tx, mut rx) = mpsc::unbounded_channel::<FlowResult>();

        // Respondent answers are sampled HERE, in deterministic loop order,
        // before any task spawns: completion order cannot affect a seeded run.
        let mut sampling_rng = make_rng(self.seed.map(|s| s ^ SAMPLING_SEED_SALT));

        let mut total_tasks = 0;

        for tenant in &self.cluster.tenants {
            for emp_idx in 0..tenant.employee_count {
                let employee =
                    SimulatedEmployee::new(format!("{}-employee-{emp_idx}", tenant.name));

                let plan: ResponsePlan = tenant
                    .batches
                    .iter()
                    .map(|batch| (batch.id, batch.distribution.sample(&mut sampling_rng)))
                    .collect();

                let identity_url = tenant.identity_url.clone();
                let signal_url = tenant.signal_url.clone();
                let pk = tenant.pk.clone();
                let tenant_id = tenant.tenant_id;
                let key_version = tenant.key_version;
                let analytics_dek = tenant.analytics_dek;
                let tenant_name = tenant.name.clone();
                let permit = semaphore.clone();
                let tx = tx.clone();

                tokio::spawn(async move {
                    let _permit = permit.acquire().await.unwrap();

                    let client = ConnectedClient::with_config(
                        ReqwestTransport::new(),
                        identity_url,
                        signal_url,
                        pk,
                        tenant_id,
                        key_version,
                    );

                    let result = employee
                        .run_flow(
                            client,
                            &plan,
                            tenant_id,
                            analytics_dek.as_ref(),
                            &tenant_name,
                        )
                        .await;

                    let _ = tx.send(result);
                });

                total_tasks += 1;
            }
        }

        drop(tx);

        let mut results = Vec::with_capacity(total_tasks);
        while let Some(result) = rx.recv().await {
            results.push(result);
        }

        let tenant_names: Vec<String> = self
            .cluster
            .tenants
            .iter()
            .map(|t| t.name.clone())
            .collect();

        let mut report = SimulationReport::from_results(results, start.elapsed(), &tenant_names);
        report.seed = self.seed;
        report.batches = self.fetch_batch_aggregations().await;
        report
    }

    /// Fetch the k-anonymous aggregation for every provisioned batch from
    /// `GET /analytics/batch/{id}` and pair it with its question text.
    #[cfg(feature = "reqwest-transport")]
    async fn fetch_batch_aggregations(&self) -> Vec<super::report::BatchReport> {
        use pulse_server::analytics::BatchAggregation;

        use super::report::BatchReport;

        let client = reqwest::Client::new();
        let mut batch_reports = Vec::new();

        for tenant in &self.cluster.tenants {
            for batch in &tenant.batches {
                let url = format!(
                    "{}/analytics/batch/{}?tenant_id={}",
                    tenant.signal_url, batch.id, tenant.tenant_id
                );
                let response = client
                    .get(&url)
                    .send()
                    .await
                    .expect("analytics request failed");
                assert!(
                    response.status().is_success(),
                    "analytics endpoint returned {} for {url}",
                    response.status()
                );
                let aggregation: BatchAggregation = response
                    .json()
                    .await
                    .expect("analytics response must deserialize as BatchAggregation");

                batch_reports.push(BatchReport {
                    tenant_name: tenant.name.clone(),
                    question_text: batch.question_text.0.clone(),
                    aggregation,
                });
            }
        }

        batch_reports
    }
}
