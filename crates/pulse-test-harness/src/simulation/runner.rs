use super::cluster::SimulationCluster;

/// Orchestrates concurrent protocol flows across all tenants.
#[allow(dead_code)] // Fields read inside #[cfg(feature = "reqwest-transport")]
pub struct SimulationRunner {
    cluster: SimulationCluster,
    concurrency: usize,
}

impl SimulationRunner {
    pub fn new(cluster: SimulationCluster, concurrency: usize) -> Self {
        Self {
            cluster,
            concurrency,
        }
    }

    /// Run all employees across all tenants concurrently.
    #[cfg(feature = "reqwest-transport")]
    pub async fn run(&self) -> super::report::SimulationReport {
        use std::time::Instant;

        use tokio::sync::{Semaphore, mpsc};

        use pulse_client::{ConnectedClient, ReqwestTransport};

        use super::employee::{FlowResult, SimulatedEmployee};
        use super::report::SimulationReport;

        let start = Instant::now();
        let semaphore = std::sync::Arc::new(Semaphore::new(self.concurrency));
        let (tx, mut rx) = mpsc::unbounded_channel::<FlowResult>();

        let mut total_tasks = 0;

        for tenant in &self.cluster.tenants {
            for emp_idx in 0..tenant.employee_count {
                let employee =
                    SimulatedEmployee::new(format!("{}-employee-{emp_idx}", tenant.name));

                let identity_url = tenant.identity_url.clone();
                let signal_url = tenant.signal_url.clone();
                let pk = tenant.pk.clone();
                let tenant_id = tenant.tenant_id;
                let key_version = tenant.key_version;
                let batch_id = tenant.batch_ids[0];
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
                            batch_id,
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

        SimulationReport::from_results(results, start.elapsed(), &tenant_names)
    }
}
