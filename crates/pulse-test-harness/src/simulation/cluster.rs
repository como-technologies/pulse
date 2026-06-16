use std::sync::Arc;

use axum::{
    Router,
    routing::{get, post},
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;
use tokio::net::TcpListener;

use pulse_crypto::blind_sig;
use pulse_identity::{InMemorySessionStore, QuestionBatch, SamplingEngine, TokenIssuer};
use pulse_protocol::{KeyVersion, QuestionBatchId, TenantId, UnixTimestamp};
use pulse_signal::{InMemoryLedger, InMemoryStore, ResponseCollector};

use pulse_server::dev_auth::DevAuthenticator;
use pulse_server::dev_tenant_keys::InMemoryTenantKeyStore;
use pulse_server::{IdentityState, SignalState, identity_routes, signal_routes};

use super::config::SimulationConfig;
use super::sampling::{SimBatch, SimSamplingEngine};
use super::survey::ResponseDistribution;

/// A question batch provisioned on a tenant's servers.
pub struct ProvisionedBatch {
    pub id: QuestionBatchId,
    pub question_text: pulse_protocol::QuestionText,
    /// How simulated respondents answer this batch's question.
    pub distribution: ResponseDistribution,
}

/// Build a ChaCha RNG: seeded (deterministic) or from OS entropy.
///
/// ChaCha is pinned explicitly (rather than `StdRng`) so the deterministic
/// artifact stream survives `rand` algorithm changes.
pub(crate) fn make_rng(seed: Option<u64>) -> ChaCha12Rng {
    match seed {
        Some(seed) => ChaCha12Rng::seed_from_u64(seed),
        None => ChaCha12Rng::from_os_rng(),
    }
}

/// Generate a v4-format UUID from the simulation RNG (deterministic when seeded).
fn rng_uuid(rng: &mut ChaCha12Rng) -> uuid::Uuid {
    uuid::Builder::from_random_bytes(rng.random()).into_uuid()
}

/// A provisioned tenant instance with running servers.
pub struct TenantInstance {
    pub name: String,
    pub employee_count: usize,
    pub identity_url: String,
    pub signal_url: String,
    pub pk: pulse_crypto::BrssPublicKey,
    pub tenant_id: TenantId,
    pub key_version: KeyVersion,
    pub batches: Vec<ProvisionedBatch>,
    pub analytics_dek: Option<[u8; 32]>,
}

/// A cluster of tenant server pairs for simulation.
pub struct SimulationCluster {
    pub tenants: Vec<TenantInstance>,
}

impl SimulationCluster {
    /// Provision all tenants and start server pairs.
    pub async fn start(config: &SimulationConfig) -> Self {
        let mut tenants = Vec::with_capacity(config.tenants.len());
        // Drives tenant/batch IDs; deterministic when the config is seeded.
        let mut rng = make_rng(config.seed);

        for tenant_setup in &config.tenants {
            let kp = blind_sig::generate_keypair().unwrap();
            let pk = kp.pk.clone();
            let tenant_id = TenantId::from_uuid(rng_uuid(&mut rng));
            let key_store = Arc::new(InMemoryTenantKeyStore::new());
            key_store.register_tenant(tenant_id, kp.sk, kp.pk, KeyVersion(1));

            let ledger = Arc::new(InMemoryLedger::new());
            let store: Arc<dyn pulse_signal::ResponseStore> = Arc::new(InMemoryStore::new());

            // Provision every question batch from the setup
            let mut batches = Vec::with_capacity(tenant_setup.question_batches.len());
            let mut sim_batches = Vec::with_capacity(tenant_setup.question_batches.len());
            for batch_setup in &tenant_setup.question_batches {
                let batch_id = QuestionBatchId::from_uuid(rng_uuid(&mut rng));
                batches.push(ProvisionedBatch {
                    id: batch_id,
                    question_text: batch_setup.question_text.clone(),
                    distribution: batch_setup.distribution.clone(),
                });
                sim_batches.push(SimBatch {
                    batch: QuestionBatch {
                        id: batch_id,
                        question_text: batch_setup.question_text.clone(),
                        response_type: batch_setup.response_type.clone(),
                        expiry: UnixTimestamp(u64::MAX),
                    },
                    segment_labels: batch_setup.segment_labels.clone(),
                });
            }
            let sampling_engine: Arc<dyn SamplingEngine> = Arc::new(SimSamplingEngine::new(
                sim_batches,
                tenant_setup.max_tokens_per_batch,
            ));

            // Optionally provision analytics
            let (analytics, analytics_dek) = if config.with_analytics {
                use pulse_server::analytics::AnalyticsEngine;
                use pulse_server::cmk::CmkProvider;
                use pulse_server::dek_store::{DekDomain, DekStore, InMemoryDekStore};
                use pulse_server::dev_cmk::DevCmkProvider;

                let cmk = Arc::new(DevCmkProvider::new());
                let dek_store = Arc::new(InMemoryDekStore::new());
                let analytics_dek = pulse_crypto::aead::generate_key();
                let wrapped = cmk.wrap_dek(&tenant_id, &analytics_dek).unwrap();
                dek_store.store_wrapped_dek(&tenant_id, DekDomain::Analytics, wrapped);

                let engine =
                    AnalyticsEngine::new(store.clone(), dek_store, cmk, config.k_threshold);
                (Some(engine), Some(analytics_dek))
            } else {
                (None, None)
            };

            let identity_state = Arc::new(IdentityState {
                issuer: TokenIssuer::with_sampling(key_store.clone(), sampling_engine.clone()),
                authenticator: Arc::new(DevAuthenticator),
                session_store: Arc::new(InMemorySessionStore::new()),
                sampling_engine,
                tenant_id,
                public_key: pk.clone(),
                key_version: KeyVersion(1),
            });

            let signal_state = Arc::new(SignalState {
                collector: ResponseCollector::new(key_store, ledger, store.clone()),
                store,
                analytics,
            });

            let identity_router = Router::new()
                .route("/config", get(identity_routes::get_config))
                .route("/auth", post(identity_routes::auth))
                .route("/question", get(identity_routes::get_questions))
                .route("/token/sign", post(identity_routes::sign_token))
                .with_state(identity_state);

            let mut signal_router = Router::new()
                .route("/response", post(signal_routes::submit_response))
                .route("/debug/responses", get(signal_routes::debug_responses));

            if config.with_analytics {
                signal_router = signal_router.route(
                    "/analytics/batch/{batch_id}",
                    get(pulse_server::analytics_routes::aggregate_batch),
                );
            }

            let signal_router = signal_router.with_state(signal_state);

            let identity_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let signal_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

            let identity_addr = identity_listener.local_addr().unwrap();
            let signal_addr = signal_listener.local_addr().unwrap();

            tokio::spawn(axum::serve(identity_listener, identity_router).into_future());
            tokio::spawn(axum::serve(signal_listener, signal_router).into_future());

            tenants.push(TenantInstance {
                name: tenant_setup.name.clone(),
                employee_count: tenant_setup.employee_count,
                identity_url: format!("http://{identity_addr}"),
                signal_url: format!("http://{signal_addr}"),
                pk,
                tenant_id,
                key_version: KeyVersion(1),
                batches,
                analytics_dek,
            });
        }

        Self { tenants }
    }
}
