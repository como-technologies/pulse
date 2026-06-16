//! Multi-tenant concurrent protocol simulation framework.
//!
//! Spin up multiple tenants with configurable employee populations,
//! run full protocol flows concurrently, and collect timing/correctness metrics.

pub mod cluster;
pub mod config;
pub mod employee;
pub mod report;
pub mod runner;
pub mod sampling;
pub mod survey;

pub use cluster::{ProvisionedBatch, SimulationCluster, TenantInstance};
pub use config::{QuestionBatchSetup, SimulationConfig, TenantSetup};
pub use employee::{FlowOutcome, FlowResult, FlowStep, FlowTimings, SimulatedEmployee};
pub use report::{AggregateTimings, BatchReport, PercentileStats, SimulationReport, TenantReport};
pub use runner::SimulationRunner;
pub use sampling::{SimBatch, SimSamplingEngine};
pub use survey::{ResponseDistribution, SurveyError, SurveyFile, SurveyQuestion};
