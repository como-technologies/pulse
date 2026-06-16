//! Survey-as-data: question batches and response distributions defined in TOML.
//!
//! Each dogfood iteration retros itself by editing the checked-in survey file
//! (`dogfood/iteration-retro.toml`) instead of recompiling the simulation.

use serde::Deserialize;

use pulse_protocol::QuestionText;
use pulse_protocol::messages::{ResponseData, ResponseType};

use super::config::{QuestionBatchSetup, TenantSetup};

/// Errors loading or validating a survey file.
#[derive(Debug, thiserror::Error)]
pub enum SurveyError {
    #[error("failed to read survey file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse survey TOML: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("survey must define at least one question")]
    NoQuestions,
    #[error("question {index}: scale5 requires exactly 5 weights, got {got}")]
    BadWeights { index: usize, got: usize },
    #[error("question {index}: weights must not all be zero")]
    ZeroWeights { index: usize },
}

/// A survey definition loaded from TOML.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurveyFile {
    /// Survey name; used as the simulated tenant name.
    pub name: Option<String>,
    pub questions: Vec<SurveyQuestion>,
}

/// One question batch: text, type, segment labels, and the seeded
/// response distribution simulated respondents sample from.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurveyQuestion {
    pub text: String,
    pub response_type: SurveyResponseType,
    pub segments: Vec<String>,
    /// Relative weights for scores 1..=5 (need not sum to anything).
    pub weights: Vec<u64>,
}

/// Response types a survey file may declare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SurveyResponseType {
    Scale5,
}

/// How a simulated respondent picks an answer.
#[derive(Debug, Clone)]
pub enum ResponseDistribution {
    /// Always answer the same Scale5 score (legacy hardcoded behavior).
    ConstantScale5(u8),
    /// Sample a Scale5 score 1..=5 from relative weights.
    WeightedScale5([u64; 5]),
}

impl ResponseDistribution {
    /// Draw one response. Deterministic for a deterministic `rng`.
    pub fn sample<R: rand::Rng>(&self, rng: &mut R) -> ResponseData {
        match self {
            Self::ConstantScale5(score) => ResponseData::Scale5(*score),
            Self::WeightedScale5(weights) => {
                let total: u64 = weights.iter().sum();
                let mut draw = rng.random_range(0..total);
                for (i, weight) in weights.iter().enumerate() {
                    if draw < *weight {
                        return ResponseData::Scale5((i + 1) as u8);
                    }
                    draw -= weight;
                }
                unreachable!("draw < total guarantees a bucket")
            }
        }
    }
}

impl SurveyFile {
    /// Parse and validate a survey from TOML text.
    pub fn parse(toml_str: &str) -> Result<Self, SurveyError> {
        let survey: SurveyFile = toml::from_str(toml_str)?;
        if survey.questions.is_empty() {
            return Err(SurveyError::NoQuestions);
        }
        for (index, question) in survey.questions.iter().enumerate() {
            match question.response_type {
                SurveyResponseType::Scale5 => {
                    if question.weights.len() != 5 {
                        return Err(SurveyError::BadWeights {
                            index,
                            got: question.weights.len(),
                        });
                    }
                    if question.weights.iter().all(|w| *w == 0) {
                        return Err(SurveyError::ZeroWeights { index });
                    }
                }
            }
        }
        Ok(survey)
    }

    /// Load and validate a survey from a TOML file on disk.
    pub fn load(path: &std::path::Path) -> Result<Self, SurveyError> {
        Self::parse(&std::fs::read_to_string(path)?)
    }

    /// Build the simulated tenant for this survey: one question batch per
    /// question, each carrying its response distribution.
    pub fn to_tenant_setup(&self, employee_count: usize, max_tokens_per_batch: u32) -> TenantSetup {
        TenantSetup {
            name: self.name.clone().unwrap_or_else(|| "dogfood".to_string()),
            employee_count,
            question_batches: self
                .questions
                .iter()
                .map(|q| {
                    let mut weights = [0u64; 5];
                    weights.copy_from_slice(&q.weights);
                    QuestionBatchSetup {
                        question_text: QuestionText::from(q.text.as_str()),
                        response_type: match q.response_type {
                            SurveyResponseType::Scale5 => ResponseType::Scale5,
                        },
                        segment_labels: q.segments.iter().map(|s| s.as_str().into()).collect(),
                        distribution: ResponseDistribution::WeightedScale5(weights),
                    }
                })
                .collect(),
            max_tokens_per_batch,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    use pulse_protocol::messages::ResponseData;

    const RETRO_TOML: &str = r#"
name = "iteration-retro"

[[questions]]
text = "How did the iteration go?"
response_type = "scale5"
segments = ["company"]
weights = [0, 1, 2, 4, 3]

[[questions]]
text = "How sustainable is the pace?"
response_type = "scale5"
segments = ["company"]
weights = [1, 2, 3, 3, 1]
"#;

    #[test]
    fn parses_questions_with_distributions() {
        let survey = SurveyFile::parse(RETRO_TOML).unwrap();
        assert_eq!(survey.name.as_deref(), Some("iteration-retro"));
        assert_eq!(survey.questions.len(), 2);
        assert_eq!(survey.questions[0].text, "How did the iteration go?");
        assert_eq!(survey.questions[0].segments, vec!["company".to_string()]);
        assert_eq!(survey.questions[0].weights, vec![0, 1, 2, 4, 3]);
    }

    #[test]
    fn rejects_empty_question_list() {
        let err = SurveyFile::parse("name = \"empty\"\nquestions = []\n").unwrap_err();
        assert!(matches!(err, SurveyError::NoQuestions));
    }

    #[test]
    fn rejects_wrong_weight_count_for_scale5() {
        let toml = r#"
[[questions]]
text = "Bad weights"
response_type = "scale5"
segments = ["company"]
weights = [1, 2, 3]
"#;
        let err = SurveyFile::parse(toml).unwrap_err();
        assert!(matches!(err, SurveyError::BadWeights { index: 0, got: 3 }));
    }

    #[test]
    fn rejects_all_zero_weights() {
        let toml = r#"
[[questions]]
text = "Zero weights"
response_type = "scale5"
segments = ["company"]
weights = [0, 0, 0, 0, 0]
"#;
        let err = SurveyFile::parse(toml).unwrap_err();
        assert!(matches!(err, SurveyError::ZeroWeights { index: 0 }));
    }

    #[test]
    fn rejects_unknown_response_type() {
        let toml = r#"
[[questions]]
text = "Free text"
response_type = "freetext"
segments = ["company"]
weights = [1, 1, 1, 1, 1]
"#;
        assert!(matches!(
            SurveyFile::parse(toml).unwrap_err(),
            SurveyError::Parse(_)
        ));
    }

    #[test]
    fn converts_to_tenant_setup_with_distributions() {
        let survey = SurveyFile::parse(RETRO_TOML).unwrap();
        let setup = survey.to_tenant_setup(10, 1);
        assert_eq!(setup.name, "iteration-retro");
        assert_eq!(setup.employee_count, 10);
        assert_eq!(setup.question_batches.len(), 2);
        assert_eq!(
            setup.question_batches[0].question_text.0,
            "How did the iteration go?"
        );
        assert!(matches!(
            setup.question_batches[0].distribution,
            ResponseDistribution::WeightedScale5([0, 1, 2, 4, 3])
        ));
    }

    #[test]
    fn identical_seeds_yield_identical_sample_sequences() {
        let dist = ResponseDistribution::WeightedScale5([1, 2, 3, 3, 1]);
        let sample = |seed: u64| -> Vec<ResponseData> {
            let mut rng = ChaCha12Rng::seed_from_u64(seed);
            (0..50).map(|_| dist.sample(&mut rng)).collect()
        };
        let a = sample(42);
        let b = sample(42);
        let c = sample(43);
        assert_eq!(a, b, "same seed must reproduce the exact sequence");
        assert_ne!(a, c, "different seeds should diverge");
    }

    #[test]
    fn degenerate_distribution_always_samples_that_score() {
        let dist = ResponseDistribution::WeightedScale5([0, 0, 0, 0, 7]);
        let mut rng = ChaCha12Rng::seed_from_u64(1);
        for _ in 0..20 {
            assert_eq!(dist.sample(&mut rng), ResponseData::Scale5(5));
        }
    }

    #[test]
    fn constant_distribution_ignores_rng() {
        let dist = ResponseDistribution::ConstantScale5(4);
        let mut rng = ChaCha12Rng::seed_from_u64(9);
        assert_eq!(dist.sample(&mut rng), ResponseData::Scale5(4));
    }
}
