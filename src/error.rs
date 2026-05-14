#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("text content too short for fingerprinting")]
    ContentTooShort,

    #[error("fingerprint generation failed: {0}")]
    GenerationFailed(String),

    #[error("fingerprint match failed: {0}")]
    MatchFailed(String),
}
