use std::fmt;

#[derive(Debug)]
pub enum Error {
    ContentTooShort,
    GenerationFailed(String),
    MatchFailed(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContentTooShort => write!(f, "text content too short for fingerprinting"),
            Self::GenerationFailed(s) => write!(f, "fingerprint generation failed: {s}"),
            Self::MatchFailed(s) => write!(f, "fingerprint match failed: {s}"),
        }
    }
}

impl std::error::Error for Error {}
