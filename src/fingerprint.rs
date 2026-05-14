use crate::error::Error;

#[derive(Debug, Clone)]
pub struct FingerprintResult {
    pub fingerprint: Vec<u8>,
    pub algorithm: String,
    pub confidence: f64,
}

pub trait TextFingerprint {
    fn algorithm_id(&self) -> &str;

    fn generate(&self, text: &str) -> Result<FingerprintResult, Error>;

    fn match_fingerprint(
        &self,
        text: &str,
        fingerprint: &[u8],
    ) -> Result<f64, Error>;
}
