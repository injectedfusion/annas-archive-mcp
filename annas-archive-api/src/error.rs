use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Network error: {0}")]
    Network(String),

    #[error("HTTP error: status {status}")]
    Http { status: u16 },

    #[error("Parse error: {message}")]
    Parse { message: String },

    #[error("API error: {message}")]
    Api { message: String },

    #[error("Missing API key - required for download URLs")]
    MissingApiKey,

    #[error("All domains failed: {message}")]
    AllDomainsFailed { message: String },

    #[error("Domain not allowed: {0}")]
    DomainNotAllowed(String),

    #[error("Domain blacklisted after repeated failures: {0}")]
    DomainBlacklisted(String),
}

impl Error {
    pub fn from_reqwest(e: reqwest::Error) -> Self {
        Self::Network(e.without_url().to_string())
    }
}
