pub mod auth;
pub mod config;
pub mod console;
pub mod lb;
pub mod policy;
pub mod pool;
pub mod proxy;
pub mod router;
pub mod secrets;
pub mod telemetry;

use http::StatusCode;
use thiserror::Error;

/// Typed production errors mapped cleanly to HTTP status codes (zero `.unwrap()` in production paths).
#[derive(Debug, Error)]
pub enum EdgeGateError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("payload too large: {0}")]
    PayloadTooLarge(String),
    #[error("too many requests: {0}")]
    TooManyRequests(String),
    #[error("bad gateway: {0}")]
    BadGateway(String),
    #[error("pool exhausted: {0}")]
    PoolExhausted(String),
    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),
    #[error("gateway timeout: {0}")]
    GatewayTimeout(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl EdgeGateError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            Self::TooManyRequests(_) => StatusCode::TOO_MANY_REQUESTS,
            Self::BadGateway(_) => StatusCode::BAD_GATEWAY,
            Self::PoolExhausted(_) | Self::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::GatewayTimeout(_) => StatusCode::GATEWAY_TIMEOUT,
            Self::Config(_) | Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn public_message(&self) -> String {
        match self {
            Self::BadRequest(m) => m.clone(),
            Self::Unauthorized(_) => "unauthorized workload identity".to_string(),
            Self::Forbidden(_) => "access denied by edgegate policy".to_string(),
            Self::PayloadTooLarge(m) => m.clone(),
            Self::TooManyRequests(_) => "rate limit exceeded by edgegate policy".to_string(),
            Self::BadGateway(_) => "upstream connection error".to_string(),
            Self::PoolExhausted(_) => "upstream connection pool exhausted".to_string(),
            Self::ServiceUnavailable(_) => "no healthy upstream backends available".to_string(),
            Self::GatewayTimeout(_) => "upstream gateway timeout".to_string(),
            Self::Config(_) | Self::Internal(_) => "internal gateway error".to_string(),
        }
    }
}

pub fn healthcheck() -> &'static str {
    "ok"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_test() {
        assert_eq!(healthcheck(), "ok");
    }
}
