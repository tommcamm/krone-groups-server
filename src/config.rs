use std::{net::SocketAddr, path::PathBuf, str::FromStr};

use anyhow::{Context, Result, anyhow};

/// Hard cap on envelopes per submit request. Bumping this requires re-checking the body-size
/// cap in `auth::signed_request::max_body_bytes` and the batch rejection in
/// `routes::envelopes::submit`.
pub const MAX_ENVELOPES_PER_BATCH: usize = 256;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub bind_addr: SocketAddr,
    pub data_dir: PathBuf,
    pub database_url: String,
    pub policy: Policy,
    pub server_seed_hex: Option<String>,
    pub server_version: String,
}

#[derive(Clone, Debug)]
pub struct Policy {
    pub ttl_seconds: u64,
    pub max_envelope_bytes: u64,
    pub max_inbox_per_device: u32,
    pub max_envelopes_per_device_per_hour: u32,
    pub clock_skew_seconds: i64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            ttl_seconds: 30 * 24 * 60 * 60,
            max_envelope_bytes: 64 * 1024,
            max_inbox_per_device: 10_000,
            max_envelopes_per_device_per_hour: 600,
            clock_skew_seconds: 120,
        }
    }
}

impl AppConfig {
    pub fn from_env() -> Result<Self> {
        let bind_addr = env_or("KRONE_BIND", "0.0.0.0:8080")
            .parse::<SocketAddr>()
            .context("parse KRONE_BIND as SocketAddr")?;
        let data_dir = PathBuf::from(env_or("KRONE_DATA_DIR", "./data"));
        let database_url = std::env::var("KRONE_DATABASE_URL")
            .unwrap_or_else(|_| format!("sqlite://{}/krone.sqlite?mode=rwc", data_dir.display()));
        let server_seed_hex = std::env::var("KRONE_SERVER_SEED")
            .ok()
            .filter(|s| !s.is_empty());
        let server_version = std::env::var("KRONE_VERSION")
            .unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_string());

        let mut policy = Policy::default();
        if let Ok(v) = std::env::var("KRONE_TTL_SECONDS") {
            policy.ttl_seconds = parse_env("KRONE_TTL_SECONDS", &v)?;
        }
        if let Ok(v) = std::env::var("KRONE_MAX_ENVELOPE_BYTES") {
            policy.max_envelope_bytes = parse_env("KRONE_MAX_ENVELOPE_BYTES", &v)?;
        }
        if let Ok(v) = std::env::var("KRONE_MAX_INBOX_PER_DEVICE") {
            policy.max_inbox_per_device = parse_env("KRONE_MAX_INBOX_PER_DEVICE", &v)?;
        }
        if let Ok(v) = std::env::var("KRONE_MAX_ENVELOPES_PER_DEVICE_PER_HOUR") {
            policy.max_envelopes_per_device_per_hour =
                parse_env("KRONE_MAX_ENVELOPES_PER_DEVICE_PER_HOUR", &v)?;
        }
        if let Ok(v) = std::env::var("KRONE_CLOCK_SKEW_SECONDS") {
            policy.clock_skew_seconds = parse_env("KRONE_CLOCK_SKEW_SECONDS", &v)?;
        }

        Ok(Self {
            bind_addr,
            data_dir,
            database_url,
            policy,
            server_seed_hex,
            server_version,
        })
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn parse_env<T: FromStr>(key: &str, value: &str) -> Result<T>
where
    T::Err: std::fmt::Display,
{
    value
        .parse::<T>()
        .map_err(|e| anyhow!("invalid env {key}={value}: {e}"))
}
