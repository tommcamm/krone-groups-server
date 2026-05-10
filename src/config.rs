use std::{net::SocketAddr, path::PathBuf, str::FromStr};

use anyhow::{Context, Result, anyhow};

/// Hard cap on envelopes per submit request. Bumping this requires re-checking the body-size
/// cap in `auth::signed_request::max_body_bytes` and the batch rejection in
/// `routes::envelopes::submit`.
pub const MAX_ENVELOPES_PER_BATCH: usize = 256;
pub const MIN_TTL_SECONDS: u64 = 60;
pub const MAX_TTL_SECONDS: u64 = 365 * 24 * 60 * 60;
pub const MIN_ENVELOPE_BYTES_LIMIT: u64 = 1;
pub const MAX_ENVELOPE_BYTES_LIMIT: u64 = 1024 * 1024;
pub const MIN_INBOX_PER_DEVICE: u32 = 1;
pub const MAX_INBOX_PER_DEVICE: u32 = 1_000_000;
pub const MIN_ENVELOPES_PER_DEVICE_PER_HOUR: u32 = 1;
pub const MAX_ENVELOPES_PER_DEVICE_PER_HOUR: u32 = 100_000;
pub const MIN_CLOCK_SKEW_SECONDS: i64 = 1;
pub const MAX_CLOCK_SKEW_SECONDS: i64 = 60 * 60;

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

impl Policy {
    pub fn validate(&self) -> Result<()> {
        ensure_range(
            "KRONE_TTL_SECONDS",
            self.ttl_seconds,
            MIN_TTL_SECONDS,
            MAX_TTL_SECONDS,
        )?;
        ensure_range(
            "KRONE_MAX_ENVELOPE_BYTES",
            self.max_envelope_bytes,
            MIN_ENVELOPE_BYTES_LIMIT,
            MAX_ENVELOPE_BYTES_LIMIT,
        )?;
        ensure_range(
            "KRONE_MAX_INBOX_PER_DEVICE",
            self.max_inbox_per_device,
            MIN_INBOX_PER_DEVICE,
            MAX_INBOX_PER_DEVICE,
        )?;
        ensure_range(
            "KRONE_MAX_ENVELOPES_PER_DEVICE_PER_HOUR",
            self.max_envelopes_per_device_per_hour,
            MIN_ENVELOPES_PER_DEVICE_PER_HOUR,
            MAX_ENVELOPES_PER_DEVICE_PER_HOUR,
        )?;
        ensure_range(
            "KRONE_CLOCK_SKEW_SECONDS",
            self.clock_skew_seconds,
            MIN_CLOCK_SKEW_SECONDS,
            MAX_CLOCK_SKEW_SECONDS,
        )?;
        Ok(())
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
        policy.validate()?;

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

fn ensure_range<T>(key: &'static str, value: T, min: T, max: T) -> Result<()>
where
    T: Copy + PartialOrd + std::fmt::Display,
{
    if value < min || value > max {
        return Err(anyhow!("invalid env {key}={value}: expected {min}..={max}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_with(change: impl FnOnce(&mut Policy)) -> Policy {
        let mut policy = Policy::default();
        change(&mut policy);
        policy
    }

    #[test]
    fn default_policy_is_valid() {
        Policy::default().validate().expect("default policy");
    }

    #[test]
    fn policy_rejects_unusable_lower_bounds() {
        assert!(policy_with(|p| p.ttl_seconds = 0).validate().is_err());
        assert!(
            policy_with(|p| p.max_envelope_bytes = 0)
                .validate()
                .is_err()
        );
        assert!(
            policy_with(|p| p.max_inbox_per_device = 0)
                .validate()
                .is_err()
        );
        assert!(
            policy_with(|p| p.max_envelopes_per_device_per_hour = 0)
                .validate()
                .is_err()
        );
        assert!(
            policy_with(|p| p.clock_skew_seconds = -1)
                .validate()
                .is_err()
        );
    }

    #[test]
    fn policy_rejects_excessive_upper_bounds() {
        assert!(
            policy_with(|p| p.ttl_seconds = MAX_TTL_SECONDS + 1)
                .validate()
                .is_err()
        );
        assert!(
            policy_with(|p| p.max_envelope_bytes = MAX_ENVELOPE_BYTES_LIMIT + 1)
                .validate()
                .is_err()
        );
        assert!(
            policy_with(|p| p.max_inbox_per_device = MAX_INBOX_PER_DEVICE + 1)
                .validate()
                .is_err()
        );
        assert!(
            policy_with(|p| {
                p.max_envelopes_per_device_per_hour = MAX_ENVELOPES_PER_DEVICE_PER_HOUR + 1;
            })
            .validate()
            .is_err()
        );
        assert!(
            policy_with(|p| p.clock_skew_seconds = MAX_CLOCK_SKEW_SECONDS + 1)
                .validate()
                .is_err()
        );
    }
}
