use crate::error::{MailServerError, Result};
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct RateLimitEntry {
    pub attempts: u32,
    pub last_attempt: DateTime<Utc>,
    pub locked_until: Option<DateTime<Utc>>,
}

pub struct RateLimiter {
    entries: Arc<RwLock<HashMap<String, RateLimitEntry>>>,
    max_attempts: u32,
    window_duration: Duration,
    lockout_duration: Duration,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            max_attempts: 5,
            window_duration: Duration::minutes(15),
            lockout_duration: Duration::minutes(30),
        }
    }

    pub fn with_config(max_attempts: u32, window_minutes: i64, lockout_minutes: i64) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            max_attempts,
            window_duration: Duration::minutes(window_minutes),
            lockout_duration: Duration::minutes(lockout_minutes),
        }
    }

    pub async fn is_rate_limited(&self, email: &str, ip_address: &Option<String>) -> Result<bool> {
        let limiter = self.entries.read().await;

        // Check both email and IP-based rate limiting
        let keys = self.get_rate_limit_keys(email, ip_address);

        for key in keys.iter().filter(|k| !k.is_empty()) {
            if let Some(entry) = limiter.get(key) {
                // Check if currently locked out
                if let Some(locked_until) = entry.locked_until {
                    if locked_until > Utc::now() {
                        return Ok(true);
                    }
                }

                // Check if too many attempts in recent time window
                if entry.attempts >= self.max_attempts
                    && entry.last_attempt > Utc::now() - self.window_duration
                {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    pub async fn record_failed_attempt(
        &self,
        email: &str,
        ip_address: &Option<String>,
    ) -> Result<()> {
        let mut limiter = self.entries.write().await;

        let keys = self.get_rate_limit_keys(email, ip_address);

        for key in keys.iter().filter(|k| !k.is_empty()) {
            let entry = limiter.entry(key.clone()).or_insert(RateLimitEntry {
                attempts: 0,
                last_attempt: Utc::now(),
                locked_until: None,
            });

            entry.attempts += 1;
            entry.last_attempt = Utc::now();

            // Lock after max attempts reached
            if entry.attempts >= self.max_attempts {
                entry.locked_until = Some(Utc::now() + self.lockout_duration);
            }
        }

        Ok(())
    }

    pub async fn reset_attempts(&self, email: &str, ip_address: &Option<String>) -> Result<()> {
        let mut limiter = self.entries.write().await;

        let keys = self.get_rate_limit_keys(email, ip_address);

        for key in keys.iter().filter(|k| !k.is_empty()) {
            limiter.remove(key);
        }

        Ok(())
    }

    pub async fn get_remaining_attempts(
        &self,
        email: &str,
        ip_address: &Option<String>,
    ) -> Result<u32> {
        let limiter = self.entries.read().await;

        let keys = self.get_rate_limit_keys(email, ip_address);
        let mut min_remaining = self.max_attempts;

        for key in keys.iter().filter(|k| !k.is_empty()) {
            if let Some(entry) = limiter.get(key) {
                if entry.last_attempt > Utc::now() - self.window_duration {
                    let remaining = self.max_attempts.saturating_sub(entry.attempts);
                    min_remaining = min_remaining.min(remaining);
                }
            }
        }

        Ok(min_remaining)
    }

    pub async fn get_lockout_time(
        &self,
        email: &str,
        ip_address: &Option<String>,
    ) -> Result<Option<DateTime<Utc>>> {
        let limiter = self.entries.read().await;

        let keys = self.get_rate_limit_keys(email, ip_address);
        let mut latest_lockout: Option<DateTime<Utc>> = None;

        for key in keys.iter().filter(|k| !k.is_empty()) {
            if let Some(entry) = limiter.get(key) {
                if let Some(locked_until) = entry.locked_until {
                    if locked_until > Utc::now() {
                        latest_lockout = Some(match latest_lockout {
                            Some(existing) => existing.max(locked_until),
                            None => locked_until,
                        });
                    }
                }
            }
        }

        Ok(latest_lockout)
    }

    pub async fn cleanup_expired_entries(&self) -> Result<()> {
        let mut limiter = self.entries.write().await;
        let now = Utc::now();

        limiter.retain(|_, entry| {
            // Keep entries that are still locked or have recent attempts
            if let Some(locked_until) = entry.locked_until {
                if locked_until > now {
                    return true;
                }
            }

            entry.last_attempt > now - self.window_duration
        });

        Ok(())
    }

    fn get_rate_limit_keys(&self, email: &str, ip_address: &Option<String>) -> Vec<String> {
        vec![
            format!("email:{}", email),
            ip_address
                .as_ref()
                .map(|ip| format!("ip:{}", ip))
                .unwrap_or_default(),
        ]
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}
