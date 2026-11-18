//! HTTP access. Everything that downloads goes through `Fetcher` so tests can run offline.

use std::time::Duration;

use anyhow::{Context, Result, bail};

pub const MAX_DOWNLOAD_BYTES: u64 = 1 << 30;

pub trait Fetcher {
    fn get(&self, url: &str) -> Result<Vec<u8>>;

    /// Like `get`, but an HTTP error status is returned with its body instead of failing:
    /// some APIs explain an error in it (the wordpress.org info API's 404 for a closed plugin).
    fn get_with_status(&self, url: &str) -> Result<(u16, Vec<u8>)> {
        self.get(url).map(|b| (200, b))
    }
}

/// HTTPS-only fetcher. `https_only(true)` is enforced by ureq on every redirect hop,
/// not just the initial URL. ureq's `gzip` feature is deliberately disabled: the body
/// limit counts compressed bytes, so transparent decompression would let a small
/// stream expand without bound.
pub struct HttpFetcher {
    agent: ureq::Agent,
}

impl HttpFetcher {
    pub fn new() -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .https_only(true)
            .timeout_global(Some(Duration::from_secs(300)))
            .user_agent(concat!("iwp/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Self { agent }
    }

    #[cfg(test)]
    pub(crate) fn https_only(&self) -> bool {
        self.agent.config().https_only()
    }
}

impl Default for HttpFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpFetcher {
    fn fetch(&self, url: &str, status_as_error: bool) -> Result<(u16, Vec<u8>)> {
        if !url.starts_with("https://") {
            bail!("refusing non-https URL {url}");
        }
        let mut resp = self
            .agent
            .get(url)
            .config()
            .http_status_as_error(status_as_error)
            .build()
            .call()
            .with_context(|| format!("GET {url}"))?;
        let status = resp.status().as_u16();
        let body = resp
            .body_mut()
            .with_config()
            .limit(MAX_DOWNLOAD_BYTES)
            .read_to_vec()
            .with_context(|| format!("reading body of {url}"))?;
        Ok((status, body))
    }
}

impl Fetcher for HttpFetcher {
    fn get(&self, url: &str) -> Result<Vec<u8>> {
        self.fetch(url, true).map(|(_, b)| b)
    }

    fn get_with_status(&self, url: &str) -> Result<(u16, Vec<u8>)> {
        self.fetch(url, false)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_plain_http() {
        let err = HttpFetcher::new().get("http://example.org/x").unwrap_err();
        assert!(err.to_string().contains("non-https"), "{err}");
    }

    #[test]
    fn real_agent_is_https_only() {
        assert!(HttpFetcher::new().https_only());
    }
}
