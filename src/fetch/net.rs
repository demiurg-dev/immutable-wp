//! HTTP access. Everything that downloads goes through `Fetcher` so tests can run offline.

use std::time::Duration;

use anyhow::{Context, Result, bail};

pub const MAX_DOWNLOAD_BYTES: u64 = 1 << 30;

pub trait Fetcher {
    fn get(&self, url: &str) -> Result<Vec<u8>>;
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

impl Fetcher for HttpFetcher {
    fn get(&self, url: &str) -> Result<Vec<u8>> {
        if !url.starts_with("https://") {
            bail!("refusing non-https URL {url}");
        }
        let mut resp = self
            .agent
            .get(url)
            .call()
            .with_context(|| format!("GET {url}"))?;
        resp.body_mut()
            .with_config()
            .limit(MAX_DOWNLOAD_BYTES)
            .read_to_vec()
            .with_context(|| format!("reading body of {url}"))
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
