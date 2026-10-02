//! Download cache. Cached bytes are never trusted: `get_verified` re-hashes on every read,
//! and `get_url` callers verify content themselves (e.g. per-file plugin checksums).

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::fetch::net::Fetcher;
use crate::hash::sha256_hex;

/// A `get_verified` download whose hash differs from the pinned one.
#[derive(Debug)]
pub struct Sha256Mismatch {
    pub url: String,
    pub expected: String,
    pub got: String,
}

impl std::fmt::Display for Sha256Mismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "sha256 mismatch for {}: expected {}, got {}",
            self.url, self.expected, self.got
        )
    }
}

impl std::error::Error for Sha256Mismatch {}

pub struct Cache {
    dir: PathBuf,
}

impl Cache {
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
        }
    }

    /// Unverified: callers must verify the content (e.g. per-file checksums).
    pub fn get_url(&self, f: &dyn Fetcher, url: &str) -> Result<Vec<u8>> {
        let path = self.dir.join("url").join(sha256_hex(url.as_bytes()));
        if let Ok(bytes) = fs::read(&path) {
            return Ok(bytes);
        }
        let bytes = f.get(url)?;
        write_atomic(&path, &bytes)?;
        Ok(bytes)
    }

    /// Whether `get_url` would be served from the cache without a fetch.
    pub fn has_url(&self, url: &str) -> bool {
        self.dir
            .join("url")
            .join(sha256_hex(url.as_bytes()))
            .is_file()
    }

    /// Stores bytes content-addressed so a later `get_verified` needs no fetch.
    pub fn put_verified(&self, sha256: &str, bytes: &[u8]) -> Result<()> {
        let got = sha256_hex(bytes);
        if got != sha256 {
            bail!("refusing to cache bytes with sha256 {got} under {sha256}");
        }
        write_atomic(&self.dir.join("sha256").join(sha256), bytes)
    }

    /// Call when cached bytes turn out unusable so the next run refetches.
    pub fn evict_url(&self, url: &str) -> Result<()> {
        let path = self.dir.join("url").join(sha256_hex(url.as_bytes()));
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("evicting {}", path.display())),
        }
    }

    /// Returns bytes whose sha256 matches `sha256`; cached blobs are re-hashed on every read.
    pub fn get_verified(&self, f: &dyn Fetcher, url: &str, sha256: &str) -> Result<Vec<u8>> {
        let path = self.dir.join("sha256").join(sha256);
        if let Ok(bytes) = fs::read(&path) {
            if sha256_hex(&bytes) == sha256 {
                return Ok(bytes);
            }
            fs::remove_file(&path)
                .with_context(|| format!("removing corrupt cache entry {}", path.display()))?;
        }
        let bytes = f.get(url)?;
        let got = sha256_hex(&bytes);
        if got != sha256 {
            return Err(Sha256Mismatch {
                url: url.to_string(),
                expected: sha256.to_string(),
                got,
            }
            .into());
        }
        write_atomic(&path, &bytes)?;
        Ok(bytes)
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().expect("cache paths have a parent");
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    std::io::Write::write_all(&mut tmp, bytes)?;
    tmp.persist(path)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha256_hex;
    use crate::testutil::{FakeFetcher, tmp};

    const URL: &str = "https://downloads.wordpress.org/plugin/x.1.0.zip";

    #[test]
    fn get_url_caches_after_first_fetch() {
        let d = tmp();
        let c = Cache::new(d.path());
        let f = FakeFetcher::new().with(URL, "zipbytes");
        assert_eq!(c.get_url(&f, URL).unwrap(), b"zipbytes");
        assert_eq!(c.get_url(&f, URL).unwrap(), b"zipbytes");
        assert_eq!(f.calls().len(), 1);
    }

    #[test]
    fn evict_url_forces_refetch() {
        let d = tmp();
        let c = Cache::new(d.path());
        let f = FakeFetcher::new().with(URL, "zipbytes");
        c.get_url(&f, URL).unwrap();
        c.evict_url(URL).unwrap();
        c.evict_url(URL).unwrap();
        c.get_url(&f, URL).unwrap();
        assert_eq!(f.calls().len(), 2);
    }

    #[test]
    fn get_verified_rejects_mismatch_and_writes_nothing() {
        let d = tmp();
        let c = Cache::new(d.path());
        let f = FakeFetcher::new().with(URL, "tampered");
        let err = c
            .get_verified(&f, URL, &sha256_hex(b"original"))
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("sha256 mismatch") && msg.contains(URL),
            "{msg}"
        );
        assert!(
            !d.path()
                .join("sha256")
                .join(sha256_hex(b"original"))
                .exists()
        );
    }

    #[test]
    fn get_verified_reverifies_cached_blob() {
        let d = tmp();
        let c = Cache::new(d.path());
        let good = sha256_hex(b"original");
        let f = FakeFetcher::new().with(URL, "original");
        c.get_verified(&f, URL, &good).unwrap();
        // poison the cache on disk
        std::fs::write(d.path().join("sha256").join(&good), "poison").unwrap();
        assert_eq!(c.get_verified(&f, URL, &good).unwrap(), b"original");
        assert_eq!(
            f.calls().len(),
            2,
            "poisoned blob must be discarded and refetched"
        );
    }

    #[test]
    fn fetch_errors_name_the_url() {
        let d = tmp();
        let err = Cache::new(d.path())
            .get_url(&FakeFetcher::new(), URL)
            .unwrap_err();
        assert!(format!("{err:#}").contains(URL));
    }

    #[test]
    fn put_verified_stores_content_addressed_and_checks_hash() {
        let d = tmp();
        let c = Cache::new(d.path());
        let h = sha256_hex(b"bytes");
        assert!(c.put_verified(&"0".repeat(64), b"bytes").is_err());
        assert!(!d.path().join("sha256").join("0".repeat(64)).exists());
        c.put_verified(&h, b"bytes").unwrap();
        let f = FakeFetcher::new();
        assert_eq!(c.get_verified(&f, URL, &h).unwrap(), b"bytes");
        assert!(
            f.calls().is_empty(),
            "served from the content-addressed cache"
        );
    }

    #[test]
    fn has_url_reports_cached_state() {
        let d = tmp();
        let c = Cache::new(d.path());
        let f = FakeFetcher::new().with(URL, "z");
        assert!(!c.has_url(URL));
        c.get_url(&f, URL).unwrap();
        assert!(c.has_url(URL));
        c.evict_url(URL).unwrap();
        assert!(!c.has_url(URL));
    }
}
