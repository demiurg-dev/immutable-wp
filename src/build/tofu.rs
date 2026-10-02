//! Trust-on-first-use hashes for artifacts wordpress.org does not publish checksums for (themes).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

pub struct Tofu {
    path: PathBuf,
    entries: BTreeMap<String, String>,
}

impl Tofu {
    pub fn load(path: &Path) -> Result<Tofu> {
        let entries = match fs::read(path) {
            Ok(b) => {
                serde_json::from_slice(&b).with_context(|| format!("parsing {}", path.display()))?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        Ok(Tofu {
            path: path.to_path_buf(),
            entries,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// `what` is used in the error message, e.g. "theme th@1.0".
    pub fn check_or_record(&mut self, key: &str, what: &str, sha256: &str) -> Result<()> {
        match self.entries.get(key) {
            Some(known) if known == sha256 => Ok(()),
            Some(known) => bail!(
                "{what}: zip changed since first use (recorded {known}, now {sha256}); if expected, remove \"{key}\" from {}",
                self.path.display()
            ),
            None => {
                self.entries.insert(key.to_string(), sha256.to_string());
                Ok(())
            }
        }
    }

    /// Checks against a recorded hash without recording. `Ok(true)` = known and matching,
    /// `Ok(false)` = not recorded yet.
    pub fn verify(&self, key: &str, what: &str, sha256: &str) -> Result<bool> {
        match self.entries.get(key) {
            Some(known) if known == sha256 => Ok(true),
            Some(known) => bail!(
                "{what}: zip changed since first use (recorded {known}, now {sha256}); if expected, remove \"{key}\" from {}",
                self.path.display()
            ),
            None => Ok(false),
        }
    }

    pub fn record(&mut self, key: &str, sha256: &str) {
        self.entries.insert(key.to_string(), sha256.to_string());
    }

    /// Merges our entries into what is on disk under an exclusive lock, so concurrent builds
    /// for different sites never lose each other's records. A key already recorded with a
    /// different hash is never overwritten.
    pub fn save(&self) -> Result<()> {
        let dir = self.path.parent().expect("tofu path has a parent");
        fs::create_dir_all(dir)?;
        let mut lock_name = self
            .path
            .file_name()
            .expect("tofu path has a name")
            .to_owned();
        lock_name.push(".lock");
        let lock_path = dir.join(lock_name);
        let lock = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&lock_path)
            .with_context(|| format!("opening {}", lock_path.display()))?;
        lock.lock()
            .with_context(|| format!("locking {}", lock_path.display()))?;
        let _lock = crate::host::lock::FileLock::held(lock);
        let mut merged = Tofu::load(&self.path)?.entries;
        for (k, v) in &self.entries {
            match merged.get(k) {
                Some(known) if known != v => bail!(
                    "TOFU conflict for {k}: stored {known}, this build saw {v} \u{2014} possible tampering or an upstream re-release; investigate before trusting (store: {})",
                    self.path.display()
                ),
                _ => {
                    merged.insert(k.clone(), v.clone());
                }
            }
        }
        let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
        serde_json::to_writer_pretty(&mut tmp, &merged)?;
        tmp.persist(&self.path)
            .with_context(|| format!("writing {}", self.path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::tmp;

    #[test]
    fn save_merges_concurrent_instances() {
        let d = tmp();
        let path = d.path().join("tofu.json");
        let mut a = Tofu::load(&path).unwrap();
        let mut b = Tofu::load(&path).unwrap();
        a.record("theme:a@1", "aaa");
        b.record("theme:b@1", "bbb");
        a.save().unwrap();
        b.save().unwrap();
        let merged = Tofu::load(&path).unwrap();
        assert!(merged.verify("theme:a@1", "x", "aaa").unwrap());
        assert!(merged.verify("theme:b@1", "x", "bbb").unwrap());
        assert!(d.path().join("tofu.json.lock").is_file());
    }

    #[test]
    fn save_never_overwrites_a_different_value() {
        let d = tmp();
        let path = d.path().join("tofu.json");
        let mut a = Tofu::load(&path).unwrap();
        let mut b = Tofu::load(&path).unwrap();
        a.record("theme:a@1", "aaa");
        b.record("theme:a@1", "evil");
        a.save().unwrap();
        let err = b.save().unwrap_err();
        assert!(format!("{err:#}").contains("theme:a@1"), "{err:#}");
        assert!(
            Tofu::load(&path)
                .unwrap()
                .verify("theme:a@1", "x", "aaa")
                .unwrap()
        );
        // identical value is fine
        let mut c = Tofu::load(&path).unwrap();
        c.record("theme:a@1", "aaa");
        c.save().unwrap();
    }

    #[test]
    fn save_conflict_message_is_distinct() {
        let d = tmp();
        let path = d.path().join("tofu.json");
        let mut a = Tofu::load(&path).unwrap();
        let mut b = Tofu::load(&path).unwrap();
        a.record("theme:a@1", "aaa");
        b.record("theme:a@1", "evil");
        a.save().unwrap();
        let msg = format!("{:#}", b.save().unwrap_err());
        assert!(
            msg.contains(
                "TOFU conflict for theme:a@1: stored aaa, this build saw evil \u{2014} possible tampering or an upstream re-release; investigate before trusting"
            ),
            "{msg}"
        );
    }
}
