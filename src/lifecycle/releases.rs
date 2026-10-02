//! Release directories under <base>/releases and the current/previous symlinks.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::build::{ReleaseManifest, remove_tree};

pub fn is_release_name(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 23
        && b[..8].iter().all(u8::is_ascii_digit)
        && b[8] == b'-'
        && b[9..15].iter().all(u8::is_ascii_digit)
        && b[15] == b'-'
        && b[16..]
            .iter()
            .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn list(base: &Path) -> Result<Vec<String>> {
    let dir = base.join("releases");
    let mut out = Vec::new();
    match fs::read_dir(&dir) {
        Ok(rd) => {
            for e in rd {
                let e = e?;
                let name = e.file_name().to_string_lossy().into_owned();
                if is_release_name(&name) && e.file_type()?.is_dir() {
                    out.push(name);
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    }
    out.sort();
    Ok(out)
}

pub fn link_target(base: &Path, link: &str) -> Result<Option<String>> {
    let p = base.join(link);
    let t = match fs::read_link(&p) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", p.display())),
    };
    let mut c = t.components();
    match (c.next(), c.next(), c.next()) {
        (Some(std::path::Component::Normal(r)), Some(std::path::Component::Normal(n)), None)
            if r == "releases" && is_release_name(&n.to_string_lossy()) =>
        {
            Ok(Some(n.to_string_lossy().into_owned()))
        }
        _ => bail!(
            "{} points to {}, expected releases/<release>",
            p.display(),
            t.display()
        ),
    }
}

pub fn current(base: &Path) -> Result<Option<String>> {
    link_target(base, "current")
}
pub fn previous(base: &Path) -> Result<Option<String>> {
    link_target(base, "previous")
}

pub fn point(base: &Path, link: &str, name: &str) -> Result<()> {
    if !is_release_name(name) {
        bail!("{name:?} is not a release name");
    }
    if !base.join("releases").join(name).is_dir() {
        bail!("release {name} does not exist");
    }
    let tmp = base.join(format!("{link}.tmp"));
    let _ = fs::remove_file(&tmp);
    std::os::unix::fs::symlink(Path::new("releases").join(name), &tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    fs::rename(&tmp, base.join(link)).with_context(|| format!("replacing {link}"))?;
    fs::File::open(base)?.sync_all()?;
    Ok(())
}

pub fn swap_current(base: &Path, name: &str) -> Result<Option<String>> {
    let old = current(base)?;
    point(base, "current", name)?;
    if let Some(o) = &old
        && o != name
    {
        point(base, "previous", o)?;
    }
    Ok(old)
}

pub fn read_manifest(base: &Path, name: &str) -> Result<ReleaseManifest> {
    let p = base.join("releases").join(name).join(".iwp-release.json");
    let bytes = fs::read(&p).with_context(|| format!("reading {}", p.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", p.display()))
}

/// `<base>/config/releases/<name>.json`: the resolved site file a release was deployed with.
pub fn snapshot_path(base: &Path, name: &str) -> PathBuf {
    base.join("config")
        .join("releases")
        .join(format!("{name}.json"))
}

/// Removes a release's site snapshot; a missing snapshot is fine.
pub fn remove_snapshot(base: &Path, name: &str) -> Result<()> {
    if !is_release_name(name) {
        bail!("{name:?} is not a release name");
    }
    let p = snapshot_path(base, name);
    match fs::remove_file(&p) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            Err(e).with_context(|| format!("removing {}", p.display()))
        }
        _ => Ok(()),
    }
}

pub fn gc_releases(base: &Path, keep: usize) -> Result<Vec<String>> {
    let protect: Vec<String> = [current(base)?, previous(base)?]
        .into_iter()
        .flatten()
        .collect();
    let all = list(base)?;
    let mut removed = Vec::new();
    let n = all.len();
    for (i, name) in all.into_iter().enumerate() {
        let newest_kept = i + keep >= n;
        if newest_kept || protect.contains(&name) {
            continue;
        }
        remove_tree(&base.join("releases").join(&name))?;
        removed.push(name);
    }
    Ok(removed)
}

/// Removes all but the `keep` newest (by mtime) pre-deploy dumps `db-<release>.sql.gz`.
/// Operator dumps (`iwp db dump`) and the safety dumps of `db restore` / `rollback --with-db`
/// (`db-pre-restore-*`, `db-pre-rollback-*`) are never removed automatically.
pub fn gc_dumps(base: &Path, keep: usize) -> Result<Vec<PathBuf>> {
    let dir = base.join("backups");
    let mut dumps: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
    if let Ok(rd) = fs::read_dir(&dir) {
        for e in rd {
            let e = e?;
            let name = e.file_name().to_string_lossy().into_owned();
            let release = name
                .strip_prefix("db-")
                .and_then(|n| n.strip_suffix(".sql.gz"));
            if release.is_some_and(is_release_name) && e.file_type()?.is_file() {
                dumps.push((e.metadata()?.modified()?, e.path()));
            }
        }
    }
    dumps.sort();
    let cut = dumps.len().saturating_sub(keep);
    let mut removed = Vec::new();
    for (_, p) in dumps.into_iter().take(cut) {
        fs::remove_file(&p).with_context(|| format!("removing {}", p.display()))?;
        removed.push(p);
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::tmp;
    use std::os::unix::fs::PermissionsExt;

    const A: &str = "20261001-100000-aaaaaaa";
    const B: &str = "20261001-110000-bbbbbbb";
    const C: &str = "20261001-120000-ccccccc";
    const D: &str = "20261001-130000-ddddddd";

    fn mk(base: &Path, name: &str) {
        let r = base.join("releases").join(name);
        fs::create_dir_all(r.join("wp-content")).unwrap();
        fs::write(r.join("wp-content/x"), "x").unwrap();
        // Releases are read-only after build.
        fs::set_permissions(r.join("wp-content/x"), fs::Permissions::from_mode(0o444)).unwrap();
        fs::set_permissions(r.join("wp-content"), fs::Permissions::from_mode(0o555)).unwrap();
        fs::set_permissions(&r, fs::Permissions::from_mode(0o555)).unwrap();
    }

    #[test]
    fn names_and_listing_ignore_junk() {
        assert!(is_release_name(A));
        for bad in [
            "20261001-10000-aaaaaaa",
            "20261001-100000-AAAAAAA",
            "x",
            ".iwp-build.lock",
            "20261001-100000-aaaaaaa.partial",
        ] {
            assert!(!is_release_name(bad), "{bad}");
        }
        let t = tmp();
        for n in [B, A] {
            mk(t.path(), n);
        }
        fs::create_dir_all(t.path().join("releases").join(format!("{C}.partial"))).unwrap();
        fs::write(t.path().join("releases/.iwp-build.lock"), "").unwrap();
        assert_eq!(list(t.path()).unwrap(), vec![A.to_string(), B.to_string()]);
    }

    #[test]
    fn swap_sets_current_and_previous_atomically() {
        let t = tmp();
        for n in [A, B] {
            mk(t.path(), n);
        }
        assert_eq!(swap_current(t.path(), A).unwrap(), None);
        assert_eq!(current(t.path()).unwrap().as_deref(), Some(A));
        assert_eq!(previous(t.path()).unwrap(), None);
        assert_eq!(swap_current(t.path(), B).unwrap().as_deref(), Some(A));
        assert_eq!(current(t.path()).unwrap().as_deref(), Some(B));
        assert_eq!(previous(t.path()).unwrap().as_deref(), Some(A));
        assert_eq!(
            fs::read_link(t.path().join("current")).unwrap(),
            Path::new("releases").join(B)
        );
        assert!(!t.path().join("current.tmp").exists());
        // Re-pointing to the same release leaves previous alone.
        swap_current(t.path(), B).unwrap();
        assert_eq!(previous(t.path()).unwrap().as_deref(), Some(A));
    }

    #[test]
    fn bad_link_targets_are_errors() {
        let t = tmp();
        std::os::unix::fs::symlink("/etc", t.path().join("current")).unwrap();
        assert!(current(t.path()).is_err());
        assert!(point(t.path(), "current", "../etc").is_err());
    }

    #[test]
    fn gc_keeps_newest_current_and_previous() {
        let t = tmp();
        for n in [A, B, C, D] {
            mk(t.path(), n);
        }
        swap_current(t.path(), A).unwrap();
        swap_current(t.path(), B).unwrap(); // previous = A, current = B
        let removed = gc_releases(t.path(), 1).unwrap();
        // keep 1 newest (D) + current (B) + previous (A); C goes.
        assert_eq!(removed, vec![C.to_string()]);
        assert!(!t.path().join("releases").join(C).exists());
        assert_eq!(list(t.path()).unwrap(), vec![A, B, D]);
    }

    #[test]
    fn gc_dumps_rotates_release_dumps_by_mtime_and_keeps_the_rest() {
        let t = tmp();
        let b = t.path().join("backups");
        fs::create_dir(&b).unwrap();
        // mtime order (oldest first) is the reverse of name order for the release dumps.
        let files = [
            format!("db-{D}.sql.gz"),
            format!("db-{C}.sql.gz"),
            format!("db-{B}.sql.gz"),
            format!("db-{A}.sql.gz"),
            "db-20250101-000000.sql.gz".to_string(), // operator `iwp db dump`
            "db-pre-restore-20250101-000000.sql.gz".to_string(),
            "db-pre-rollback-20250101-000000.sql.gz".to_string(),
            "notes.txt".to_string(),
        ];
        for (i, n) in files.iter().enumerate() {
            let p = b.join(n);
            fs::write(&p, "x").unwrap();
            let t0 = std::time::SystemTime::UNIX_EPOCH
                + std::time::Duration::from_secs(1_000 + i as u64);
            fs::File::options()
                .write(true)
                .open(&p)
                .unwrap()
                .set_modified(t0)
                .unwrap();
        }
        let removed = gc_dumps(t.path(), 2).unwrap();
        assert_eq!(
            removed,
            vec![
                b.join(format!("db-{D}.sql.gz")),
                b.join(format!("db-{C}.sql.gz"))
            ]
        );
        for n in &files[2..] {
            assert!(b.join(n).exists(), "{n}");
        }
    }
}
