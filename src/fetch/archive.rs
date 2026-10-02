//! Safe zip extraction: no path escapes, no symlinks, no overwrites, bounded size.

use std::collections::BTreeSet;
use std::fs;
use std::io::{Cursor, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};

#[derive(Debug, Clone)]
pub struct ExtractLimits {
    pub max_total_bytes: u64,
    pub max_entries: usize,
}

impl Default for ExtractLimits {
    fn default() -> Self {
        Self {
            max_total_bytes: 1 << 30,
            max_entries: 100_000,
        }
    }
}

/// Validates an archive entry name and returns it as a relative path of Normal components.
pub(crate) fn safe_rel(raw: &str) -> Result<PathBuf> {
    let unsafe_name = || anyhow::anyhow!("unsafe path in archive: {raw:?}");
    if raw.is_empty()
        || raw.starts_with('/')
        || raw.contains('\\')
        || raw.chars().any(char::is_control)
    {
        return Err(unsafe_name());
    }
    let p = Path::new(raw.trim_end_matches('/'));
    if !p.components().all(|c| matches!(c, Component::Normal(_))) {
        return Err(unsafe_name());
    }
    Ok(p.to_path_buf())
}

/// The zip reader silently collapses entries with the same name, so walk the central
/// directory ourselves and refuse archives that contain any name twice.
fn reject_duplicate_names(bytes: &[u8], dir_start: u64, max_entries: usize) -> Result<usize> {
    const SIG: &[u8] = b"PK\x01\x02";
    let u16_at = |b: &[u8], o: usize| usize::from(u16::from_le_bytes([b[o], b[o + 1]]));
    let mut pos = usize::try_from(dir_start).context("bad central directory offset")?;
    let mut seen: BTreeSet<&[u8]> = BTreeSet::new();
    let mut count = 0usize;
    while bytes.get(pos..pos.saturating_add(4)) == Some(SIG) {
        let Some(h) = pos.checked_add(46).and_then(|e| bytes.get(pos..e)) else {
            bail!("truncated central directory");
        };
        let (n, x, c) = (u16_at(h, 28), u16_at(h, 30), u16_at(h, 32));
        let Some(name) = bytes.get(pos + 46..pos + 46 + n) else {
            bail!("truncated central directory");
        };
        count += 1;
        if count > max_entries {
            bail!("archive has more than the limit of {max_entries} entries");
        }
        if !seen.insert(name) {
            bail!(
                "duplicate entry in archive: {:?}",
                String::from_utf8_lossy(name)
            );
        }
        pos = pos
            .checked_add(46 + n + x + c)
            .context("bad central directory")?;
    }
    Ok(count)
}

pub fn extract_zip(bytes: &[u8], dest: &Path, limits: &ExtractLimits) -> Result<Option<String>> {
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).context("not a valid zip archive")?;
    let walked = reject_duplicate_names(bytes, zip.central_directory_start(), limits.max_entries)?;
    if walked != zip.len() {
        bail!(
            "archive entry count mismatch ({walked} in directory, {} readable), possible duplicate or aliased names",
            zip.len()
        );
    }
    if zip.len() > limits.max_entries {
        bail!(
            "archive has {} entries, more than the limit of {} entries",
            zip.len(),
            limits.max_entries
        );
    }

    // Pass 1: validate every name, reject symlinks, find a common top-level directory.
    let mut entries = Vec::with_capacity(zip.len());
    for i in 0..zip.len() {
        let f = zip.by_index(i)?;
        let raw = f.name().to_string();
        if f.is_symlink() {
            bail!("symlink in archive not allowed: {raw:?}");
        }
        let rel = safe_rel(&raw)?;
        // macOS Finder adds resource forks under __MACOSX/; they are never part of the package.
        if rel
            .components()
            .next()
            .is_some_and(|c| c.as_os_str() == "__MACOSX")
        {
            continue;
        }
        entries.push((i, rel, f.is_dir()));
    }
    let tops: BTreeSet<_> = entries
        .iter()
        .filter_map(|(_, p, _)| p.components().next().map(|c| c.as_os_str().to_owned()))
        .collect();
    let strip = tops.len() == 1
        && entries
            .iter()
            .all(|(_, p, is_dir)| *is_dir || p.components().count() > 1);
    let top = if strip {
        tops.into_iter()
            .next()
            .map(|t| t.to_string_lossy().into_owned())
    } else {
        None
    };

    // Pass 2: write files.
    let mut total: u64 = 0;
    for (i, rel, is_dir) in &entries {
        let mut f = zip.by_index(*i)?;
        let rel = match &top {
            Some(t) => rel
                .strip_prefix(t)
                .expect("checked in pass 1")
                .to_path_buf(),
            None => rel.clone(),
        };
        if rel.as_os_str().is_empty() {
            continue;
        }
        let out = dest.join(&rel);
        if *is_dir {
            fs::create_dir_all(&out).with_context(|| format!("creating {}", out.display()))?;
            continue;
        }
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        let mut w = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&out)
            .with_context(|| format!("duplicate or conflicting entry {}", rel.display()))?;
        let remaining = limits.max_total_bytes - total;
        let n = std::io::copy(&mut (&mut f).take(remaining.saturating_add(1)), &mut w)
            .with_context(|| format!("extracting {}", rel.display()))?;
        total += n;
        if total > limits.max_total_bytes {
            bail!(
                "archive expands beyond {} bytes (at {})",
                limits.max_total_bytes,
                rel.display()
            );
        }
        let exec = f.unix_mode().is_some_and(|m| m & 0o111 != 0);
        fs::set_permissions(
            &out,
            fs::Permissions::from_mode(if exec { 0o755 } else { 0o644 }),
        )?;
    }
    Ok(top)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{make_zip, make_zip_with_symlink, tmp};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn strips_single_top_level_dir() {
        let z = make_zip(&[
            ("gutena-tabs/", b""),
            ("gutena-tabs/a.php", b"<?php"),
            ("gutena-tabs/build/x.js", b"x"),
        ]);
        let d = tmp();
        let top = extract_zip(&z, d.path(), &ExtractLimits::default()).unwrap();
        assert_eq!(top.as_deref(), Some("gutena-tabs"));
        assert_eq!(std::fs::read(d.path().join("a.php")).unwrap(), b"<?php");
        assert!(d.path().join("build/x.js").is_file());
        let mode = std::fs::metadata(d.path().join("a.php"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o644);
    }

    #[test]
    fn macosx_entries_are_ignored() {
        let z = make_zip(&[
            ("__MACOSX/", b""),
            ("__MACOSX/prem/._a.php", b"junk"),
            ("prem/", b""),
            ("prem/a.php", b"<?php"),
        ]);
        let d = tmp();
        let top = extract_zip(&z, d.path(), &ExtractLimits::default()).unwrap();
        assert_eq!(top.as_deref(), Some("prem"));
        assert!(d.path().join("a.php").is_file());
        assert!(!d.path().join("__MACOSX").exists());
    }

    #[test]
    fn control_characters_in_names_rejected() {
        for bad in ["a\nb.php", "a\rb", "a\x07b", "dir/\x1b[0m.txt", "a\x7fb"] {
            assert!(safe_rel(bad).is_err(), "{bad:?}");
        }
        assert!(safe_rel("ok/file name.txt").is_ok());
    }

    #[test]
    fn keeps_flat_archives() {
        let z = make_zip(&[("hr.mo", b"m"), ("admin-hr.mo", b"n")]);
        let d = tmp();
        assert_eq!(
            extract_zip(&z, d.path(), &ExtractLimits::default()).unwrap(),
            None
        );
        assert!(d.path().join("hr.mo").is_file() && d.path().join("admin-hr.mo").is_file());
    }

    #[test]
    fn single_file_at_root_is_not_stripped() {
        let z = make_zip(&[("only.mo", b"m")]);
        let d = tmp();
        assert_eq!(
            extract_zip(&z, d.path(), &ExtractLimits::default()).unwrap(),
            None
        );
        assert!(d.path().join("only.mo").is_file());
    }

    #[test]
    fn rejects_path_traversal_and_absolute() {
        for name in [
            "../evil.php",
            "a/../../evil.php",
            "/etc/evil",
            "a\\..\\evil",
        ] {
            let z = make_zip(&[(name, b"x")]);
            let d = tmp();
            let outside = d.path().parent().unwrap().join("evil.php");
            let err = extract_zip(&z, d.path(), &ExtractLimits::default()).unwrap_err();
            assert!(format!("{err:#}").contains("unsafe"), "{name}: {err:#}");
            assert!(!outside.exists());
        }
    }

    #[test]
    fn rejects_symlinks() {
        let z = make_zip_with_symlink("p/link", "/etc/passwd");
        let d = tmp();
        let err = extract_zip(&z, d.path(), &ExtractLimits::default()).unwrap_err();
        assert!(format!("{err:#}").contains("symlink"), "{err:#}");
    }

    #[test]
    fn rejects_duplicates() {
        // The zip writer refuses duplicate names, so patch a same-length placeholder.
        let mut z = make_zip(&[("p/a", b"1"), ("p/b", b"2")]);
        let mut patched = 0;
        for i in 0..z.len() - 2 {
            if &z[i..i + 3] == b"p/b" {
                z[i + 2] = b'a';
                patched += 1;
            }
        }
        assert_eq!(patched, 2, "local header and central directory entries");
        let d = tmp();
        let err = extract_zip(&z, d.path(), &ExtractLimits::default()).unwrap_err();
        assert!(
            format!("{err:#}").contains("duplicate") || format!("{err:#}").contains("exists"),
            "{err:#}"
        );
    }

    #[test]
    fn enforces_limits() {
        let big = vec![0u8; 4096];
        let z = make_zip(&[("p/a", &big), ("p/b", &big)]);
        let d = tmp();
        let err = extract_zip(
            &z,
            d.path(),
            &ExtractLimits {
                max_total_bytes: 5000,
                max_entries: 10,
            },
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("5000"), "{err:#}");
        let d = tmp();
        let err = extract_zip(
            &z,
            d.path(),
            &ExtractLimits {
                max_total_bytes: 1 << 20,
                max_entries: 1,
            },
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("entries"), "{err:#}");
    }

    #[test]
    fn rejects_garbage() {
        let d = tmp();
        assert!(
            extract_zip(
                b"<html>not a zip</html>",
                d.path(),
                &ExtractLimits::default()
            )
            .is_err()
        );
    }

    fn crc32(data: &[u8]) -> u32 {
        let mut c = !0u32;
        for &b in data {
            c ^= u32::from(b);
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    (c >> 1) ^ 0xEDB8_8320
                } else {
                    c >> 1
                };
            }
        }
        !c
    }

    /// Stored-only zip; each entry is (name, body, central-directory extra field).
    fn raw_zip(entries: &[(&str, &[u8], Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, body, extra) in entries {
            let off = out.len() as u32;
            let crc = crc32(body);
            out.extend(b"PK\x03\x04");
            out.extend([20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            out.extend(crc.to_le_bytes());
            out.extend((body.len() as u32).to_le_bytes());
            out.extend((body.len() as u32).to_le_bytes());
            out.extend((name.len() as u16).to_le_bytes());
            out.extend(0u16.to_le_bytes());
            out.extend(name.as_bytes());
            out.extend(*body);
            central.extend(b"PK\x01\x02");
            central.extend([20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            central.extend(crc.to_le_bytes());
            central.extend((body.len() as u32).to_le_bytes());
            central.extend((body.len() as u32).to_le_bytes());
            central.extend((name.len() as u16).to_le_bytes());
            central.extend((extra.len() as u16).to_le_bytes());
            central.extend([0u8; 10]);
            central.extend(off.to_le_bytes());
            central.extend(name.as_bytes());
            central.extend(extra);
        }
        let dir = out.len() as u32;
        out.extend(&central);
        out.extend(b"PK\x05\x06");
        out.extend([0u8; 4]);
        out.extend((entries.len() as u16).to_le_bytes());
        out.extend((entries.len() as u16).to_le_bytes());
        out.extend((central.len() as u32).to_le_bytes());
        out.extend(dir.to_le_bytes());
        out.extend(0u16.to_le_bytes());
        out
    }

    #[test]
    fn rejects_unicode_path_alias_duplicates() {
        let mut extra = Vec::new();
        extra.extend(0x7075u16.to_le_bytes());
        extra.extend(8u16.to_le_bytes());
        extra.push(1);
        extra.extend(crc32(b"p/b").to_le_bytes());
        extra.extend(b"p/a");
        let z = raw_zip(&[("p/a", b"first", vec![]), ("p/b", b"second", extra)]);
        let d = tmp();
        let err = extract_zip(&z, d.path(), &ExtractLimits::default()).unwrap_err();
        let m = format!("{err:#}");
        assert!(m.contains("mismatch") || m.contains("duplicate"), "{m}");
    }

    #[test]
    fn raw_zip_fixture_is_valid() {
        let z = raw_zip(&[("p/a", b"first", vec![]), ("p/b", b"second", vec![])]);
        let d = tmp();
        assert_eq!(
            extract_zip(&z, d.path(), &ExtractLimits::default())
                .unwrap()
                .as_deref(),
            Some("p")
        );
        assert_eq!(std::fs::read(d.path().join("b")).unwrap(), b"second");
    }

    #[test]
    fn exec_bits_map_to_0755_and_setuid_is_dropped() {
        use std::io::Write;
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let o = zip::write::SimpleFileOptions::default();
        w.start_file("p/run.sh", o.unix_permissions(0o755)).unwrap();
        w.write_all(b"x").unwrap();
        w.start_file("p/suid", o.unix_permissions(0o106777))
            .unwrap();
        w.write_all(b"x").unwrap();
        w.start_file("p/plain", o.unix_permissions(0o600)).unwrap();
        w.write_all(b"x").unwrap();
        let z = w.finish().unwrap().into_inner();
        let d = tmp();
        extract_zip(&z, d.path(), &ExtractLimits::default()).unwrap();
        let m = |n: &str| {
            std::fs::metadata(d.path().join(n))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777
        };
        assert_eq!(m("run.sh"), 0o755);
        assert_eq!(m("suid"), 0o755);
        assert_eq!(m("plain"), 0o644);
    }

    #[test]
    fn size_limit_boundary() {
        let z = make_zip(&[("p/a", &[0u8; 100])]);
        let lim = |n| ExtractLimits {
            max_total_bytes: n,
            max_entries: 10,
        };
        let d = tmp();
        extract_zip(&z, d.path(), &lim(100)).unwrap();
        let d = tmp();
        let err = extract_zip(&z, d.path(), &lim(99)).unwrap_err();
        assert!(format!("{err:#}").contains("99"));
    }

    #[test]
    fn rejects_file_dir_conflicts() {
        for entries in [
            vec![("p/a", &b"x"[..]), ("p/a/", &b""[..])],
            vec![("p/a", &b"x"[..]), ("p/a/b", &b"y"[..])],
        ] {
            let z = make_zip(&entries);
            let d = tmp();
            assert!(
                extract_zip(&z, d.path(), &ExtractLimits::default()).is_err(),
                "{entries:?}"
            );
        }
    }
}
