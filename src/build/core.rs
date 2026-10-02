//! WordPress core checks on the image's webroot and extraction of its static files.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::hash::{list_files, md5_hex};

pub fn verify_core(checksums: &BTreeMap<String, String>, webroot: &Path) -> Result<usize> {
    let mut n = 0;
    for (path, md5) in checksums
        .iter()
        .filter(|(p, _)| !p.starts_with("wp-content/"))
    {
        let file = webroot.join(path);
        let bytes =
            fs::read(&file).with_context(|| format!("core file {path} missing from image"))?;
        let got = md5_hex(&bytes);
        if &got != md5 {
            bail!("core file {path}: md5 mismatch (expected {md5}, got {got})");
        }
        n += 1;
    }
    let listed: BTreeSet<&str> = checksums.keys().map(String::as_str).collect();
    for (rel, _) in list_files(webroot)? {
        if rel == "wp-config.php" || listed.contains(rel.as_str()) {
            continue;
        }
        if rel.to_ascii_lowercase().ends_with(".php") {
            bail!("unexpected PHP file in image webroot: {rel}");
        }
        bail!("unexpected file in image webroot: {rel}");
    }
    Ok(n)
}

pub fn copy_static(src: &Path, dst: &Path) -> Result<()> {
    for (rel, exec) in list_files(src)? {
        if rel.ends_with(".php") {
            continue;
        }
        let to = dst.join(&rel);
        fs::create_dir_all(to.parent().expect("file has parent"))?;
        fs::copy(src.join(&rel), &to).with_context(|| format!("copying {rel}"))?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            &to,
            fs::Permissions::from_mode(if exec { 0o755 } else { 0o644 }),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::md5_hex;
    use crate::testutil::tmp;

    #[test]
    fn verify_core_detects_modified_and_missing() {
        let d = tmp();
        std::fs::write(d.path().join("index.php"), "<?php").unwrap();
        let mut sums = BTreeMap::new();
        sums.insert("index.php".to_string(), md5_hex(b"<?php"));
        assert_eq!(verify_core(&sums, d.path()).unwrap(), 1);
        sums.insert("xmlrpc.php".to_string(), md5_hex(b"x"));
        assert!(format!("{:#}", verify_core(&sums, d.path()).unwrap_err()).contains("xmlrpc.php"));
        sums.remove("xmlrpc.php");
        std::fs::write(d.path().join("index.php"), "<?php evil();").unwrap();
        assert!(format!("{:#}", verify_core(&sums, d.path()).unwrap_err()).contains("index.php"));
    }

    #[test]
    fn unlisted_files_in_webroot_rejected() {
        for bad in [
            "wp-includes/js/evil.js",
            "wp-admin/x.PHP",
            "wp-content/plugins/evil.txt",
            "wp-content/mu-plugins/backdoor.php",
        ] {
            let d = tmp();
            std::fs::write(d.path().join("index.php"), "<?php").unwrap();
            std::fs::create_dir_all(d.path().join("wp-content/plugins")).unwrap();
            std::fs::write(d.path().join("wp-content/index.php"), "<?php // silence").unwrap();
            std::fs::write(d.path().join("wp-config.php"), "<?php").unwrap();
            let mut sums = BTreeMap::new();
            sums.insert("index.php".to_string(), md5_hex(b"<?php"));
            sums.insert(
                "wp-content/index.php".to_string(),
                md5_hex(b"<?php // silence"),
            );
            assert_eq!(verify_core(&sums, d.path()).unwrap(), 1);
            let p = d.path().join(bad);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, "x").unwrap();
            let e = format!("{:#}", verify_core(&sums, d.path()).unwrap_err());
            assert!(e.contains("unexpected") && e.contains(bad), "{e}");
        }
    }

    #[test]
    fn copy_static_skips_php_and_empty_dirs() {
        let d = tmp();
        let src = d.path().join("s");
        std::fs::create_dir_all(src.join("only-php")).unwrap();
        std::fs::create_dir_all(src.join("css")).unwrap();
        std::fs::write(src.join("only-php/x.php"), "<?php").unwrap();
        std::fs::write(src.join("css/a.css"), "a").unwrap();
        copy_static(&src, &d.path().join("o")).unwrap();
        assert!(d.path().join("o/css/a.css").is_file());
        assert!(!d.path().join("o/only-php").exists());
    }
}
