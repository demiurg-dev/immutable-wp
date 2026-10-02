//! Read-only scan of an existing WordPress webroot. Never follows symlinks, never writes.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Plugin,
    Theme,
    MuPlugin,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LocalPackage {
    pub kind: Kind,
    pub slug: String,
    pub version: Option<String>,
    /// Directory, or the file itself for single-file packages.
    pub dir: PathBuf,
    pub single_file: bool,
}

#[derive(Debug, Default)]
pub struct Detected {
    pub wordpress: String,
    pub languages: Vec<String>,
    pub packages: Vec<LocalPackage>,
    pub dropins: Vec<String>,
    pub other_content_dirs: Vec<String>,
    /// Top-level webroot entries that are not WordPress core, `wp-config.php` or `wp-content`
    /// (dotfiles included); none of them is carried into the new site.
    pub other_root_files: Vec<String>,
    pub warnings: Vec<String>,
}

/// The webroot's own core entries (the version's core checksums are not available offline).
const CORE_ROOT: [&str; 20] = [
    "wp-admin",
    "wp-includes",
    "wp-content",
    "wp-config.php",
    "index.php",
    "xmlrpc.php",
    "license.txt",
    "readme.html",
    "wp-config-sample.php",
    "wp-activate.php",
    "wp-blog-header.php",
    "wp-comments-post.php",
    "wp-cron.php",
    "wp-links-opml.php",
    "wp-load.php",
    "wp-login.php",
    "wp-mail.php",
    "wp-settings.php",
    "wp-signup.php",
    "wp-trackback.php",
];

const HEADER_BYTES: u64 = 8192;

const DROPINS: [&str; 9] = [
    "advanced-cache.php",
    "object-cache.php",
    "db.php",
    "db-error.php",
    "maintenance.php",
    "sunrise.php",
    "blog-deleted.php",
    "blog-inactive.php",
    "blog-suspended.php",
];

const KNOWN_DIRS: [&str; 8] = [
    "plugins",
    "themes",
    "mu-plugins",
    "languages",
    "uploads",
    "upgrade",
    "upgrade-temp-backup",
    "cache",
];

/// Scan `root` (read-only; symlinks are never followed).
pub fn detect(root: &Path) -> Result<Detected> {
    let mut det = Detected::default();
    let vp = root.join("wp-includes/version.php");
    let text = match fs::symlink_metadata(&vp) {
        Ok(m) if m.is_file() => {
            fs::read_to_string(&vp).with_context(|| format!("read {}", vp.display()))?
        }
        _ => bail!("not a WordPress root: {}", root.display()),
    };
    det.wordpress =
        parse_wp_version(&text).with_context(|| format!("no $wp_version in {}", vp.display()))?;

    let content = root.join("wp-content");
    if !is_real_dir(&content) {
        bail!(
            "wp-content is missing or a symlink in {}; import cannot continue",
            root.display()
        );
    }
    scan_plugins(&content, &mut det)?;
    scan_themes(&content, &mut det)?;
    scan_mu(&content, &mut det)?;
    scan_languages(&content.join("languages"), &mut det)?;
    for name in DROPINS {
        match fs::symlink_metadata(content.join(name)) {
            Ok(m) if m.file_type().is_symlink() => det
                .warnings
                .push(format!("wp-content/{name} is a symlink; drop-in skipped")),
            Ok(m) if m.is_file() => det.dropins.push(name.to_string()),
            _ => {}
        }
    }
    let mut root_names: Vec<String> = fs::read_dir(root)
        .with_context(|| format!("read {}", root.display()))?
        .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<std::io::Result<_>>()?;
    root_names.sort();
    det.other_root_files = root_names
        .into_iter()
        .filter(|n| !CORE_ROOT.contains(&n.as_str()))
        .collect();
    for (name, path) in entries(&content)? {
        let m = fs::symlink_metadata(&path)?;
        if m.file_type().is_symlink() {
            // plugins/themes/mu-plugins and drop-ins were already reported above.
            if !["plugins", "themes", "mu-plugins"].contains(&name.as_str())
                && !DROPINS.contains(&name.as_str())
            {
                det.warnings
                    .push(format!("wp-content/{name} is a symlink; skipped"));
            }
        } else if m.is_dir() && !KNOWN_DIRS.contains(&name.as_str()) {
            det.other_content_dirs.push(name);
        }
    }
    Ok(det)
}

/// `wp-content/<name>` when it is a real directory; a symlink warns, a missing one is fine.
fn content_dir(content: &Path, name: &str, det: &mut Detected) -> Option<PathBuf> {
    let p = content.join(name);
    match fs::symlink_metadata(&p) {
        Ok(m) if m.file_type().is_symlink() => {
            det.warnings.push(format!(
                "wp-content/{name} is a symlink; skipped (copy its contents into a real directory first)"
            ));
            None
        }
        Ok(m) if m.is_dir() => Some(p),
        _ => None,
    }
}

fn is_real_dir(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok_and(|m| m.is_dir())
}

/// Sorted `(name, path)` of a directory's entries; empty when it is absent or a symlink.
fn entries(dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    if !is_real_dir(dir) {
        return Ok(Vec::new());
    }
    let mut v = Vec::new();
    for e in fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let e = e?;
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        v.push((name, e.path()));
    }
    v.sort();
    Ok(v)
}

fn parse_wp_version(text: &str) -> Option<String> {
    let re = regex::Regex::new(r#"\$wp_version\s*=\s*['"]([^'"]+)['"]"#).ok()?;
    re.captures(text).map(|c| c[1].to_string())
}

/// First 8 KiB of a file as text.
fn head(path: &Path) -> Result<String> {
    let f = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut buf = Vec::new();
    f.take(HEADER_BYTES).read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Like WordPress's `get_file_data`: case-insensitive key, optional leading `<?php`, value cut at
/// the first `*/` or `?>`, trimmed; an empty value counts as absent.
fn header(text: &str, key: &str) -> Option<String> {
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    let re = regex::Regex::new(&format!(
        r"(?mi)^(?:[ \t]*<\?php)?[ \t/*#@]*{}:(.*)$",
        regex::escape(key)
    ))
    .ok()?;
    let v = re.captures(&text)?.get(1)?.as_str();
    let end = [v.find("*/"), v.find("?>")].into_iter().flatten().min();
    let v = end.map_or(v, |i| &v[..i]).trim();
    (!v.is_empty()).then(|| v.to_string())
}

fn php_stem(name: &str) -> Option<&str> {
    name.strip_suffix(".php").filter(|s| !s.is_empty())
}

fn scan_plugins(content: &Path, det: &mut Detected) -> Result<()> {
    let Some(dir) = content_dir(content, "plugins", det) else {
        return Ok(());
    };
    for (name, path) in entries(&dir)? {
        let m = fs::symlink_metadata(&path)?;
        if m.file_type().is_symlink() {
            det.warnings
                .push(format!("plugins/{name} is a symlink; skipped"));
        } else if m.is_file() {
            let Some(stem) = php_stem(&name).filter(|_| name != "index.php") else {
                continue;
            };
            let t = head(&path)?;
            if header(&t, "Plugin Name").is_some() {
                det.packages.push(LocalPackage {
                    kind: Kind::Plugin,
                    slug: stem.to_string(),
                    version: header(&t, "Version"),
                    dir: path,
                    single_file: true,
                });
            } else {
                det.warnings
                    .push(format!("plugins/{name}: no plugin header found; skipped"));
            }
        } else if m.is_dir() {
            let mut found = None;
            for (fname, fpath) in entries(&path)? {
                if php_stem(&fname).is_none() || !fs::symlink_metadata(&fpath)?.is_file() {
                    continue;
                }
                let t = head(&fpath)?;
                if header(&t, "Plugin Name").is_some() {
                    found = Some(header(&t, "Version"));
                    break;
                }
            }
            match found {
                Some(version) => det.packages.push(LocalPackage {
                    kind: Kind::Plugin,
                    slug: name,
                    version,
                    dir: path,
                    single_file: false,
                }),
                None => det
                    .warnings
                    .push(format!("plugins/{name}: no plugin header found; skipped")),
            }
        }
    }
    Ok(())
}

fn scan_themes(content: &Path, det: &mut Detected) -> Result<()> {
    let Some(dir) = content_dir(content, "themes", det) else {
        return Ok(());
    };
    for (name, path) in entries(&dir)? {
        let m = fs::symlink_metadata(&path)?;
        if m.file_type().is_symlink() {
            det.warnings
                .push(format!("themes/{name} is a symlink; skipped"));
        } else if m.is_dir() {
            let css = path.join("style.css");
            let t = match fs::symlink_metadata(&css) {
                Ok(cm) if cm.is_file() => head(&css)?,
                _ => String::new(),
            };
            if header(&t, "Theme Name").is_some() {
                det.packages.push(LocalPackage {
                    kind: Kind::Theme,
                    slug: name,
                    version: header(&t, "Version"),
                    dir: path,
                    single_file: false,
                });
            } else {
                det.warnings
                    .push(format!("themes/{name}: no theme header found; skipped"));
            }
        }
    }
    Ok(())
}

fn scan_mu(content: &Path, det: &mut Detected) -> Result<()> {
    let Some(dir) = content_dir(content, "mu-plugins", det) else {
        return Ok(());
    };
    for (name, path) in entries(&dir)? {
        let m = fs::symlink_metadata(&path)?;
        if m.file_type().is_symlink() {
            det.warnings
                .push(format!("mu-plugins/{name} is a symlink; skipped"));
        } else if m.is_dir() {
            det.warnings.push(format!(
                "mu-plugins/{name}: mu-plugin directories are not supported; load them from a single file"
            ));
        } else if m.is_file()
            && let Some(stem) = php_stem(&name)
        {
            let version = header(&head(&path)?, "Version");
            det.packages.push(LocalPackage {
                kind: Kind::MuPlugin,
                slug: stem.to_string(),
                version,
                dir: path,
                single_file: true,
            });
        }
    }
    Ok(())
}

fn scan_languages(dir: &Path, det: &mut Detected) -> Result<()> {
    for (name, path) in entries(dir)? {
        let Some(locale) = name.strip_suffix(".mo") else {
            continue;
        };
        if locale.is_empty()
            || locale.starts_with("admin-")
            || locale.starts_with("continents-cities-")
            || !fs::symlink_metadata(&path)?.is_file()
        {
            continue;
        }
        det.languages.push(locale.to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn w(root: &Path, rel: &str, body: &str) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }

    fn base() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        w(
            d.path(),
            "wp-includes/version.php",
            "<?php\n$wp_version = '6.8.1';\n$wp_db_version = 1;\n",
        );
        fs::create_dir_all(d.path().join("wp-content")).unwrap();
        d
    }

    fn pkg<'a>(d: &'a Detected, k: Kind, slug: &str) -> &'a LocalPackage {
        d.packages
            .iter()
            .find(|p| p.kind == k && p.slug == slug)
            .unwrap()
    }

    #[test]
    fn core_version_and_missing() {
        let d = base();
        assert_eq!(detect(d.path()).unwrap().wordpress, "6.8.1");
        let e = tempfile::tempdir().unwrap();
        let err = detect(e.path()).unwrap_err().to_string();
        assert!(err.starts_with("not a WordPress root:"), "{err}");
    }

    #[test]
    fn plugins() {
        let d = base();
        let r = d.path();
        w(r, "wp-content/plugins/index.php", "<?php // Silence");
        w(
            r,
            "wp-content/plugins/hello.php",
            "<?php\n/*\nPlugin Name: Hello\nVersion: 1.7\n*/",
        );
        w(r, "wp-content/plugins/foo/a-lib.php", "<?php // nothing");
        w(
            r,
            "wp-content/plugins/foo/foo.php",
            "<?php\n/**\n * Plugin Name: Foo\n * version:  2.3.4 \n */",
        );
        w(
            r,
            "wp-content/plugins/bar/bar.php",
            "<?php\n/* PLUGIN NAME: Bar */",
        );
        w(r, "wp-content/plugins/nohdr/x.php", "<?php");
        let det = detect(r).unwrap();
        let hello = pkg(&det, Kind::Plugin, "hello");
        assert!(hello.single_file);
        assert_eq!(hello.version.as_deref(), Some("1.7"));
        let foo = pkg(&det, Kind::Plugin, "foo");
        assert!(!foo.single_file);
        assert_eq!(foo.version.as_deref(), Some("2.3.4"));
        assert_eq!(foo.dir, r.join("wp-content/plugins/foo"));
        assert_eq!(pkg(&det, Kind::Plugin, "bar").version, None);
        assert!(
            det.packages
                .iter()
                .all(|p| p.slug != "index" && p.slug != "nohdr")
        );
        assert!(det.warnings.iter().any(|w| w.contains("nohdr")));
    }

    #[test]
    fn header_beyond_8k_ignored() {
        let d = base();
        let body = format!("<?php\n{}\n/* Plugin Name: Late */", " ".repeat(9000));
        w(d.path(), "wp-content/plugins/late/late.php", &body);
        let det = detect(d.path()).unwrap();
        assert!(det.packages.is_empty());
        assert!(det.warnings.iter().any(|w| w.contains("late")));
    }

    #[test]
    fn themes_and_mu() {
        let d = base();
        let r = d.path();
        w(
            r,
            "wp-content/themes/twenty/style.css",
            "/*\nTheme Name: Twenty\nVersion: 3.1\n*/",
        );
        w(r, "wp-content/themes/broken/style.css", "/* nothing */");
        w(r, "wp-content/themes/index.php", "<?php");
        w(
            r,
            "wp-content/mu-plugins/a.php",
            "<?php // Plugin Name: A\nVersion: 9",
        );
        w(r, "wp-content/mu-plugins/sub/b.php", "<?php");
        let det = detect(r).unwrap();
        assert_eq!(
            pkg(&det, Kind::Theme, "twenty").version.as_deref(),
            Some("3.1")
        );
        assert!(det.packages.iter().all(|p| p.slug != "broken"));
        let mu = pkg(&det, Kind::MuPlugin, "a");
        assert!(mu.single_file);
        assert_eq!(mu.dir, r.join("wp-content/mu-plugins/a.php"));
        assert!(det.warnings.iter().any(|w| {
            w.contains("mu-plugin directories are not supported; load them from a single file")
        }));
    }

    #[test]
    fn languages_dropins_other_dirs() {
        let d = base();
        let r = d.path();
        for f in [
            "hr.mo",
            "hr.po",
            "admin-hr.mo",
            "continents-cities-hr.mo",
            "de_DE.mo",
            "plugins/x-hr.mo",
            "advanced-cache.php",
            "object-cache.php",
            "other.php",
        ] {
            let rel = if f.contains('/') || f.ends_with(".php") {
                f.to_string()
            } else {
                format!("languages/{f}")
            };
            w(r, &format!("wp-content/{rel}"), "x");
        }
        for dd in [
            "uploads",
            "upgrade",
            "upgrade-temp-backup",
            "cache",
            "plugins",
            "themes",
            "mu-plugins",
            "languages",
            "w3tc-config",
            "wflogs",
        ] {
            fs::create_dir_all(r.join("wp-content").join(dd)).unwrap();
        }
        let det = detect(r).unwrap();
        assert_eq!(det.languages, vec!["de_DE", "hr"]);
        assert_eq!(det.dropins, vec!["advanced-cache.php", "object-cache.php"]);
        assert_eq!(det.other_content_dirs, vec!["w3tc-config", "wflogs"]);
    }

    #[test]
    fn symlinks_not_followed() {
        let d = base();
        let r = d.path();
        let out = tempfile::tempdir().unwrap();
        w(
            out.path(),
            "evil/evil.php",
            "<?php\n/* Plugin Name: Evil */",
        );
        fs::create_dir_all(r.join("wp-content/plugins")).unwrap();
        symlink(out.path().join("evil"), r.join("wp-content/plugins/evil")).unwrap();
        w(
            r,
            "wp-content/plugins/real/real.php",
            "<?php\n/* Plugin Name: Real */",
        );
        symlink(
            r.join("wp-content/plugins/real/real.php"),
            r.join("wp-content/plugins/link.php"),
        )
        .unwrap();
        symlink(out.path(), r.join("wp-content/linked-dir")).unwrap();
        let det = detect(r).unwrap();
        assert!(
            det.packages
                .iter()
                .all(|p| p.slug != "evil" && p.slug != "link")
        );
        assert!(
            det.warnings
                .iter()
                .any(|w| w.contains("evil") && w.contains("symlink"))
        );
        assert!(!det.other_content_dirs.contains(&"linked-dir".to_string()));
        assert!(det.warnings.iter().any(|w| w.contains("linked-dir")));
    }

    #[test]
    fn fix_round_1() {
        // double-quoted wp_version
        let d = tempfile::tempdir().unwrap();
        w(
            d.path(),
            "wp-includes/version.php",
            "<?php\n$wp_version = \"6.9\";",
        );
        fs::create_dir_all(d.path().join("wp-content")).unwrap();
        assert_eq!(detect(d.path()).unwrap().wordpress, "6.9");
        // missing $wp_version
        w(d.path(), "wp-includes/version.php", "<?php\n");
        assert!(
            detect(d.path())
                .unwrap_err()
                .to_string()
                .contains("wp_version")
        );
        // wp-content missing / symlink
        let e = tempfile::tempdir().unwrap();
        w(
            e.path(),
            "wp-includes/version.php",
            "<?php $wp_version = '1.0';",
        );
        let err = detect(e.path()).unwrap_err().to_string();
        assert_eq!(
            err,
            format!(
                "wp-content is missing or a symlink in {}; import cannot continue",
                e.path().display()
            )
        );
        let out = tempfile::tempdir().unwrap();
        symlink(out.path(), e.path().join("wp-content")).unwrap();
        assert!(detect(e.path()).is_err());
    }

    #[test]
    fn other_root_files_are_listed_with_dotfiles() {
        let d = base();
        let r = d.path();
        for f in [
            "index.php",
            "wp-config.php",
            "wp-login.php",
            "wp-settings.php",
            "xmlrpc.php",
            "license.txt",
            "readme.html",
            "wp-config-sample.php",
            "wp-admin/x.php",
            "google1234.html",
            "phpinfo.php",
            "wp-custom.php",
            ".well-known/acme-challenge/t",
            ".htaccess",
            "robots.txt",
        ] {
            w(r, f, "x");
        }
        let out = tempfile::tempdir().unwrap();
        symlink(out.path(), r.join("linked")).unwrap();
        let det = detect(r).unwrap();
        assert_eq!(
            det.other_root_files,
            vec![
                ".htaccess",
                ".well-known",
                "google1234.html",
                "linked",
                "phpinfo.php",
                "robots.txt",
                "wp-custom.php",
            ]
        );
    }

    #[test]
    fn fix_round_1_headers() {
        let d = base();
        let r = d.path();
        w(
            r,
            "wp-content/plugins/a.php",
            "<?php /* Plugin Name: A\n Version: 1.0 */",
        );
        w(
            r,
            "wp-content/plugins/b.php",
            "<?php // Plugin Name: B\r\n// Version: 2.0\r\n",
        );
        w(
            r,
            "wp-content/plugins/c.php",
            "<?php\r/* Plugin Name: C\rVersion: 3.0 */",
        );
        w(r, "wp-content/plugins/d.php", "<?php\n/* Plugin Name:   */");
        w(
            r,
            "wp-content/plugins/e.php",
            "<?php\n/* Plugin Name: E ?> junk",
        );
        w(r, "wp-content/plugins/plain.php", "<?php echo 1;");
        w(
            r,
            "wp-content/plugins/.hidden/h.php",
            "<?php /* Plugin Name: H */",
        );
        w(r, "wp-content/themes/.t/style.css", "Theme Name: T");
        w(r, "wp-content/mu-plugins/.m.php", "<?php");
        w(r, "wp-content/.git/x", "x");
        w(r, "wp-content/languages/admin-network-hr.mo", "x");
        w(r, "wp-content/languages/hr.mo", "x");
        let det = detect(r).unwrap();
        assert_eq!(pkg(&det, Kind::Plugin, "a").version.as_deref(), Some("1.0"));
        assert_eq!(pkg(&det, Kind::Plugin, "b").version.as_deref(), Some("2.0"));
        assert_eq!(pkg(&det, Kind::Plugin, "c").version.as_deref(), Some("3.0"));
        assert!(det.packages.iter().all(|p| p.slug != "d"));
        assert!(pkg(&det, Kind::Plugin, "e").single_file);
        assert!(
            det.warnings
                .iter()
                .any(|w| w == "plugins/plain.php: no plugin header found; skipped")
        );
        assert_eq!(det.packages.len(), 4);
        assert!(det.other_content_dirs.is_empty());
        assert_eq!(det.languages, vec!["hr"]);
        assert!(
            !det.warnings
                .iter()
                .any(|w| w.contains("hidden") || w.contains(".t") || w.contains(".m.php"))
        );
    }

    #[test]
    fn fix_round_1_symlinks() {
        let d = base();
        let r = d.path();
        let out = tempfile::tempdir().unwrap();
        symlink(out.path(), r.join("wp-content/plugins")).unwrap();
        symlink(out.path(), r.join("wp-content/uploads")).unwrap();
        w(r, "wp-content/real.php", "x");
        symlink(r.join("wp-content/real.php"), r.join("wp-content/db.php")).unwrap();
        w(r, "wp-content/plugins2/p.php", "x");
        let det = detect(r).unwrap();
        let has = |m: &str| det.warnings.iter().any(|w| w == m);
        assert!(has(
            "wp-content/plugins is a symlink; skipped (copy its contents into a real directory first)"
        ));
        assert!(has("wp-content/db.php is a symlink; drop-in skipped"));
        assert!(
            det.warnings
                .iter()
                .any(|w| w.contains("uploads") && w.contains("symlink"))
        );
        assert!(det.dropins.is_empty());
        // a symlinked single-file plugin warns
        let d = base();
        w(
            d.path(),
            "wp-content/plugins/real/real.php",
            "<?php\n/* Plugin Name: Real */",
        );
        symlink(
            d.path().join("wp-content/plugins/real/real.php"),
            d.path().join("wp-content/plugins/link.php"),
        )
        .unwrap();
        let det = detect(d.path()).unwrap();
        assert!(
            det.warnings
                .iter()
                .any(|w| w == "plugins/link.php is a symlink; skipped")
        );
    }
}
