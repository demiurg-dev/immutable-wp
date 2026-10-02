//! Decides whether a detected package is an unmodified wordpress.org release (a `version`
//! entry) or custom/modified code (a pinned `path` source). A modified package must never
//! classify as `Wporg`; a lookup failure other than "not found" is an error, never "clean".

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use super::detect::{Kind, LocalPackage};
use crate::build::sources::is_interpretable;
use crate::config::validate::{valid_pkg_version, valid_slug};
use crate::fetch::archive::{ExtractLimits, extract_zip};
use crate::fetch::wporg::WpOrg;
use crate::hash::{list_files, sha256_file};

#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// `local_only`: files of the local copy that the wordpress.org release does not list
    /// (never PHP; runtime files such as caches), which the release will not contain.
    Wporg {
        version: String,
        local_only: Vec<String>,
    },
    Source {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Classified {
    pub pkg: LocalPackage,
    pub verdict: Verdict,
}

/// One result per package, in order. `Err` means the wordpress.org lookup itself failed.
pub fn classify(w: &WpOrg, pkgs: &[LocalPackage]) -> Vec<Result<Classified>> {
    pkgs.iter()
        .map(|p| {
            classify_one(w, p)
                .map(|verdict| Classified {
                    pkg: p.clone(),
                    verdict,
                })
                .with_context(|| format!("classifying {:?} {}", p.kind, p.slug))
        })
        .collect()
}

fn source(reason: impl Into<String>) -> Result<Verdict> {
    Ok(Verdict::Source {
        reason: reason.into(),
    })
}

/// Symlinks and special files in the local tree make it custom code; any other local I/O
/// failure (permissions, ...) is an error for this package, never a verdict.
fn local_error(path: &Path, e: anyhow::Error) -> Result<Verdict> {
    let msg = format!("{e:#}");
    if msg.contains("symlink not allowed") || msg.contains("special file not allowed") {
        return source(format!("cannot classify local files: {msg}"));
    }
    Err(e.context(format!("reading {}", path.display())))
}

/// True only for a wordpress.org HTTP 404 (typed status error from the HTTP client).
fn is_not_found(e: &anyhow::Error) -> bool {
    matches!(
        e.downcast_ref::<ureq::Error>(),
        Some(ureq::Error::StatusCode(404))
    )
}

fn classify_one(w: &WpOrg, p: &LocalPackage) -> Result<Verdict> {
    // Slug and version come from an untrusted webroot and reach URL builders: validate first.
    if p.kind != Kind::MuPlugin
        && !p.single_file
        && let Some(v) = p.version.as_deref()
        && !(valid_slug(&p.slug) && valid_pkg_version(v))
    {
        return source("slug or version not usable on wordpress.org");
    }
    match p.kind {
        Kind::MuPlugin => source("mu-plugin"),
        _ if p.single_file => source("single-file package"),
        _ => {
            let Some(ver) = p.version.as_deref() else {
                return source("no version detected");
            };
            if p.kind == Kind::Plugin {
                plugin(w, p, ver)
            } else {
                theme(w, p, ver)
            }
        }
    }
}

fn plugin(w: &WpOrg, p: &LocalPackage, ver: &str) -> Result<Verdict> {
    let sums = match w.plugin_checksums(&p.slug, ver) {
        Ok(s) => s,
        Err(e) if is_not_found(&e) => return source(format!("not on wordpress.org at {ver}")),
        Err(e) => return Err(e),
    };
    let local = match list_files(&p.dir) {
        Ok(l) => l,
        Err(e) => return local_error(&p.dir, e),
    };
    let local_set: BTreeSet<&str> = local.iter().map(|(r, _)| r.as_str()).collect();
    let mut modified: Vec<&str> = Vec::new();
    let mut local_only: Vec<String> = Vec::new();
    for (rel, _) in &local {
        match sums.get(rel) {
            Some(allowed) => {
                let got = match sha256_file(&p.dir.join(rel)) {
                    Ok(h) => h,
                    Err(e) => return local_error(&p.dir.join(rel), e),
                };
                if !allowed.contains(&got) {
                    modified.push(rel);
                }
            }
            None if is_interpretable(rel) => return source(format!("unlisted PHP file {rel}")),
            None => local_only.push(rel.clone()),
        }
    }
    if let Some(missing) = sums.keys().find(|k| !local_set.contains(k.as_str())) {
        return source(format!("missing {missing}"));
    }
    if let Some(first) = modified.first() {
        let more = modified.len() - 1;
        return source(if more == 0 {
            format!("modified {first}")
        } else {
            format!("modified {first} (and {more} more)")
        });
    }
    Ok(Verdict::Wporg {
        version: ver.to_string(),
        local_only,
    })
}

/// File path -> sha256, ignoring modes (zip extraction and local installs differ in them).
fn content_map(root: &Path) -> Result<BTreeMap<String, String>> {
    list_files(root)?
        .into_iter()
        .map(|(rel, _)| {
            let h = sha256_file(&root.join(&rel))?;
            Ok((rel, h))
        })
        .collect()
}

fn theme(w: &WpOrg, p: &LocalPackage, ver: &str) -> Result<Verdict> {
    let zip = match w.theme_zip(&p.slug, ver) {
        Ok(z) => z,
        Err(e) if is_not_found(&e) => return source(format!("not on wordpress.org at {ver}")),
        Err(e) => return Err(e),
    };
    let differs = || source(format!("differs from wordpress.org {ver}"));
    let tmp = tempfile::Builder::new().prefix("iwp-classify-").tempdir()?;
    let dest = tmp.path().join(&p.slug);
    fs::create_dir_all(&dest)?;
    // A zip we cannot extract safely is not a match, but is not a lookup failure either.
    match extract_zip(&zip, &dest, &ExtractLimits::default()) {
        Ok(top) if top.as_deref() == Some(p.slug.as_str()) => {}
        Ok(_) => return source(format!("wordpress.org zip is not rooted at {}", p.slug)),
        Err(_) => return differs(),
    }
    let Ok(theirs) = content_map(&dest) else {
        return differs();
    };
    let ours = match content_map(&p.dir) {
        Ok(m) => m,
        Err(e) => return local_error(&p.dir, e),
    };
    if theirs == ours {
        Ok(Verdict::Wporg {
            version: ver.to_string(),
            local_only: Vec::new(),
        })
    } else {
        differs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetch::cache::Cache;
    use crate::fetch::net::Fetcher;
    use crate::fetch::wporg::{plugin_checksums_url, theme_zip_url};
    use crate::hash::sha256_hex;
    use crate::testutil::{FakeFetcher, make_zip, tmp};

    struct Down;
    impl Fetcher for Down {
        fn get(&self, _: &str) -> Result<Vec<u8>> {
            anyhow::bail!("connection refused")
        }
    }

    fn pkg(kind: Kind, slug: &str, dir: &Path) -> LocalPackage {
        LocalPackage {
            kind,
            slug: slug.into(),
            version: Some("1.0".into()),
            dir: dir.to_path_buf(),
            single_file: false,
        }
    }

    fn write(dir: &Path, files: &[(&str, &str)]) {
        for (n, c) in files {
            let p = dir.join(n);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, c).unwrap();
        }
    }

    fn sums_json(files: &[(&str, &str)]) -> String {
        let f: Vec<String> = files
            .iter()
            .map(|(n, c)| format!(r#""{n}":{{"sha256":"{}"}}"#, sha256_hex(c.as_bytes())))
            .collect();
        format!(r#"{{"files":{{{}}}}}"#, f.join(","))
    }

    fn run(f: &dyn Fetcher, p: LocalPackage) -> Result<Verdict> {
        let c = tmp();
        let cache = Cache::new(c.path());
        let w = WpOrg {
            fetcher: f,
            cache: &cache,
        };
        classify(&w, &[p]).remove(0).map(|c| c.verdict)
    }

    const FILES: [(&str, &str); 2] = [("p.php", "<?php a"), ("inc/b.js", "b")];

    fn plugin_case(local: &[(&str, &str)]) -> Result<Verdict> {
        let d = tmp();
        write(d.path(), local);
        let f = FakeFetcher::new().with(&plugin_checksums_url("p", "1.0"), sums_json(&FILES));
        run(&f, pkg(Kind::Plugin, "p", d.path()))
    }

    fn reason(v: Result<Verdict>) -> String {
        match v.unwrap() {
            Verdict::Source { reason } => reason,
            v => panic!("expected Source, got {v:?}"),
        }
    }

    #[test]
    fn exact_plugin_is_wporg() {
        assert_eq!(
            plugin_case(&FILES).unwrap(),
            Verdict::Wporg {
                version: "1.0".into(),
                local_only: vec![],
            }
        );
    }

    #[test]
    fn wporg_plugin_lists_local_only_runtime_files() {
        let mut l = FILES.to_vec();
        l.push(("cache/z.json", "{}"));
        l.push(("readme-local.txt", "x"));
        assert_eq!(
            plugin_case(&l).unwrap(),
            Verdict::Wporg {
                version: "1.0".into(),
                local_only: vec!["cache/z.json".into(), "readme-local.txt".into()],
            }
        );
    }

    #[test]
    fn modified_byte_is_source() {
        let r = reason(plugin_case(&[("p.php", "<?php b"), ("inc/b.js", "b")]));
        assert_eq!(r, "modified p.php");
        let r = reason(plugin_case(&[("p.php", "<?php b"), ("inc/b.js", "x")]));
        assert_eq!(r, "modified inc/b.js (and 1 more)");
    }

    #[test]
    fn unlisted_php_is_source_but_text_is_allowed() {
        let mut l = FILES.to_vec();
        l.push(("evil.php", "x"));
        assert_eq!(reason(plugin_case(&l)), "unlisted PHP file evil.php");
        let mut l = FILES.to_vec();
        l.push(("readme-local.txt", "x"));
        assert!(matches!(plugin_case(&l).unwrap(), Verdict::Wporg { .. }));
    }

    #[test]
    fn missing_listed_file_is_source() {
        assert_eq!(reason(plugin_case(&FILES[..1])), "missing inc/b.js");
    }

    #[test]
    fn not_found_is_source_and_network_error_is_err() {
        let d = tmp();
        write(d.path(), &FILES);
        let r = reason(run(&FakeFetcher::new(), pkg(Kind::Plugin, "p", d.path())));
        assert_eq!(r, "not on wordpress.org at 1.0");
        let e = run(&Down, pkg(Kind::Plugin, "p", d.path())).unwrap_err();
        assert!(format!("{e:#}").contains("connection refused"), "{e:#}");
        let e = run(&Down, pkg(Kind::Theme, "t", d.path())).unwrap_err();
        assert!(format!("{e:#}").contains("connection refused"), "{e:#}");
    }

    #[test]
    fn plain_text_404_is_not_treated_as_not_found() {
        struct Fake404;
        impl Fetcher for Fake404 {
            fn get(&self, _: &str) -> Result<Vec<u8>> {
                anyhow::bail!("proxy said 404 somewhere")
            }
        }
        let d = tmp();
        write(d.path(), &FILES);
        assert!(run(&Fake404, pkg(Kind::Plugin, "p", d.path())).is_err());
    }

    #[test]
    fn versionless_single_file_and_mu_are_source() {
        let d = tmp();
        let mut p = pkg(Kind::Plugin, "p", d.path());
        p.version = None;
        assert_eq!(reason(run(&Down, p)), "no version detected");
        let mut p = pkg(Kind::Plugin, "p", d.path());
        p.single_file = true;
        assert_eq!(reason(run(&Down, p)), "single-file package");
        let p = pkg(Kind::MuPlugin, "m", d.path());
        assert_eq!(reason(run(&Down, p)), "mu-plugin");
    }

    fn theme_case(local_fn: &str) -> Result<Verdict> {
        let d = tmp();
        write(d.path(), &[("style.css", "s"), ("functions.php", local_fn)]);
        let zip = make_zip(&[
            ("t/", b""),
            ("t/style.css", b"s"),
            ("t/functions.php", b"<?php f"),
        ]);
        let f = FakeFetcher::new().with(&theme_zip_url("t", "1.0"), zip);
        run(&f, pkg(Kind::Theme, "t", d.path()))
    }

    #[test]
    fn theme_equal_tree_is_wporg_even_with_different_modes() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp();
        write(
            d.path(),
            &[("style.css", "s"), ("functions.php", "<?php f")],
        );
        fs::set_permissions(
            d.path().join("style.css"),
            fs::Permissions::from_mode(0o664),
        )
        .unwrap();
        let zip = make_zip(&[("t/style.css", b"s"), ("t/functions.php", b"<?php f")]);
        let f = FakeFetcher::new().with(&theme_zip_url("t", "1.0"), zip);
        assert!(matches!(
            run(&f, pkg(Kind::Theme, "t", d.path())).unwrap(),
            Verdict::Wporg { .. }
        ));
        assert!(matches!(
            theme_case("<?php f").unwrap(),
            Verdict::Wporg { .. }
        ));
    }

    #[test]
    fn theme_edit_or_404_is_source() {
        assert_eq!(
            reason(theme_case("<?php EVIL")),
            "differs from wordpress.org 1.0"
        );
        let d = tmp();
        write(d.path(), &[("style.css", "s")]);
        let r = reason(run(&FakeFetcher::new(), pkg(Kind::Theme, "t", d.path())));
        assert_eq!(r, "not on wordpress.org at 1.0");
    }

    #[test]
    fn untrusted_slug_or_version_never_reaches_a_fetch() {
        let d = tmp();
        write(d.path(), &FILES);
        let f = FakeFetcher::new();
        let c = tmp();
        let cache = Cache::new(c.path());
        let w = WpOrg {
            fetcher: &f,
            cache: &cache,
        };
        let mut bad = pkg(Kind::Plugin, "p", d.path());
        bad.version = Some("5.0/../../evilslug/1.0#".into());
        let mut upper = pkg(Kind::Theme, "Evil", d.path());
        upper.version = Some("1.0".into());
        let mut dots = pkg(Kind::Plugin, "a..b", d.path());
        dots.version = Some("1.0".into());
        for r in classify(&w, &[bad, upper, dots]) {
            assert_eq!(
                r.unwrap().verdict,
                Verdict::Source {
                    reason: "slug or version not usable on wordpress.org".into()
                }
            );
        }
        assert!(f.calls().is_empty(), "{:?}", f.calls());
    }

    #[test]
    fn non_404_http_status_is_err() {
        struct Unavailable;
        impl Fetcher for Unavailable {
            fn get(&self, _: &str) -> Result<Vec<u8>> {
                Err(anyhow::Error::new(ureq::Error::StatusCode(503)).context("GET x"))
            }
        }
        let d = tmp();
        write(d.path(), &FILES);
        assert!(run(&Unavailable, pkg(Kind::Plugin, "p", d.path())).is_err());
        assert!(run(&Unavailable, pkg(Kind::Theme, "p", d.path())).is_err());
    }

    #[test]
    fn theme_zip_must_be_rooted_at_slug() {
        let d = tmp();
        write(d.path(), &[("style.css", "s")]);
        let zip = make_zip(&[("other/style.css", b"s")]);
        let f = FakeFetcher::new().with(&theme_zip_url("t", "1.0"), zip);
        assert_eq!(
            reason(run(&f, pkg(Kind::Theme, "t", d.path()))),
            "wordpress.org zip is not rooted at t"
        );
    }

    #[test]
    fn theme_extra_local_files_are_source() {
        for extra in [("evil.php", "x"), ("copy.php", "<?php f")] {
            let d = tmp();
            write(
                d.path(),
                &[("style.css", "s"), ("functions.php", "<?php f"), extra],
            );
            let zip = make_zip(&[("t/style.css", b"s"), ("t/functions.php", b"<?php f")]);
            let f = FakeFetcher::new().with(&theme_zip_url("t", "1.0"), zip);
            assert_eq!(
                reason(run(&f, pkg(Kind::Theme, "t", d.path()))),
                "differs from wordpress.org 1.0"
            );
        }
    }

    #[test]
    fn local_io_error_is_err_but_symlink_is_source() {
        let d = tmp();
        let missing = d.path().join("gone");
        let f = FakeFetcher::new().with(&plugin_checksums_url("p", "1.0"), sums_json(&FILES));
        assert!(run(&f, pkg(Kind::Plugin, "p", &missing)).is_err());
        write(d.path(), &FILES);
        std::os::unix::fs::symlink("p.php", d.path().join("ln")).unwrap();
        assert!(reason(run(&f, pkg(Kind::Plugin, "p", d.path()))).contains("symlink"));
    }
}
