//! Fetch, verify and stage one plugin/theme into the release being built.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};

use super::tofu::Tofu;
use crate::config::edit::PackageKind;
use crate::config::{Package, Source};
use crate::fetch::archive::{ExtractLimits, extract_zip, safe_rel};
use crate::fetch::cache::{Cache, Sha256Mismatch};
use crate::fetch::net::Fetcher;
use crate::fetch::wporg::{WpOrg, plugin_zip_url, theme_zip_url};
use crate::hash::{list_files, sha256_file, sha256_hex, tree_hash};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Origin {
    Wporg { version: String },
    Path { path: String },
    Git { url: String, rev: String },
    Url { url: String },
}

#[derive(Debug, Clone)]
pub struct Staged {
    pub origin: Origin,
    pub sha256: String,
    pub files_verified: usize,
    pub unlisted_files: Vec<String>,
}

pub struct SourceCtx<'a> {
    pub fetcher: &'a dyn Fetcher,
    pub cache: &'a Cache,
    pub tofu: RefCell<Tofu>,
}

impl SourceCtx<'_> {
    pub fn wporg(&self) -> WpOrg<'_> {
        WpOrg {
            fetcher: self.fetcher,
            cache: self.cache,
        }
    }
}

pub fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst).with_context(|| format!("creating {}", dst.display()))?;
    for (rel, exec) in list_files(src)? {
        let to = dst.join(&rel);
        if let Some(p) = to.parent() {
            fs::create_dir_all(p)?;
        }
        fs::copy(src.join(&rel), &to).with_context(|| format!("copying {rel}"))?;
        fs::set_permissions(
            &to,
            fs::Permissions::from_mode(if exec { 0o755 } else { 0o644 }),
        )?;
    }
    Ok(())
}

fn mismatch(kind: PackageKind, slug: &str, expected: &str, actual: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "{}[{slug}]: sha256 mismatch: site file pins {expected}, source is {actual}; if this change is intended run `iwp pin <site> {slug}`",
        kind.table()
    )
}

fn extract_expecting_slug(zip: &[u8], dest: &Path, slug: &str, what: &str) -> Result<()> {
    fs::create_dir_all(dest)?;
    let top =
        extract_zip(zip, dest, &ExtractLimits::default()).with_context(|| what.to_string())?;
    if top.as_deref() != Some(slug) {
        bail!("{what}: archive top-level directory is {top:?}, expected {slug:?}");
    }
    Ok(())
}

/// Extracts a `url` source zip; a single top-level directory must be named after the slug.
fn extract_url_zip(zip: &[u8], dest: &Path, slug: &str, what: &str) -> Result<()> {
    let top =
        extract_zip(zip, dest, &ExtractLimits::default()).with_context(|| what.to_string())?;
    if top.as_deref().is_some_and(|t| t != slug) {
        bail!("{what}: archive top-level directory is {top:?}, expected {slug:?}");
    }
    Ok(())
}

type Verified = (usize, Vec<String>);

/// Whether an unlisted file in a wordpress.org plugin may be executed by the web server and
/// is therefore rejected: interpretable extensions, `.htaccess` and `.user.ini`.
pub(crate) fn is_interpretable(rel: &str) -> bool {
    static INTERPRETABLE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(?i)\.(php[0-9]?|phtml|phar|inc)$").expect("static regex")
    });
    let base = rel.rsplit('/').next().unwrap_or(rel).to_ascii_lowercase();
    INTERPRETABLE.is_match(rel) || base == ".htaccess" || base == ".user.ini"
}

/// Extracts a wordpress.org plugin zip into a clean `dest` and checks it against the published
/// per-file checksums. Returns (files verified, unlisted files).
fn verify_wporg_plugin(
    zip: &[u8],
    sums: &BTreeMap<String, Vec<String>>,
    dest: &Path,
    slug: &str,
    what: &str,
) -> Result<Verified> {
    extract_expecting_slug(zip, dest, slug, what)?;
    for (file, allowed) in sums {
        if safe_rel(file).is_err() {
            bail!("{what}: invalid path in wordpress.org checksums: {file}");
        }
        let path = dest.join(file);
        if !path.is_file() {
            bail!("{what}: {file}: listed in wordpress.org checksums but missing");
        }
        let got = sha256_file(&path)?;
        if !allowed.contains(&got) {
            bail!("{what}: {file}: sha256 mismatch (expected one of {allowed:?}, got {got})");
        }
    }
    let listed: BTreeSet<&str> = sums.keys().map(String::as_str).collect();
    let unlisted: Vec<String> = list_files(dest)?
        .into_iter()
        .map(|(r, _)| r)
        .filter(|r| !listed.contains(r.as_str()))
        .collect();
    for file in &unlisted {
        if is_interpretable(file) {
            bail!("{what}: {file}: not in wordpress.org checksums (interpretable file rejected)");
        }
    }
    Ok((sums.len(), unlisted))
}

fn git_checkout(url: &str, rev: &str, into: &Path) -> Result<()> {
    git_checkout_with(url, rev, into, false)
}

/// `allow_file_protocol` exists for tests only; production always passes false.
fn git_checkout_with(url: &str, rev: &str, into: &Path, allow_file_protocol: bool) -> Result<()> {
    let allow = if allow_file_protocol {
        "protocol.file.allow=always"
    } else {
        "protocol.file.allow=never"
    };
    let git = |args: &[&str]| -> Result<bool> {
        let st = Command::new("git")
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.autocrlf=false",
                "-c",
                "core.symlinks=true",
            ])
            .args(args)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_SSH_COMMAND", "ssh -o BatchMode=yes")
            .status()
            .context("running git (is it installed?)")?;
        Ok(st.success())
    };
    let dir = into.to_str().context("non-UTF-8 temp path")?;
    if !git(&["init", "-q", dir])? {
        bail!("git init failed");
    }
    let fetched = git(&[
        "-C", dir, "-c", allow, "fetch", "-q", "--depth", "1", "--", url, rev,
    ])? || git(&[
        "-C",
        dir,
        "-c",
        allow,
        "fetch",
        "-q",
        "--",
        url,
        "+refs/heads/*:refs/remotes/origin/*",
        "+refs/tags/*:refs/tags/*",
    ])?;
    if !fetched {
        bail!("git fetch of {url} failed");
    }
    if !git(&[
        "-C",
        dir,
        "-c",
        "advice.detachedHead=false",
        "checkout",
        "-q",
        rev,
    ])? {
        bail!("git checkout of {rev} from {url} failed");
    }
    fs::remove_dir_all(into.join(".git"))?;
    Ok(())
}

pub fn stage_package(
    ctx: &SourceCtx,
    kind: PackageKind,
    p: &Package,
    dest: &Path,
) -> Result<Staged> {
    let slug = p.slug.as_str();
    match (&p.version, &p.source) {
        (Some(ver), None) => {
            let what = format!("{} {slug}@{ver}", kind.table());
            let w = ctx.wporg();
            match kind {
                PackageKind::Plugin => {
                    let url = plugin_zip_url(slug, ver);
                    let sums = w.plugin_checksums(slug, ver)?;
                    let mut from_cache = ctx.cache.has_url(&url);
                    loop {
                        let zip = w.plugin_zip(slug, ver)?;
                        let r = verify_wporg_plugin(&zip, &sums, dest, slug, &what);
                        // A cached zip is never trusted: any verification failure or any file
                        // wordpress.org does not list triggers one fresh download and a full re-run.
                        let retry = from_cache
                            && match &r {
                                Err(_) => true,
                                Ok((_, unlisted)) => !unlisted.is_empty(),
                            };
                        if !retry {
                            return match r {
                                Ok((n, unlisted)) => Ok(Staged {
                                    origin: Origin::Wporg {
                                        version: ver.clone(),
                                    },
                                    sha256: sha256_hex(&zip),
                                    files_verified: n,
                                    unlisted_files: unlisted,
                                }),
                                Err(e) => {
                                    // A corrupted download must be refetched next run.
                                    let _ = ctx.cache.evict_url(&url);
                                    Err(e)
                                }
                            };
                        }
                        ctx.cache.evict_url(&url)?;
                        super::remove_tree(dest)?;
                        from_cache = false;
                    }
                }
                PackageKind::Theme => {
                    let key = format!("theme:{slug}@{ver}");
                    let url = theme_zip_url(slug, ver);
                    let cached = ctx.cache.has_url(&url);
                    let mut zip = w.theme_zip(slug, ver)?;
                    let mut sha = sha256_hex(&zip);
                    let mut known = match ctx.tofu.borrow().verify(&key, &what, &sha) {
                        Ok(k) => k,
                        Err(first) => {
                            if !cached {
                                return Err(first);
                            }
                            // The cached blob may be poisoned: refetch once before blaming upstream.
                            let _ = ctx.cache.evict_url(&url);
                            zip = w.theme_zip(slug, ver)?;
                            sha = sha256_hex(&zip);
                            if ctx.tofu.borrow().verify(&key, &what, &sha).is_err() {
                                return Err(first);
                            }
                            true
                        }
                    };
                    if !known && cached {
                        // First use: never record a hash taken from an unverified cached blob.
                        ctx.cache.evict_url(&url)?;
                        zip = w.theme_zip(slug, ver)?;
                        sha = sha256_hex(&zip);
                        known = ctx.tofu.borrow().verify(&key, &what, &sha)?;
                    }
                    if let Err(e) = extract_expecting_slug(&zip, dest, slug, &what) {
                        let _ = ctx.cache.evict_url(&url);
                        return Err(e);
                    }
                    if !known {
                        ctx.tofu.borrow_mut().record(&key, &sha);
                    }
                    Ok(Staged {
                        origin: Origin::Wporg {
                            version: ver.clone(),
                        },
                        sha256: sha,
                        files_verified: 0,
                        unlisted_files: vec![],
                    })
                }
            }
        }
        (None, Some(source)) => {
            let expected = p
                .sha256
                .as_deref()
                .context("validated: sha256 present with source")?;
            let origin = match source {
                Source::Url { url } => {
                    let zip = ctx
                        .cache
                        .get_verified(ctx.fetcher, url, expected)
                        .map_err(|e| match e.downcast_ref::<Sha256Mismatch>() {
                            Some(m) => anyhow::anyhow!(
                                "{}[{slug}]: sha256 mismatch for {url}: site file pins {expected}, source is {}; if this change is intended run `iwp pin <site> {slug}`",
                                kind.table(),
                                m.got
                            ),
                            None => e.context(format!("{}[{slug}]", kind.table())),
                        })?;
                    fs::create_dir_all(dest)?;
                    extract_url_zip(&zip, dest, slug, &format!("{}[{slug}] {url}", kind.table()))?;
                    Origin::Url { url: url.clone() }
                }
                Source::Path { path } if p.mu => {
                    let meta = fs::symlink_metadata(path)
                        .with_context(|| format!("{}[{slug}] {}", kind.table(), path.display()))?;
                    if !meta.file_type().is_file() {
                        bail!(
                            "{}[{slug}]: mu-plugin path source must be a regular file (not a symlink or directory)",
                            kind.table()
                        );
                    }
                    let bytes =
                        fs::read(path).with_context(|| format!("reading {}", path.display()))?;
                    let got = sha256_hex(&bytes);
                    if got != expected {
                        return Err(mismatch(kind, slug, expected, &got));
                    }
                    if let Some(parent) = dest.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::write(dest, &bytes)?;
                    fs::set_permissions(dest, fs::Permissions::from_mode(0o644))?;
                    Origin::Path {
                        path: path.display().to_string(),
                    }
                }
                Source::Path { path } => {
                    if !fs::symlink_metadata(path)
                        .map(|m| m.file_type().is_dir())
                        .unwrap_or(false)
                    {
                        bail!(
                            "{}[{slug}]: path source must be a directory (only mu-plugins may be single files)",
                            kind.table()
                        );
                    }
                    copy_tree(path, dest)
                        .with_context(|| format!("{}[{slug}] {}", kind.table(), path.display()))?;
                    let got = tree_hash(dest)?;
                    if got != expected {
                        return Err(mismatch(kind, slug, expected, &got));
                    }
                    Origin::Path {
                        path: path.display().to_string(),
                    }
                }
                Source::Git { git, rev } => {
                    let tmp = tempfile::Builder::new().prefix("iwp-git-").tempdir()?;
                    let co = tmp.path().join("co");
                    git_checkout(git, rev, &co)
                        .with_context(|| format!("{}[{slug}]", kind.table()))?;
                    let got = tree_hash(&co)?;
                    if got != expected {
                        return Err(mismatch(kind, slug, expected, &got));
                    }
                    copy_tree(&co, dest)?;
                    Origin::Git {
                        url: git.clone(),
                        rev: rev.clone(),
                    }
                }
            };
            Ok(Staged {
                origin,
                sha256: expected.to_string(),
                files_verified: 0,
                unlisted_files: vec![],
            })
        }
        _ => bail!(
            "{}[{slug}]: invalid package (run `iwp validate`)",
            kind.table()
        ),
    }
}

pub fn source_hash(ctx: &SourceCtx, p: &Package) -> Result<String> {
    match p
        .source
        .as_ref()
        .context("only `source` packages can be pinned")?
    {
        Source::Url { url } => {
            // Always fetch fresh: the vendor may have changed the bytes since the last pin.
            let bytes = ctx.fetcher.get(url)?;
            let probe = tempfile::Builder::new().prefix("iwp-pin-").tempdir()?;
            extract_url_zip(
                &bytes,
                probe.path(),
                &p.slug,
                &format!("{url} is not usable"),
            )?;
            let sha = sha256_hex(&bytes);
            // Store it content-addressed so the next build does not download it again.
            ctx.cache.put_verified(&sha, &bytes)?;
            Ok(sha)
        }
        Source::Path { path } if p.mu => Ok(sha256_file(path)?),
        Source::Path { path } => tree_hash(path),
        Source::Git { git, rev } => {
            let tmp = tempfile::Builder::new().prefix("iwp-git-").tempdir()?;
            let co = tmp.path().join("co");
            git_checkout(git, rev, &co)?;
            tree_hash(&co)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::edit::PackageKind;
    use crate::config::{Package, Source};
    use crate::fetch::wporg::{plugin_checksums_url, plugin_zip_url, theme_zip_url};
    use crate::hash::{sha256_hex, tree_hash};
    use crate::testutil::{FakeFetcher, make_zip, tmp};

    fn wp(slug: &str, ver: &str) -> Package {
        Package {
            slug: slug.into(),
            version: Some(ver.into()),
            source: None,
            sha256: None,
            writable: vec![],
            cache: vec![],
            mu: false,
            hold: false,
        }
    }
    fn src(slug: &str, s: Source, sha: &str) -> Package {
        Package {
            slug: slug.into(),
            version: None,
            source: Some(s),
            sha256: Some(sha.into()),
            writable: vec![],
            cache: vec![],
            mu: false,
            hold: false,
        }
    }
    fn plugin_fixture() -> (Vec<u8>, String) {
        let zip = make_zip(&[
            ("gt/", b""),
            ("gt/gt.php", b"<?php // main"),
            ("gt/build/a.js", b"a"),
            ("gt/readme.txt", b"r"),
        ]);
        let sums = format!(
            r#"{{"files":{{"gt.php":{{"sha256":"{}"}},"build/a.js":{{"sha256":["x","{}"]}}}}}}"#,
            sha256_hex(b"<?php // main"),
            sha256_hex(b"a")
        );
        (zip, sums)
    }
    fn ctx<'a>(f: &'a FakeFetcher, cache: &'a Cache, tofu_path: &Path) -> SourceCtx<'a> {
        SourceCtx {
            fetcher: f,
            cache,
            tofu: std::cell::RefCell::new(Tofu::load(tofu_path).unwrap()),
        }
    }

    #[test]
    fn wporg_plugin_verified_per_file() {
        let (zip, sums) = plugin_fixture();
        let f = FakeFetcher::new()
            .with(&plugin_zip_url("gt", "1.0"), zip.clone())
            .with(&plugin_checksums_url("gt", "1.0"), sums);
        let t = tmp();
        let cache = Cache::new(&t.path().join("cache"));
        let c = ctx(&f, &cache, &t.path().join("tofu.json"));
        let dest = t.path().join("plugins/gt");
        let s = stage_package(&c, PackageKind::Plugin, &wp("gt", "1.0"), &dest).unwrap();
        assert_eq!(
            s.origin,
            Origin::Wporg {
                version: "1.0".into()
            }
        );
        assert_eq!(s.sha256, sha256_hex(&zip));
        assert_eq!(s.files_verified, 2);
        assert_eq!(s.unlisted_files, vec!["readme.txt".to_string()]);
        assert!(dest.join("build/a.js").is_file());
    }

    #[test]
    fn wporg_plugin_tampered_or_missing_file_fails() {
        let (_, sums) = plugin_fixture();
        let tampered = make_zip(&[("gt/gt.php", b"<?php evil();"), ("gt/build/a.js", b"a")]);
        let f = FakeFetcher::new()
            .with(&plugin_zip_url("gt", "1.0"), tampered)
            .with(&plugin_checksums_url("gt", "1.0"), sums.clone());
        let t = tmp();
        let cache = Cache::new(&t.path().join("cache"));
        let err = stage_package(
            &ctx(&f, &cache, &t.path().join("tofu.json")),
            PackageKind::Plugin,
            &wp("gt", "1.0"),
            &t.path().join("d"),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("plugin gt@1.0")
                && msg.contains("gt.php")
                && msg.contains("sha256 mismatch"),
            "{msg}"
        );

        let missing = make_zip(&[("gt/gt.php", b"<?php // main")]);
        let f = FakeFetcher::new()
            .with(&plugin_zip_url("gt", "1.0"), missing)
            .with(&plugin_checksums_url("gt", "1.0"), sums);
        let t = tmp();
        let cache = Cache::new(&t.path().join("cache"));
        let err = stage_package(
            &ctx(&f, &cache, &t.path().join("tofu.json")),
            PackageKind::Plugin,
            &wp("gt", "1.0"),
            &t.path().join("d"),
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("build/a.js") && format!("{err:#}").contains("missing"),
            "{err:#}"
        );
    }

    #[test]
    fn wporg_zip_top_dir_must_match_slug() {
        let (_, sums) = plugin_fixture();
        let wrong = make_zip(&[
            ("other/gt.php", b"<?php // main"),
            ("other/build/a.js", b"a"),
        ]);
        let f = FakeFetcher::new()
            .with(&plugin_zip_url("gt", "1.0"), wrong)
            .with(&plugin_checksums_url("gt", "1.0"), sums);
        let t = tmp();
        let cache = Cache::new(&t.path().join("cache"));
        let err = stage_package(
            &ctx(&f, &cache, &t.path().join("tofu.json")),
            PackageKind::Plugin,
            &wp("gt", "1.0"),
            &t.path().join("d"),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("other"), "{err:#}");
    }

    #[test]
    fn theme_tofu_records_then_detects_change() {
        let t = tmp();
        let tofu_path = t.path().join("tofu.json");
        let z1 = make_zip(&[("th/style.css", b"v1")]);
        let f = FakeFetcher::new().with(&theme_zip_url("th", "1.0"), z1.clone());
        let cache = Cache::new(&t.path().join("cache"));
        let c = ctx(&f, &cache, &tofu_path);
        stage_package(
            &c,
            PackageKind::Theme,
            &wp("th", "1.0"),
            &t.path().join("a"),
        )
        .unwrap();
        c.tofu.borrow().save().unwrap();
        assert!(
            std::fs::read_to_string(&tofu_path)
                .unwrap()
                .contains(&sha256_hex(&z1))
        );

        let z2 = make_zip(&[("th/style.css", b"v2")]);
        let f2 = FakeFetcher::new().with(&theme_zip_url("th", "1.0"), z2);
        let cache2 = Cache::new(&t.path().join("cache2"));
        let err = stage_package(
            &ctx(&f2, &cache2, &tofu_path),
            PackageKind::Theme,
            &wp("th", "1.0"),
            &t.path().join("b"),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("theme th@1.0")
                && msg.contains("changed since first use")
                && msg.contains("tofu.json"),
            "{msg}"
        );
    }

    #[test]
    fn url_source_verified() {
        let t = tmp();
        let zip = make_zip(&[("prem/prem.php", b"<?php")]);
        let url = "https://vendor.example/prem.zip";
        let f = FakeFetcher::new().with(url, zip.clone());
        let cache = Cache::new(&t.path().join("cache"));
        let c = ctx(&f, &cache, &t.path().join("tofu.json"));
        let ok = stage_package(
            &c,
            PackageKind::Plugin,
            &src("prem", Source::Url { url: url.into() }, &sha256_hex(&zip)),
            &t.path().join("p"),
        )
        .unwrap();
        assert!(t.path().join("p/prem.php").is_file());
        assert_eq!(ok.origin, Origin::Url { url: url.into() });
        let err = stage_package(
            &c,
            PackageKind::Plugin,
            &src("prem", Source::Url { url: url.into() }, &"0".repeat(64)),
            &t.path().join("q"),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("sha256 mismatch"), "{err:#}");
    }

    #[test]
    fn path_dir_and_file_sources() {
        let t = tmp();
        let srcdir = t.path().join("src/custom");
        std::fs::create_dir_all(srcdir.join("inc")).unwrap();
        std::fs::write(srcdir.join("custom.php"), "<?php").unwrap();
        std::fs::write(srcdir.join("inc/x.php"), "<?php").unwrap();
        let h = tree_hash(&srcdir).unwrap();
        let f = FakeFetcher::new();
        let cache = Cache::new(&t.path().join("cache"));
        let c = ctx(&f, &cache, &t.path().join("tofu.json"));
        stage_package(
            &c,
            PackageKind::Plugin,
            &src(
                "custom",
                Source::Path {
                    path: srcdir.clone(),
                },
                &h,
            ),
            &t.path().join("out/custom"),
        )
        .unwrap();
        assert!(t.path().join("out/custom/inc/x.php").is_file());
        assert_eq!(
            source_hash(
                &c,
                &src(
                    "custom",
                    Source::Path {
                        path: srcdir.clone()
                    },
                    &h
                )
            )
            .unwrap(),
            h
        );

        std::fs::write(srcdir.join("inc/x.php"), "<?php changed();").unwrap();
        let err = stage_package(
            &c,
            PackageKind::Plugin,
            &src(
                "custom",
                Source::Path {
                    path: srcdir.clone(),
                },
                &h,
            ),
            &t.path().join("out2/custom"),
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("iwp pin <site> custom"),
            "{err:#}"
        );

        let mu = t.path().join("src/tweaks.php");
        std::fs::write(&mu, "<?php // mu").unwrap();
        let mut p = src(
            "tweaks",
            Source::Path { path: mu.clone() },
            &sha256_hex(b"<?php // mu"),
        );
        p.mu = true;
        stage_package(
            &c,
            PackageKind::Plugin,
            &p,
            &t.path().join("mu-plugins/tweaks.php"),
        )
        .unwrap();
        assert_eq!(
            std::fs::read(t.path().join("mu-plugins/tweaks.php")).unwrap(),
            b"<?php // mu"
        );
    }

    #[test]
    fn path_source_with_symlink_rejected() {
        let t = tmp();
        let srcdir = t.path().join("src/s");
        std::fs::create_dir_all(&srcdir).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", srcdir.join("leak")).unwrap();
        let f = FakeFetcher::new();
        let cache = Cache::new(&t.path().join("cache"));
        let c = ctx(&f, &cache, &t.path().join("tofu.json"));
        let err = stage_package(
            &c,
            PackageKind::Plugin,
            &src("s", Source::Path { path: srcdir }, &"0".repeat(64)),
            &t.path().join("o"),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("symlink"), "{err:#}");
    }

    #[test]
    fn git_source_from_local_repo_via_file_protocol_is_refused() {
        let _spawn = crate::testutil::spawn_guard();
        // Real repo with a real commit: only `protocol.file.allow=never` may make this fail.
        let t = tmp();
        let repo = t.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("a.php"), "<?php").unwrap();
        let git = |args: &[&str]| {
            let o = std::process::Command::new("git")
                .args(["-c", "user.name=t", "-c", "user.email=t@t"])
                .args(args)
                .current_dir(&repo)
                .output()
                .unwrap();
            assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
            String::from_utf8(o.stdout).unwrap().trim().to_string()
        };
        git(&["init", "-q"]);
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "x"]);
        let rev = git(&["rev-parse", "HEAD"]);
        let f = FakeFetcher::new();
        let cache = Cache::new(&t.path().join("cache"));
        let c = ctx(&f, &cache, &t.path().join("tofu.json"));
        let p = src(
            "g",
            Source::Git {
                git: format!("file://{}", repo.display()),
                rev,
            },
            &"0".repeat(64),
        );
        let err = stage_package(&c, PackageKind::Plugin, &p, &t.path().join("o")).unwrap_err();
        assert!(format!("{err:#}").contains("fetch"), "{err:#}");
    }

    fn sums_json(entries: &[(&str, &str)]) -> String {
        let f: Vec<String> = entries
            .iter()
            .map(|(k, h)| {
                format!(
                    r#"{}:{{"sha256":"{h}"}}"#,
                    serde_json::to_string(k).unwrap()
                )
            })
            .collect();
        format!(r#"{{"files":{{{}}}}}"#, f.join(","))
    }
    fn stage_plugin_zip(
        zip: Vec<u8>,
        sums: String,
    ) -> (Result<Staged>, std::path::PathBuf, tempfile::TempDir) {
        let f = FakeFetcher::new()
            .with(&plugin_zip_url("gt", "1.0"), zip)
            .with(&plugin_checksums_url("gt", "1.0"), sums);
        let t = tmp();
        let cache = Cache::new(&t.path().join("cache"));
        let d = t.path().join("d");
        let r = stage_package(
            &ctx(&f, &cache, &t.path().join("tofu.json")),
            PackageKind::Plugin,
            &wp("gt", "1.0"),
            &d,
        );
        (r, d, t)
    }

    #[test]
    fn unlisted_interpretable_files_rejected_and_evicted() {
        let good = sha256_hex(b"<?php // main");
        for bad in [
            "gt/evil.php",
            "gt/sub/X.PHTML",
            "gt/a.php5",
            "gt/.user.ini",
            "gt/sub/.htaccess",
            "gt/lib.inc",
            "gt/p.phar",
        ] {
            let zip = make_zip(&[("gt/gt.php", b"<?php // main"), (bad, b"x")]);
            let (r, _, t) = stage_plugin_zip(zip, sums_json(&[("gt.php", &good)]));
            let msg = format!("{:#}", r.unwrap_err());
            assert!(
                msg.contains("plugin gt@1.0")
                    && msg.contains("not in wordpress.org checksums (interpretable file rejected)"),
                "{bad}: {msg}"
            );
            let n = std::fs::read_dir(t.path().join("cache/url"))
                .map(|d| d.count())
                .unwrap_or(0);
            assert_eq!(n, 0, "zip must be evicted ({bad})");
        }
        let zip = make_zip(&[
            ("gt/gt.php", b"<?php // main"),
            ("gt/readme.txt", b"r"),
            ("gt/img/a.png", b"p"),
        ]);
        let (r, _, _) = stage_plugin_zip(zip, sums_json(&[("gt.php", &good)]));
        assert_eq!(
            r.unwrap().unlisted_files,
            vec!["img/a.png".to_string(), "readme.txt".to_string()]
        );
    }

    #[test]
    fn unsafe_checksum_keys_rejected() {
        let zip = make_zip(&[("gt/gt.php", b"<?php // main")]);
        let h = sha256_hex(b"<?php // main");
        for key in ["../x", "/etc/passwd"] {
            let (r, _, _) = stage_plugin_zip(zip.clone(), sums_json(&[(key, &h)]));
            let msg = format!("{:#}", r.unwrap_err());
            assert!(
                msg.contains("invalid path in wordpress.org checksums") && msg.contains(key),
                "{msg}"
            );
        }
    }

    #[test]
    fn theme_poisoned_cache_is_refetched_but_real_change_fails() {
        let t = tmp();
        let tofu_path = t.path().join("tofu.json");
        let z1 = make_zip(&[("th/style.css", b"v1")]);
        let url = theme_zip_url("th", "1.0");
        let f = FakeFetcher::new().with(&url, z1.clone());
        let cache = Cache::new(&t.path().join("cache"));
        let c = ctx(&f, &cache, &tofu_path);
        stage_package(
            &c,
            PackageKind::Theme,
            &wp("th", "1.0"),
            &t.path().join("a"),
        )
        .unwrap();
        c.tofu.borrow().save().unwrap();
        // poison the cached blob
        let blob = t.path().join("cache/url").join(sha256_hex(url.as_bytes()));
        std::fs::write(&blob, make_zip(&[("th/style.css", b"evil")])).unwrap();
        let s = stage_package(
            &ctx(&f, &cache, &tofu_path),
            PackageKind::Theme,
            &wp("th", "1.0"),
            &t.path().join("b"),
        )
        .unwrap();
        assert_eq!(s.sha256, sha256_hex(&z1));
        assert_eq!(std::fs::read(t.path().join("b/style.css")).unwrap(), b"v1");
        // genuine upstream change (fresh cache)
        let f2 = FakeFetcher::new().with(&url, make_zip(&[("th/style.css", b"v2")]));
        let err = stage_package(
            &ctx(&f2, &Cache::new(&t.path().join("cache2")), &tofu_path),
            PackageKind::Theme,
            &wp("th", "1.0"),
            &t.path().join("c"),
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("changed since first use"),
            "{err:#}"
        );
    }

    #[test]
    fn theme_not_recorded_when_extraction_fails() {
        let t = tmp();
        let tofu_path = t.path().join("tofu.json");
        let f = FakeFetcher::new().with(
            &theme_zip_url("th", "1.0"),
            make_zip(&[("other/style.css", b"v1")]),
        );
        let cache = Cache::new(&t.path().join("cache"));
        let c = ctx(&f, &cache, &tofu_path);
        assert!(
            stage_package(
                &c,
                PackageKind::Theme,
                &wp("th", "1.0"),
                &t.path().join("a")
            )
            .is_err()
        );
        c.tofu.borrow().save().unwrap();
        assert!(
            !std::fs::read_to_string(&tofu_path)
                .unwrap()
                .contains("theme:th@1.0")
        );
    }

    #[test]
    fn path_kind_must_match_mu_flag() {
        let t = tmp();
        let f = FakeFetcher::new();
        let cache = Cache::new(&t.path().join("cache"));
        let c = ctx(&f, &cache, &t.path().join("tofu.json"));
        let file = t.path().join("one.php");
        std::fs::write(&file, "<?php").unwrap();
        let err = stage_package(
            &c,
            PackageKind::Plugin,
            &src(
                "one",
                Source::Path { path: file.clone() },
                &sha256_hex(b"<?php"),
            ),
            &t.path().join("o/one"),
        )
        .unwrap_err();
        assert!(
            format!("{err:#}")
                .contains("path source must be a directory (only mu-plugins may be single files)"),
            "{err:#}"
        );

        let dir = t.path().join("adir.php");
        std::fs::create_dir_all(&dir).unwrap();
        let mut p = src("adir", Source::Path { path: dir }, &"0".repeat(64));
        p.mu = true;
        assert!(stage_package(&c, PackageKind::Plugin, &p, &t.path().join("mu/adir.php")).is_err());

        let link = t.path().join("link.php");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        let mut p = src("link", Source::Path { path: link }, &sha256_hex(b"<?php"));
        p.mu = true;
        let err =
            stage_package(&c, PackageKind::Plugin, &p, &t.path().join("mu/link.php")).unwrap_err();
        assert!(format!("{err:#}").contains("regular file"), "{err:#}");
    }

    #[test]
    fn corrupted_cached_wporg_zip_is_evicted() {
        let (good, sums) = plugin_fixture();
        let bad = make_zip(&[("gt/gt.php", b"<?php evil();"), ("gt/build/a.js", b"a")]);
        let t = tmp();
        let cache = Cache::new(&t.path().join("cache"));
        let f = FakeFetcher::new()
            .with(&plugin_zip_url("gt", "1.0"), bad)
            .with(&plugin_checksums_url("gt", "1.0"), sums.clone());
        assert!(
            stage_package(
                &ctx(&f, &cache, &t.path().join("tofu.json")),
                PackageKind::Plugin,
                &wp("gt", "1.0"),
                &t.path().join("d1")
            )
            .is_err()
        );
        let f2 = FakeFetcher::new()
            .with(&plugin_zip_url("gt", "1.0"), good)
            .with(&plugin_checksums_url("gt", "1.0"), sums);
        let s = stage_package(
            &ctx(&f2, &cache, &t.path().join("tofu.json")),
            PackageKind::Plugin,
            &wp("gt", "1.0"),
            &t.path().join("d2"),
        )
        .unwrap();
        assert_eq!(s.files_verified, 2);
    }

    const VURL: &str = "https://vendor.example/prem.zip";

    fn pkg_url(slug: &str, sha: &str) -> Package {
        src(slug, Source::Url { url: VURL.into() }, sha)
    }

    #[test]
    fn repin_url_returns_fresh_hash_and_build_needs_no_refetch() {
        let t = tmp();
        let cache = Cache::new(&t.path().join("cache"));
        let v1 = make_zip(&[("prem/a.php", b"<?php // v1")]);
        let v2 = make_zip(&[("prem/a.php", b"<?php // v2")]);
        let p = pkg_url("prem", &"0".repeat(64));
        let f1 = FakeFetcher::new().with(VURL, v1.clone());
        let h1 = source_hash(&ctx(&f1, &cache, &t.path().join("t.json")), &p).unwrap();
        assert_eq!(h1, sha256_hex(&v1));
        let f2 = FakeFetcher::new().with(VURL, v2.clone());
        let c2 = ctx(&f2, &cache, &t.path().join("t.json"));
        let h2 = source_hash(&c2, &p).unwrap();
        assert_eq!(
            h2,
            sha256_hex(&v2),
            "re-pin must see the vendor's new bytes"
        );
        assert_eq!(f2.calls().len(), 1);
        // the next build uses the verified copy stored by pin: no further fetch
        stage_package(
            &c2,
            PackageKind::Plugin,
            &pkg_url("prem", &h2),
            &t.path().join("out"),
        )
        .unwrap();
        assert_eq!(f2.calls().len(), 1, "build must not refetch after pin");
        assert_eq!(
            std::fs::read(t.path().join("out/a.php")).unwrap(),
            b"<?php // v2"
        );
    }

    #[test]
    fn url_mismatch_suggests_pin() {
        let t = tmp();
        let cache = Cache::new(&t.path().join("cache"));
        let f = FakeFetcher::new().with(VURL, make_zip(&[("prem/a.php", b"x")]));
        let err = stage_package(
            &ctx(&f, &cache, &t.path().join("t.json")),
            PackageKind::Plugin,
            &pkg_url("prem", &"0".repeat(64)),
            &t.path().join("o"),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("sha256 mismatch")
                && msg.contains("; if this change is intended run `iwp pin <site> prem`"),
            "{msg}"
        );
    }

    #[test]
    fn url_zip_top_dir_must_equal_slug_and_macosx_ignored() {
        let t = tmp();
        let cache = Cache::new(&t.path().join("cache"));
        let wrong = make_zip(&[("other/a.php", b"x")]);
        let f = FakeFetcher::new().with(VURL, wrong.clone());
        let err = stage_package(
            &ctx(&f, &cache, &t.path().join("t.json")),
            PackageKind::Plugin,
            &pkg_url("prem", &sha256_hex(&wrong)),
            &t.path().join("o"),
        )
        .unwrap_err();
        assert!(
            format!("{err:#}")
                .contains("archive top-level directory is Some(\"other\"), expected \"prem\""),
            "{err:#}"
        );
        assert!(
            source_hash(
                &ctx(&f, &cache, &t.path().join("t.json")),
                &pkg_url("prem", "x")
            )
            .is_err()
        );

        let mac = make_zip(&[("__MACOSX/prem/._a.php", b"j"), ("prem/a.php", b"x")]);
        let f = FakeFetcher::new().with(VURL, mac.clone());
        stage_package(
            &ctx(&f, &cache, &t.path().join("t.json")),
            PackageKind::Plugin,
            &pkg_url("prem", &sha256_hex(&mac)),
            &t.path().join("ok"),
        )
        .unwrap();
        assert!(t.path().join("ok/a.php").is_file());
        assert!(!t.path().join("ok/__MACOSX").exists());
    }

    fn poison_url_cache(t: &Path, url: &str, bytes: Vec<u8>) {
        let blob = t.join("cache/url").join(sha256_hex(url.as_bytes()));
        std::fs::create_dir_all(blob.parent().unwrap()).unwrap();
        std::fs::write(blob, bytes).unwrap();
    }

    #[test]
    fn poisoned_cached_plugin_zip_with_extra_file_is_refetched() {
        let (good, sums) = plugin_fixture();
        let poisoned = make_zip(&[
            ("gt/gt.php", b"<?php // main"),
            ("gt/build/a.js", b"a"),
            ("gt/readme.txt", b"r"),
            ("gt/x.html", b"<script>evil</script>"),
        ]);
        let t = tmp();
        let url = plugin_zip_url("gt", "1.0");
        poison_url_cache(t.path(), &url, poisoned);
        let f = FakeFetcher::new()
            .with(&url, good.clone())
            .with(&plugin_checksums_url("gt", "1.0"), sums);
        let cache = Cache::new(&t.path().join("cache"));
        let d = t.path().join("d");
        let s = stage_package(
            &ctx(&f, &cache, &t.path().join("tofu.json")),
            PackageKind::Plugin,
            &wp("gt", "1.0"),
            &d,
        )
        .unwrap();
        assert!(!d.join("x.html").exists(), "poisoned file must not ship");
        assert_eq!(s.unlisted_files, vec!["readme.txt".to_string()]);
        assert_eq!(s.sha256, sha256_hex(&good));
    }

    #[test]
    fn fresh_plugin_zip_with_unlisted_files_is_fetched_once() {
        let (good, sums) = plugin_fixture();
        let f = FakeFetcher::new()
            .with(&plugin_zip_url("gt", "1.0"), good)
            .with(&plugin_checksums_url("gt", "1.0"), sums);
        let t = tmp();
        let cache = Cache::new(&t.path().join("cache"));
        let s = stage_package(
            &ctx(&f, &cache, &t.path().join("tofu.json")),
            PackageKind::Plugin,
            &wp("gt", "1.0"),
            &t.path().join("d"),
        )
        .unwrap();
        assert_eq!(s.unlisted_files.len(), 1);
        let zips = f
            .calls()
            .iter()
            .filter(|c| **c == plugin_zip_url("gt", "1.0"))
            .count();
        assert_eq!(
            zips, 1,
            "no redundant refetch when the zip was just downloaded"
        );
    }

    #[test]
    fn cached_unlisted_files_persisting_in_fresh_copy_are_accepted() {
        let (good, sums) = plugin_fixture();
        let t = tmp();
        let cache = Cache::new(&t.path().join("cache"));
        let f = FakeFetcher::new()
            .with(&plugin_zip_url("gt", "1.0"), good.clone())
            .with(&plugin_checksums_url("gt", "1.0"), sums);
        let c = ctx(&f, &cache, &t.path().join("tofu.json"));
        stage_package(
            &c,
            PackageKind::Plugin,
            &wp("gt", "1.0"),
            &t.path().join("d1"),
        )
        .unwrap();
        let s = stage_package(
            &c,
            PackageKind::Plugin,
            &wp("gt", "1.0"),
            &t.path().join("d2"),
        )
        .unwrap();
        assert_eq!(s.unlisted_files, vec!["readme.txt".to_string()]);
        assert!(t.path().join("d2/readme.txt").is_file());
    }

    #[test]
    fn theme_first_use_with_poisoned_cache_records_fresh_bytes() {
        let t = tmp();
        let tofu_path = t.path().join("tofu.json");
        let url = theme_zip_url("th", "1.0");
        let good = make_zip(&[("th/style.css", b"good")]);
        poison_url_cache(t.path(), &url, make_zip(&[("th/style.css", b"evil")]));
        let f = FakeFetcher::new().with(&url, good.clone());
        let cache = Cache::new(&t.path().join("cache"));
        let c = ctx(&f, &cache, &tofu_path);
        let s = stage_package(
            &c,
            PackageKind::Theme,
            &wp("th", "1.0"),
            &t.path().join("a"),
        )
        .unwrap();
        c.tofu.borrow().save().unwrap();
        assert_eq!(s.sha256, sha256_hex(&good));
        assert_eq!(
            std::fs::read(t.path().join("a/style.css")).unwrap(),
            b"good"
        );
        let rec = std::fs::read_to_string(&tofu_path).unwrap();
        assert!(rec.contains(&sha256_hex(&good)) && !rec.contains(&sha256_hex(b"evil")));
    }

    #[test]
    fn cached_tampered_listed_file_retries_fresh_once() {
        let (good, sums) = plugin_fixture();
        let bad = make_zip(&[("gt/gt.php", b"<?php evil();"), ("gt/build/a.js", b"a")]);
        let url = plugin_zip_url("gt", "1.0");
        // network copy is good: first build succeeds
        let t = tmp();
        poison_url_cache(t.path(), &url, bad.clone());
        let f = FakeFetcher::new()
            .with(&url, good)
            .with(&plugin_checksums_url("gt", "1.0"), sums.clone());
        let cache = Cache::new(&t.path().join("cache"));
        let s = stage_package(
            &ctx(&f, &cache, &t.path().join("tofu.json")),
            PackageKind::Plugin,
            &wp("gt", "1.0"),
            &t.path().join("d"),
        )
        .unwrap();
        assert_eq!(s.files_verified, 2);
        // network copy is bad too: fails
        let t = tmp();
        poison_url_cache(t.path(), &url, bad.clone());
        let f = FakeFetcher::new()
            .with(&url, bad)
            .with(&plugin_checksums_url("gt", "1.0"), sums);
        let cache = Cache::new(&t.path().join("cache"));
        let err = stage_package(
            &ctx(&f, &cache, &t.path().join("tofu.json")),
            PackageKind::Plugin,
            &wp("gt", "1.0"),
            &t.path().join("d"),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("sha256 mismatch"), "{err:#}");
    }

    #[test]
    fn git_fallback_fetches_non_head_branches() {
        let _spawn = crate::testutil::spawn_guard();
        let d = tmp();
        let repo = d.path().join("repo");
        let g = |args: &[&str]| {
            let o = Command::new("git")
                .arg("-C")
                .arg(&repo)
                .args(["-c", "user.name=t", "-c", "user.email=t@e"])
                .args(args)
                .output()
                .unwrap();
            assert!(
                o.status.success(),
                "{args:?}: {}",
                String::from_utf8_lossy(&o.stderr)
            );
            String::from_utf8(o.stdout).unwrap()
        };
        fs::create_dir(&repo).unwrap();
        g(&["init", "-q", "-b", "main"]);
        fs::write(repo.join("a"), "main").unwrap();
        g(&["add", "a"]);
        g(&["commit", "-q", "-m", "m"]);
        g(&["checkout", "-q", "-b", "side"]);
        fs::write(repo.join("b"), "side").unwrap();
        g(&["add", "b"]);
        g(&["commit", "-q", "-m", "s"]);
        let sha = g(&["rev-parse", "HEAD"]).trim().to_string();
        g(&["checkout", "-q", "main"]);
        // An abbreviated sha cannot be fetched directly, forcing the fallback path.
        let into = d.path().join("co");
        git_checkout_with(repo.to_str().unwrap(), &sha[..10], &into, true).unwrap();
        assert_eq!(fs::read_to_string(into.join("b")).unwrap(), "side");
        assert!(!into.join(".git").exists());
    }
}
