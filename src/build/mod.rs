//! Release building: verified, read-only release directories.

pub mod core;
pub mod pin;
pub mod sources;
pub mod tofu;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use include_dir::{Dir, include_dir};
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use crate::config::edit::PackageKind;
use crate::config::{GlobalConfig, Site, shared_rel};
use crate::fetch::archive::{ExtractLimits, extract_zip};
use crate::fetch::cache::Cache;
use crate::fetch::net::Fetcher;
use crate::fetch::wporg::{TransKind, Translation};
use crate::hash::{list_files, sha256_file, sha256_hex, tree_hash};
use regex::Regex;
use sources::{Origin, SourceCtx, stage_package};
use tofu::Tofu;

pub(crate) static MU_PLUGIN: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/share/mu-plugin");

pub trait ImageOps {
    /// Makes sure the images exist and returns the ID of the fpm image.
    fn ensure(&self, wp: &str, php: &str) -> Result<String>;
    /// Copies the webroot out of exactly the image `image` (the ID `ensure` returned).
    fn export_webroot(&self, image: &str, dest: &Path) -> Result<()>;
}

pub struct BuildEnv<'a> {
    pub global: &'a GlobalConfig,
    pub fetcher: &'a dyn Fetcher,
    pub images: &'a dyn ImageOps,
    pub now: jiff::Timestamp,
    /// Suppresses the `[site] step` progress lines on stderr.
    pub quiet: bool,
}

impl BuildEnv<'_> {
    fn step(&self, site: &str, what: &str) {
        if !self.quiet {
            eprintln!("[{site}] {what}");
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PackageRecord {
    pub kind: String,
    pub slug: String,
    pub mu: bool,
    pub origin: Origin,
    pub sha256: String,
    pub files_verified: usize,
    pub unlisted_files: Vec<String>,
    /// `tree_hash` of the staged package directory (`sha256_file` for single-file mu-plugins).
    pub tree_sha256: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct LanguageRecord {
    pub kind: String,
    pub slug: Option<String>,
    pub language: String,
    pub version: String,
    pub url: String,
    pub sha256: String,
    /// `tree_hash` of the translation files this pack installed.
    pub tree_sha256: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ReleaseManifest {
    pub iwp_version: String,
    pub site: String,
    pub release: String,
    pub built_at: String,
    pub wordpress: String,
    pub php: String,
    pub image: String,
    pub image_digest: String,
    pub core_files_verified: usize,
    pub packages: Vec<PackageRecord>,
    pub languages: Vec<LanguageRecord>,
    pub dropins: Vec<String>,
    /// Every regular file in the release (relative path -> sha256), except this manifest.
    pub files: BTreeMap<String, String>,
}

#[derive(Debug)]
pub struct BuiltRelease {
    pub name: String,
    pub path: PathBuf,
    pub manifest: ReleaseManifest,
}

pub fn release_name(site: &Site, now: jiff::Timestamp) -> String {
    let digest = sha256_hex(&serde_json::to_vec(site).expect("Site serializes"));
    format!("{}-{}", now.strftime("%Y%m%d-%H%M%S"), &digest[..7])
}

pub fn remove_tree(path: &Path) -> Result<()> {
    let md = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("inspecting {}", path.display())),
    };
    if !md.is_dir() {
        // A file or a symlink (never followed): remove just that entry.
        return fs::remove_file(path).with_context(|| format!("removing {}", path.display()));
    }
    for e in WalkDir::new(path)
        .follow_links(false)
        .follow_root_links(false)
    {
        let e = e?;
        if e.file_type().is_dir() {
            fs::set_permissions(e.path(), fs::Permissions::from_mode(0o755))?;
        }
    }
    fs::remove_dir_all(path).with_context(|| format!("removing {}", path.display()))
}

fn make_read_only(root: &Path) -> Result<()> {
    // Files first, then directories bottom-up, so we can still traverse while changing modes.
    for e in WalkDir::new(root)
        .follow_links(false)
        .follow_root_links(false)
        .contents_first(true)
    {
        let e = e?;
        let ft = e.file_type();
        if ft.is_symlink() {
            continue;
        }
        let mode = if ft.is_dir() || e.metadata()?.permissions().mode() & 0o111 != 0 {
            0o555
        } else {
            0o444
        };
        fs::set_permissions(e.path(), fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

pub fn build_release(env: &BuildEnv, site: &Site) -> Result<BuiltRelease> {
    let base = site.base_dir(env.global);
    let releases = base.join("releases");
    fs::create_dir_all(&releases).with_context(|| format!("creating {}", releases.display()))?;
    crate::host::fsx::mkdirs_nofollow(&base, Path::new("shared/uploads"))?;
    for w in site.writable_paths() {
        crate::host::fsx::mkdirs_nofollow(&base, &Path::new("shared").join(shared_rel(w)))?;
    }
    let lock = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(releases.join(".iwp-build.lock"))
        .context("opening build lock")?;
    let lock = match lock.try_lock() {
        Ok(()) => crate::host::lock::FileLock::held(lock),
        Err(fs::TryLockError::WouldBlock) => {
            bail!("another build for site {} is in progress", site.name)
        }
        Err(fs::TryLockError::Error(e)) => return Err(e).context("locking build lock"),
    };
    // Under the lock, any `.partial` is a leftover of an interrupted build.
    for e in fs::read_dir(&releases)? {
        let e = e?;
        if e.file_name().to_string_lossy().ends_with(".partial") {
            remove_tree(&e.path())?;
        }
    }
    let name = release_name(site, env.now);
    let final_path = releases.join(&name);
    if final_path.exists() {
        bail!("release {name} already exists");
    }
    let partial = releases.join(format!("{name}.partial"));
    fs::create_dir(&partial)?;
    let result = assemble(env, site, &partial, &name).and_then(|(m, tofu)| {
        make_read_only(&partial)?;
        fs::rename(&partial, &final_path)
            .with_context(|| format!("renaming {}", partial.display()))?;
        Ok((m, tofu))
    });
    match result {
        Ok((manifest, tofu)) => {
            // Only record trust-on-first-use hashes once the release really exists. The release
            // is complete at this point, so a failure here must not make the build look failed.
            if let Err(e) = tofu.save() {
                eprintln!("warning: could not save TOFU store: {e:#}");
            }
            drop(lock);
            Ok(BuiltRelease {
                name,
                path: final_path,
                manifest,
            })
        }
        Err(e) => match remove_tree(&partial) {
            Ok(()) => Err(e),
            Err(re) => Err(e.context(format!(
                "also failed to remove {}: {re:#}",
                partial.display()
            ))),
        },
    }
}

pub(crate) fn symlink_target(rel: &str) -> String {
    let parent_depth = Path::new(rel)
        .parent()
        .map_or(0, |p| p.components().count());
    format!(
        "{}shared/{}",
        "../".repeat(parent_depth + 2),
        shared_rel(rel)
    )
}

fn assemble(
    env: &BuildEnv,
    site: &Site,
    root: &Path,
    name: &str,
) -> Result<(ReleaseManifest, Tofu)> {
    let (wp, php) = (site.core.wordpress.as_str(), site.core.php.as_str());
    let cache = Cache::new(&env.global.cache_dir);
    let ctx = SourceCtx {
        fetcher: env.fetcher,
        cache: &cache,
        tofu: RefCell::new(Tofu::load(&env.global.cache_dir.join("tofu.json"))?),
    };
    let wporg = ctx.wporg();

    // The ID is what gets exported and what the manifest records: one image, no tag race.
    env.step(&site.name, "image");
    let image_digest = env
        .images
        .ensure(wp, php)
        .context("preparing container image")?;
    env.step(&site.name, "core");
    let web = root.join(".iwp-webroot");
    env.images
        .export_webroot(&image_digest, &web)
        .context("exporting core from image")?;
    let core_files_verified = core::verify_core(&wporg.core_checksums(wp)?, &web)?;
    core::copy_static(&web.join("wp-admin"), &root.join("wp-admin"))?;
    core::copy_static(&web.join("wp-includes"), &root.join("wp-includes"))?;
    remove_tree(&web)?;

    let wc = root.join("wp-content");
    for d in [
        "plugins",
        "themes",
        "mu-plugins",
        "languages/plugins",
        "languages/themes",
    ] {
        fs::create_dir_all(wc.join(d))?;
    }

    let mut packages = Vec::new();
    for (kind, list) in [
        (PackageKind::Plugin, &site.plugins),
        (PackageKind::Theme, &site.themes),
    ] {
        for p in list {
            let dest = if p.mu {
                if p.slug == "iwp" {
                    bail!("plugin[iwp]: the mu-plugin name `iwp` is reserved");
                }
                wc.join("mu-plugins").join(format!("{}.php", p.slug))
            } else {
                wc.join(format!("{}s", kind.table())).join(&p.slug)
            };
            env.step(&site.name, &format!("{} {}", kind.table(), p.slug));
            let s = stage_package(&ctx, kind, p, &dest)?;
            let tree_sha256 = if p.mu {
                sha256_file(&dest)?
            } else {
                tree_hash(&dest)?
            };
            packages.push(PackageRecord {
                kind: kind.table().into(),
                slug: p.slug.clone(),
                mu: p.mu,
                origin: s.origin,
                sha256: s.sha256,
                files_verified: s.files_verified,
                unlisted_files: s.unlisted_files,
                tree_sha256,
            });
        }
    }
    let mu_src = MU_PLUGIN.get_file("iwp.php").expect("bundled mu-plugin");
    fs::write(wc.join("mu-plugins/iwp.php"), mu_src.contents())?;

    env.step(&site.name, "languages");
    let mut languages = Vec::new();
    for lang in &site.core.languages {
        let pick = |ts: Vec<Translation>| ts.into_iter().find(|t| &t.language == lang);
        let core_t = pick(wporg.translations(TransKind::Core, None, wp)?)
            .with_context(|| format!("no {lang} core translation for WordPress {wp}"))?;
        languages.push(install_translation(
            &wporg,
            &core_t,
            "core",
            None,
            &wc.join("languages"),
        )?);
        for (kind, tk, list, sub) in [
            (
                PackageKind::Plugin,
                TransKind::Plugin,
                &site.plugins,
                "plugins",
            ),
            (PackageKind::Theme, TransKind::Theme, &site.themes, "themes"),
        ] {
            for p in list.iter().filter(|p| p.version.is_some() && !p.mu) {
                let ver = p.version.as_deref().expect("filtered");
                if let Some(t) = pick(wporg.translations(tk, Some(&p.slug), ver)?) {
                    languages.push(install_translation(
                        &wporg,
                        &t,
                        kind.table(),
                        Some(&p.slug),
                        &wc.join("languages").join(sub),
                    )?);
                }
            }
        }
    }

    env.step(&site.name, "dropins");
    let mut dropins = Vec::new();
    for (dname, d) in &site.dropins {
        let from = wc.join("plugins").join(&d.plugin).join(&d.file);
        if !from.is_file() {
            bail!("drop-in {dname}: {}/{} not found", d.plugin, d.file);
        }
        fs::copy(&from, wc.join(dname))?;
        dropins.push(dname.clone());
    }

    std::os::unix::fs::symlink("../../../shared/uploads", wc.join("uploads"))?;
    for w in site.writable_paths() {
        let link = root.join(w);
        fs::create_dir_all(link.parent().expect("writable has a parent"))?;
        std::os::unix::fs::symlink(symlink_target(w), &link)?;
    }

    env.step(&site.name, "finalize");
    let files = release_files(root)?;
    let manifest = ReleaseManifest {
        iwp_version: env!("CARGO_PKG_VERSION").into(),
        site: site.name.clone(),
        release: name.to_string(),
        built_at: env.now.to_string(),
        wordpress: wp.into(),
        php: php.into(),
        image: site.fpm_image(),
        image_digest,
        core_files_verified,
        packages,
        languages,
        dropins,
        files,
    };
    fs::write(
        root.join(".iwp-release.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok((manifest, ctx.tofu.into_inner()))
}

/// sha256 of every regular file (symlinks are not followed or listed), for a later `iwp verify`.
fn release_files(root: &Path) -> Result<BTreeMap<String, String>> {
    let mut files = BTreeMap::new();
    for e in WalkDir::new(root)
        .follow_links(false)
        .follow_root_links(false)
    {
        let e = e?;
        if !e.file_type().is_file() {
            continue;
        }
        let rel = e
            .path()
            .strip_prefix(root)
            .expect("walkdir yields paths under root")
            .to_str()
            .context("non-UTF-8 path in release")?
            .to_string();
        if rel == ".iwp-release.json" {
            continue;
        }
        let sha = sha256_file(e.path())?;
        files.insert(rel, sha);
    }
    Ok(files)
}

fn install_translation(
    w: &crate::fetch::wporg::WpOrg,
    t: &Translation,
    kind: &str,
    slug: Option<&str>,
    dest: &Path,
) -> Result<LanguageRecord> {
    let zip = w.translation_zip(t)?;
    let staging = tempfile::Builder::new().prefix("iwp-lang-").tempdir()?;
    let top = extract_zip(&zip, staging.path(), &ExtractLimits::default())
        .with_context(|| format!("translation {}", t.package))?;
    if let Some(top) = top {
        bail!(
            "translation {}: unexpected directory {top:?} (packs must be flat)",
            t.package
        );
    }
    let allowed = Regex::new(r"^[A-Za-z0-9._@-]+\.(mo|po|json|l10n\.php)$").expect("static regex");
    let files = list_files(staging.path()).with_context(|| format!("translation {}", t.package))?;
    for (rel, _) in &files {
        if !allowed.is_match(rel) {
            bail!(
                "translation {}: unexpected file {rel:?} (only .mo, .po, .json and .l10n.php files in the top level are allowed)",
                t.package
            );
        }
    }
    // Installed files are 0644, so hash them that way (tree_hash records the exec bit).
    for (rel, _) in &files {
        fs::set_permissions(staging.path().join(rel), fs::Permissions::from_mode(0o644))?;
    }
    let tree_sha256 = tree_hash(staging.path())?;
    fs::create_dir_all(dest)?;
    for (rel, _) in &files {
        let to = dest.join(rel);
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&to)
            .with_context(|| {
                format!(
                    "translation {}: {rel} already exists in {}",
                    t.package,
                    dest.display()
                )
            })?;
        let mut src = fs::File::open(staging.path().join(rel))?;
        std::io::copy(&mut src, &mut out)?;
        fs::set_permissions(&to, fs::Permissions::from_mode(0o644))?;
    }
    Ok(LanguageRecord {
        kind: kind.into(),
        slug: slug.map(str::to_string),
        language: t.language.clone(),
        version: t.version.clone(),
        url: t.package.clone(),
        sha256: sha256_hex(&zip),
        tree_sha256,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::{GlobalConfig, parse_site};
    use crate::fetch::wporg::{
        TransKind, core_checksums_url, plugin_checksums_url, plugin_zip_url, theme_zip_url,
        translations_url,
    };
    use crate::hash::{md5_hex, sha256_hex};
    use crate::testutil::{FakeFetcher, make_zip, tmp};
    use std::cell::Cell;
    use std::os::unix::fs::PermissionsExt;

    struct FakeImages {
        ensured: Cell<u32>,
        extra_php: bool,
        exported_from: std::cell::RefCell<Vec<String>>,
    }
    impl FakeImages {
        fn new(extra_php: bool) -> Self {
            Self {
                ensured: Cell::new(0),
                extra_php,
                exported_from: Default::default(),
            }
        }
    }
    impl ImageOps for FakeImages {
        fn ensure(&self, _wp: &str, _php: &str) -> Result<String> {
            self.ensured.set(self.ensured.get() + 1);
            Ok("sha256:deadbeef".into())
        }
        fn export_webroot(&self, image: &str, dest: &Path) -> Result<()> {
            self.exported_from.borrow_mut().push(image.to_string());
            for (p, body) in core_files() {
                let path = dest.join(p);
                std::fs::create_dir_all(path.parent().unwrap())?;
                std::fs::write(path, body)?;
            }
            std::fs::write(dest.join("wp-config.php"), "<?php // iwp")?;
            if self.extra_php {
                std::fs::write(dest.join("wp-includes/backdoor.php"), "<?php")?;
            }
            Ok(())
        }
    }
    fn core_files() -> Vec<(&'static str, &'static [u8])> {
        vec![
            ("index.php", b"<?php // index"),
            ("wp-admin/css/a.css", b"css"),
            ("wp-admin/index.php", b"<?php // admin"),
            ("wp-includes/js/b.js", b"js"),
            ("wp-includes/version.php", b"<?php // ver"),
        ]
    }
    fn core_checksums_json() -> String {
        let mut m = serde_json::Map::new();
        for (p, b) in core_files() {
            m.insert(p.into(), md5_hex(b).into());
        }
        m.insert("wp-content/plugins/hello.php".into(), "ignored".into());
        serde_json::json!({ "checksums": m }).to_string()
    }

    const SITE: &str = r#"
name    = "t"
domains = ["t.example.org"]
id      = 7
[core]
wordpress = "7.1.2"
php       = "8.3"
languages = ["hr"]
[[plugin]]
slug     = "gt"
version  = "1.0"
writable = ["wp-content/cache/gt"]
[[theme]]
slug    = "th"
version = "2.0"
[dropins]
"object-cache.php" = { plugin = "gt", file = "drop/object-cache.php" }
"#;

    fn fetcher() -> FakeFetcher {
        let pzip = make_zip(&[
            ("gt/gt.php", b"<?php // gt"),
            ("gt/drop/object-cache.php", b"<?php // oc"),
        ]);
        let psums = format!(
            r#"{{"files":{{"gt.php":{{"sha256":"{}"}},"drop/object-cache.php":{{"sha256":"{}"}}}}}}"#,
            sha256_hex(b"<?php // gt"),
            sha256_hex(b"<?php // oc")
        );
        let tzip = make_zip(&[("th/style.css", b"/* th */")]);
        let core_hr = make_zip(&[("hr.mo", b"mo"), ("admin-hr.mo", b"mo2")]);
        let gt_hr = make_zip(&[("gt-hr.mo", b"gtmo")]);
        let tr = |kind, slug: Option<&str>, ver, lang: &str, pkg: &str| {
            (
                translations_url(kind, slug, ver),
                format!(
                    r#"{{"translations":[{{"language":"{lang}","version":"{ver}","package":"{pkg}"}}]}}"#
                ),
            )
        };
        let (u1, b1) = tr(
            TransKind::Core,
            None,
            "7.1.2",
            "hr",
            "https://downloads.wordpress.org/translation/core/7.1.2/hr.zip",
        );
        let (u2, b2) = tr(
            TransKind::Plugin,
            Some("gt"),
            "1.0",
            "hr",
            "https://downloads.wordpress.org/translation/plugin/gt/1.0/hr.zip",
        );
        let (u3, b3) = tr(
            TransKind::Theme,
            Some("th"),
            "2.0",
            "de_DE",
            "https://downloads.wordpress.org/translation/theme/th/2.0/de_DE.zip",
        );
        FakeFetcher::new()
            .with(&core_checksums_url("7.1.2"), core_checksums_json())
            .with(&plugin_zip_url("gt", "1.0"), pzip)
            .with(&plugin_checksums_url("gt", "1.0"), psums)
            .with(&theme_zip_url("th", "2.0"), tzip)
            .with(&u1, b1)
            .with(&u2, b2)
            .with(&u3, b3)
            .with(
                "https://downloads.wordpress.org/translation/core/7.1.2/hr.zip",
                core_hr,
            )
            .with(
                "https://downloads.wordpress.org/translation/plugin/gt/1.0/hr.zip",
                gt_hr,
            )
    }

    /// A minimal valid manifest for `site` (no packages), as other modules' tests need.
    pub(crate) fn sample_manifest(site: &Site, name: &str) -> ReleaseManifest {
        ReleaseManifest {
            iwp_version: env!("CARGO_PKG_VERSION").into(),
            site: site.name.clone(),
            release: name.into(),
            built_at: "2026-10-01T10:00:00Z".into(),
            wordpress: site.core.wordpress.clone(),
            php: site.core.php.clone(),
            image: site.fpm_image(),
            // Distinct per release, so tests can tell which release's image a quadlet runs.
            image_digest: format!("sha256:{}", sha256_hex(name.as_bytes())),
            core_files_verified: 0,
            packages: vec![],
            languages: vec![],
            dropins: vec![],
            files: BTreeMap::new(),
        }
    }

    fn global(root: &Path) -> GlobalConfig {
        GlobalConfig {
            base_root: root.join("vhosts"),
            cache_dir: root.join("cache"),
            ..GlobalConfig::default()
        }
    }
    fn now() -> jiff::Timestamp {
        "2026-09-30T12:34:56Z".parse().unwrap()
    }

    #[test]
    fn release_name_format() {
        let _spawn = crate::testutil::spawn_guard();
        let site = parse_site(SITE).unwrap();
        let n = release_name(&site, now());
        assert!(
            n.starts_with("20260930-123456-") && n.len() == "20260930-123456-".len() + 7,
            "{n}"
        );
        assert_eq!(n, release_name(&site, now()), "deterministic");
    }

    #[test]
    fn builds_complete_read_only_release() {
        let _spawn = crate::testutil::spawn_guard();
        let t = tmp();
        let g = global(t.path());
        let f = fetcher();
        let images = FakeImages::new(false);
        let site = parse_site(SITE).unwrap();
        let env = BuildEnv {
            global: &g,
            fetcher: &f,
            images: &images,
            now: now(),
            quiet: true,
        };
        let r = build_release(&env, &site).unwrap();
        let root = &r.path;
        assert_eq!(root, &g.base_root.join("t/releases").join(&r.name));
        // core static only
        assert!(root.join("wp-admin/css/a.css").is_file());
        assert!(root.join("wp-includes/js/b.js").is_file());
        assert!(!root.join("wp-admin/index.php").exists() && !root.join("index.php").exists());
        // packages, mu, languages, dropins
        assert!(root.join("wp-content/plugins/gt/gt.php").is_file());
        assert!(root.join("wp-content/themes/th/style.css").is_file());
        assert!(root.join("wp-content/mu-plugins/iwp.php").is_file());
        assert!(root.join("wp-content/languages/hr.mo").is_file());
        assert!(root.join("wp-content/languages/plugins/gt-hr.mo").is_file());
        assert!(
            !root
                .join("wp-content/languages/themes")
                .read_dir()
                .unwrap()
                .any(|_| true),
            "de_DE theme pack not requested"
        );
        assert_eq!(
            std::fs::read(root.join("wp-content/object-cache.php")).unwrap(),
            b"<?php // oc"
        );
        // symlinks
        assert_eq!(
            std::fs::read_link(root.join("wp-content/uploads")).unwrap(),
            Path::new("../../../shared/uploads")
        );
        assert_eq!(
            std::fs::read_link(root.join("wp-content/cache/gt")).unwrap(),
            Path::new("../../../../shared/cache/gt")
        );
        assert!(g.base_root.join("t/shared/cache/gt").is_dir());
        // read-only
        let m = |p: &Path| std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(m(root), 0o555);
        assert_eq!(m(&root.join("wp-content/plugins/gt/gt.php")), 0o444);
        // manifest
        let man: ReleaseManifest =
            serde_json::from_slice(&std::fs::read(root.join(".iwp-release.json")).unwrap())
                .unwrap();
        assert_eq!(man, r.manifest);
        assert_eq!(man.image_digest, "sha256:deadbeef");
        assert_eq!(man.core_files_verified, 5);
        assert_eq!(man.packages.len(), 2);
        assert_eq!(
            man.languages
                .iter()
                .map(|l| l.kind.as_str())
                .collect::<Vec<_>>(),
            vec!["core", "plugin"]
        );
        assert_eq!(man.dropins, vec!["object-cache.php"]);
        assert_eq!(man.built_at, "2026-09-30T12:34:56Z");
        assert_eq!(images.ensured.get(), 1);
        assert_eq!(
            *images.exported_from.borrow(),
            vec!["sha256:deadbeef".to_string()],
            "export must use the image ID that ensure returned and the manifest records"
        );
        // no partial left, tofu saved
        assert!(
            !g.base_root
                .join("t/releases")
                .join(format!("{}.partial", r.name))
                .exists()
        );
        assert!(g.cache_dir.join("tofu.json").is_file());
    }

    #[test]
    fn shared_symlink_is_refused_and_target_untouched() {
        let _spawn = crate::testutil::spawn_guard();
        let t = tmp();
        let g = global(t.path());
        let f = fetcher();
        let images = FakeImages::new(false);
        let site = parse_site(&SITE.replace("wp-content/cache/gt", "wp-content/wflogs")).unwrap();
        let base = g.base_root.join("t");
        let target = t.path().join("target");
        std::fs::create_dir_all(base.join("shared")).unwrap();
        std::fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&target, base.join("shared/wflogs")).unwrap();
        let err = build_release(
            &BuildEnv {
                global: &g,
                fetcher: &f,
                images: &images,
                now: now(),
                quiet: true,
            },
            &site,
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("refusing to follow symlink"),
            "{err:#}"
        );
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);
    }

    #[test]
    fn failure_removes_partial_and_keeps_existing_releases() {
        let _spawn = crate::testutil::spawn_guard();
        let t = tmp();
        let g = global(t.path());
        let site = parse_site(SITE).unwrap();
        let releases = g.base_root.join("t/releases");
        std::fs::create_dir_all(releases.join("20200101-000000-aaaaaaa")).unwrap();
        std::fs::write(releases.join("20200101-000000-aaaaaaa/keep"), "x").unwrap();
        // tampered plugin → failure after core was copied
        let f = fetcher().with(
            &plugin_zip_url("gt", "1.0"),
            make_zip(&[
                ("gt/gt.php", b"<?php evil"),
                ("gt/drop/object-cache.php", b"<?php // oc"),
            ]),
        );
        let images = FakeImages::new(false);
        let err = build_release(
            &BuildEnv {
                global: &g,
                fetcher: &f,
                images: &images,
                now: now(),
                quiet: true,
            },
            &site,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("sha256 mismatch"), "{err:#}");
        let names: Vec<_> = std::fs::read_dir(&releases)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n != ".iwp-build.lock")
            .collect();
        assert_eq!(names, vec!["20200101-000000-aaaaaaa"]);
        assert!(releases.join("20200101-000000-aaaaaaa/keep").is_file());
    }

    #[test]
    fn stale_partial_is_replaced_and_duplicate_name_refused() {
        let _spawn = crate::testutil::spawn_guard();
        let t = tmp();
        let g = global(t.path());
        let site = parse_site(SITE).unwrap();
        let name = release_name(&site, now());
        let stale = g
            .base_root
            .join("t/releases")
            .join(format!("{name}.partial"));
        std::fs::create_dir_all(stale.join("ro")).unwrap();
        std::fs::set_permissions(stale.join("ro"), std::fs::Permissions::from_mode(0o555)).unwrap();
        let f = fetcher();
        let images = FakeImages::new(false);
        let env = BuildEnv {
            global: &g,
            fetcher: &f,
            images: &images,
            now: now(),
            quiet: true,
        };
        build_release(&env, &site).unwrap();
        let err = build_release(&env, &site).unwrap_err();
        assert!(format!("{err:#}").contains("already exists"), "{err:#}");
    }

    #[test]
    fn unexpected_php_in_image_fails() {
        let _spawn = crate::testutil::spawn_guard();
        let t = tmp();
        let g = global(t.path());
        let f = fetcher();
        let images = FakeImages::new(true);
        let err = build_release(
            &BuildEnv {
                global: &g,
                fetcher: &f,
                images: &images,
                now: now(),
                quiet: true,
            },
            &parse_site(SITE).unwrap(),
        )
        .unwrap_err();
        assert!(
            format!("{err:#}")
                .contains("unexpected PHP file in image webroot: wp-includes/backdoor.php"),
            "{err:#}"
        );
    }

    #[test]
    fn missing_core_language_fails() {
        let _spawn = crate::testutil::spawn_guard();
        let t = tmp();
        let g = global(t.path());
        let f = fetcher().with(
            &translations_url(TransKind::Core, None, "7.1.2"),
            r#"{"translations":[]}"#,
        );
        let images = FakeImages::new(false);
        let err = build_release(
            &BuildEnv {
                global: &g,
                fetcher: &f,
                images: &images,
                now: now(),
                quiet: true,
            },
            &parse_site(SITE).unwrap(),
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("no hr core translation for WordPress 7.1.2"),
            "{err:#}"
        );
    }

    #[test]
    fn stale_partials_removed_under_lock_and_concurrent_build_refused() {
        let _spawn = crate::testutil::spawn_guard();
        let t = tmp();
        let g = global(t.path());
        let site = parse_site(SITE).unwrap();
        let releases = g.base_root.join("t/releases");
        let stale = releases.join("20200101-000000-aaaaaaa.partial");
        std::fs::create_dir_all(stale.join("ro")).unwrap();
        std::fs::set_permissions(stale.join("ro"), std::fs::Permissions::from_mode(0o555)).unwrap();
        let f = fetcher();
        let images = FakeImages::new(false);
        let env = BuildEnv {
            global: &g,
            fetcher: &f,
            images: &images,
            now: now(),
            quiet: true,
        };
        // lock held elsewhere
        let lock = std::fs::File::create(releases.join(".iwp-build.lock")).unwrap();
        lock.try_lock().unwrap();
        let err = build_release(&env, &site).unwrap_err();
        assert!(
            format!("{err:#}").contains("another build for site t is in progress"),
            "{err:#}"
        );
        assert!(stale.exists(), "nothing removed without the lock");
        drop(lock);
        build_release(&env, &site).unwrap();
        assert!(!stale.exists());
    }

    #[test]
    fn read_only_and_cleanup_never_touch_shared() {
        let _spawn = crate::testutil::spawn_guard();
        let t = tmp();
        let base = t.path();
        let rel = base.join("releases/r");
        std::fs::create_dir_all(rel.join("wp-content/cache")).unwrap();
        std::fs::create_dir_all(base.join("shared/uploads")).unwrap();
        std::fs::create_dir_all(base.join("shared/cache")).unwrap();
        std::fs::write(base.join("shared/uploads/file"), "x").unwrap();
        std::fs::set_permissions(
            base.join("shared/cache"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::set_permissions(
            base.join("shared/uploads/file"),
            std::fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        std::os::unix::fs::symlink("../../../shared/uploads", rel.join("wp-content/uploads"))
            .unwrap();
        std::os::unix::fs::symlink("../../../../shared/cache", rel.join("wp-content/cache/gt"))
            .unwrap();
        let m = |p: &Path| std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777;
        make_read_only(&rel).unwrap();
        assert_eq!(m(&base.join("shared/cache")), 0o700);
        assert_eq!(m(&base.join("shared/uploads/file")), 0o640);
        remove_tree(&rel).unwrap();
        assert!(!rel.exists());
        assert!(base.join("shared/uploads/file").is_file());
        assert_eq!(m(&base.join("shared/cache")), 0o700);
        assert_eq!(m(&base.join("shared/uploads/file")), 0o640);
    }

    #[test]
    fn remove_tree_does_not_follow_root_symlink() {
        let _spawn = crate::testutil::spawn_guard();
        let t = tmp();
        let target = t.path().join("target");
        std::fs::create_dir_all(target.join("d")).unwrap();
        std::fs::write(target.join("d/f"), "x").unwrap();
        let link = t.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        make_read_only(&link).unwrap();
        remove_tree(&link).unwrap();
        assert!(!link.exists() && target.join("d/f").is_file());
    }

    #[test]
    fn manifest_supports_later_verification() {
        let _spawn = crate::testutil::spawn_guard();
        let t = tmp();
        let g = global(t.path());
        let f = fetcher();
        let images = FakeImages::new(false);
        let site = parse_site(SITE).unwrap();
        let r = build_release(
            &BuildEnv {
                global: &g,
                fetcher: &f,
                images: &images,
                now: now(),
                quiet: true,
            },
            &site,
        )
        .unwrap();
        let m = &r.manifest;
        assert_eq!(
            m.files["wp-content/plugins/gt/gt.php"],
            sha256_hex(b"<?php // gt")
        );
        assert_eq!(m.files["wp-content/languages/hr.mo"], sha256_hex(b"mo"));
        assert_eq!(m.files["wp-admin/css/a.css"], sha256_hex(b"css"));
        assert!(!m.files.contains_key(".iwp-release.json"));
        assert!(
            !m.files
                .keys()
                .any(|k| k.starts_with("wp-content/uploads") || k == "wp-content/cache/gt"),
            "symlinks and shared data are not listed: {:?}",
            m.files.keys().collect::<Vec<_>>()
        );
        for p in &m.packages {
            let dir = r.path.join(format!("wp-content/{}s/{}", p.kind, p.slug));
            assert_eq!(p.tree_sha256, tree_hash(&dir).unwrap(), "{}", p.slug);
        }
        let core = m.languages.iter().find(|l| l.kind == "core").unwrap();
        let staged = t.path().join("expect");
        std::fs::create_dir_all(&staged).unwrap();
        std::fs::write(staged.join("hr.mo"), "mo").unwrap();
        std::fs::write(staged.join("admin-hr.mo"), "mo2").unwrap();
        assert_eq!(core.tree_sha256, tree_hash(&staged).unwrap());
        let on_disk: ReleaseManifest =
            serde_json::from_slice(&std::fs::read(r.path.join(".iwp-release.json")).unwrap())
                .unwrap();
        assert_eq!(&on_disk, m);
    }

    #[test]
    fn mu_plugin_tree_sha_is_the_file_hash() {
        let _spawn = crate::testutil::spawn_guard();
        let t = tmp();
        let g = global(t.path());
        let mu = t.path().join("tweaks.php");
        std::fs::write(&mu, "<?php // mu").unwrap();
        let site = parse_site(&format!(
            "{SITE}\n[[plugin]]\nslug = \"tweaks\"\nmu = true\nsha256 = \"{}\"\nsource = {{ path = \"{}\" }}\n",
            sha256_hex(b"<?php // mu"),
            mu.display()
        ))
        .unwrap();
        let f = fetcher();
        let r = build_release(
            &BuildEnv {
                global: &g,
                fetcher: &f,
                images: &FakeImages::new(false),
                now: now(),
                quiet: true,
            },
            &site,
        )
        .unwrap();
        let rec = r
            .manifest
            .packages
            .iter()
            .find(|p| p.slug == "tweaks")
            .unwrap();
        assert_eq!(rec.tree_sha256, sha256_hex(b"<?php // mu"));
    }

    #[test]
    fn translation_zips_must_be_flat_language_files() {
        let _spawn = crate::testutil::spawn_guard();
        let hr = "https://downloads.wordpress.org/translation/core/7.1.2/hr.zip";
        for (bad, why) in [
            ("evil.php", "evil.php"),
            ("x.html", "x.html"),
            (".htaccess", ".htaccess"),
            ("sub/a.mo", "sub"),
            ("hr.MO", "hr.MO"),
        ] {
            let t = tmp();
            let g = global(t.path());
            let f = fetcher().with(hr, make_zip(&[("hr.mo", b"mo"), (bad, b"x")]));
            let err = build_release(
                &BuildEnv {
                    global: &g,
                    fetcher: &f,
                    images: &FakeImages::new(false),
                    now: now(),
                    quiet: true,
                },
                &parse_site(SITE).unwrap(),
            )
            .unwrap_err();
            let msg = format!("{err:#}");
            assert!(msg.contains(hr) && msg.contains(why), "{bad}: {msg}");
        }
        // allowed shapes
        let t = tmp();
        let g = global(t.path());
        let f = fetcher().with(
            hr,
            make_zip(&[
                ("hr.mo", b"mo"),
                ("hr.po", b"po"),
                ("hr-abc@1.json", b"{}"),
                ("hr.l10n.php", b"<?php return [];"),
            ]),
        );
        build_release(
            &BuildEnv {
                global: &g,
                fetcher: &f,
                images: &FakeImages::new(false),
                now: now(),
                quiet: true,
            },
            &parse_site(SITE).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn tofu_save_failure_does_not_fail_a_finished_build() {
        let _spawn = crate::testutil::spawn_guard();
        let t = tmp();
        let g = global(t.path());
        // A directory where the lock file must go makes `Tofu::save` fail after the rename.
        std::fs::create_dir_all(g.cache_dir.join("tofu.json.lock")).unwrap();
        let f = fetcher();
        let r = build_release(
            &BuildEnv {
                global: &g,
                fetcher: &f,
                images: &FakeImages::new(false),
                now: now(),
                quiet: true,
            },
            &parse_site(SITE).unwrap(),
        )
        .unwrap();
        assert!(r.path.is_dir());
    }

    #[test]
    fn translation_tree_hash_ignores_zip_exec_bit() {
        let _spawn = crate::testutil::spawn_guard();
        use std::io::Write;
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let o = zip::write::SimpleFileOptions::default().unix_permissions(0o755);
        w.start_file("hr.mo", o).unwrap();
        w.write_all(b"mo").unwrap();
        let zipb = w.finish().unwrap().into_inner();
        let pkg = "https://downloads.wordpress.org/translation/core/7.1.2/hr.zip";
        let f = FakeFetcher::new().with(pkg, zipb);
        let t = tmp();
        let cache = Cache::new(&t.path().join("c"));
        let wp = crate::fetch::wporg::WpOrg {
            fetcher: &f,
            cache: &cache,
        };
        let tr = Translation {
            language: "hr".into(),
            version: "7.1.2".into(),
            package: pkg.into(),
        };
        let dest = t.path().join("out");
        let rec = install_translation(&wp, &tr, "core", None, &dest).unwrap();
        assert_eq!(
            fs::metadata(dest.join("hr.mo"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        let copy = t.path().join("copy");
        fs::create_dir(&copy).unwrap();
        fs::write(copy.join("hr.mo"), "mo").unwrap();
        assert_eq!(rec.tree_sha256, tree_hash(&copy).unwrap());
        assert_eq!(rec.tree_sha256, tree_hash(&dest).unwrap());
    }
}
