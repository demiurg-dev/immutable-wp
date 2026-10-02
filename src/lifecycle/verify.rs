//! `iwp verify`: read-only integrity checks of a deployed site.
//!
//! The current release is checked against its own manifest (contents, write bits, symlinks),
//! `<base>/shared` is searched for PHP-like files, the running container is checked to run the
//! release's image, and the image's core files are re-hashed against wordpress.org. Nothing is
//! changed and no symlink is followed.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path};
use std::sync::LazyLock;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::Serialize;
use walkdir::WalkDir;

use crate::build::ReleaseManifest;
use crate::config::{GlobalConfig, Site, allow_php_regex};
use crate::hash::sha256_file;
use crate::host::{Cmd, Host, sys};
use crate::lifecycle::releases;

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Finding {
    pub kind: &'static str,
    pub path: Option<String>,
    pub detail: String,
}

#[derive(Serialize, Debug, Default)]
pub struct VerifyReport {
    pub site: String,
    pub release: Option<String>,
    pub findings: Vec<Finding>,
    pub notes: Vec<String>,
}

pub trait VerifyOps {
    /// Image ID of the running container `iwp-<site>`, or None if it is not running.
    fn running_image(&self, site: &str) -> Result<Option<String>>;
    /// md5 of every regular file under /var/www/html outside wp-content/ in `image`
    /// (path relative to /var/www/html -> md5 hex).
    fn image_core_md5(&self, image: &str) -> Result<BTreeMap<String, String>>;
    /// wordpress.org core checksums (path -> md5) for `version`.
    fn core_checksums(&self, version: &str) -> Result<BTreeMap<String, String>>;
    /// Logins of the site's administrators (and super admins), or None when the database has
    /// no WordPress tables.
    fn admins(&self, site: &Site) -> Result<Option<Vec<String>>>;
}

fn finding(kind: &'static str, path: Option<String>, detail: impl Into<String>) -> Finding {
    Finding {
        kind,
        path,
        detail: detail.into(),
    }
}

/// Runs every check for `site`. Findings are integrity problems; `Err` means a check could
/// not run (I/O, podman or network failure).
pub fn verify(
    host: &dyn Host,
    g: &GlobalConfig,
    site: &Site,
    ops: &dyn VerifyOps,
) -> Result<VerifyReport> {
    let base = sys(host, site.base_dir(g));
    let mut report = VerifyReport {
        site: site.name.clone(),
        ..Default::default()
    };
    // shared/ is checked even before the first deploy (e.g. right after an import).
    let mut shared = Vec::new();
    let mut shared_notes = Vec::new();
    check_shared(site, &base.join("shared"), &mut shared, &mut shared_notes)?;
    let Some(name) = releases::current(&base)? else {
        report.findings = shared;
        report.notes.push("no release deployed yet".into());
        report.notes.append(&mut shared_notes);
        return Ok(report);
    };
    let manifest = releases::read_manifest(&base, &name)?;
    let root = base.join("releases").join(&name);
    let n = check_release(site, &root, &manifest, &mut report.findings)?;
    report.notes.push(format!(
        "release {name}: {n} files checked against its manifest"
    ));
    report.findings.append(&mut shared);
    report.notes.append(&mut shared_notes);
    check_container(site, &manifest, ops, &mut report.findings)?;
    check_core(&manifest, ops, &mut report.findings)?;
    check_admins(site, ops, &mut report.findings, &mut report.notes)?;
    report.release = Some(name);
    Ok(report)
}

fn rel_string(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// Release tree vs its manifest: contents, write bits and symlinks.
fn check_release(
    site: &Site,
    root: &Path,
    manifest: &ReleaseManifest,
    out: &mut Vec<Finding>,
) -> Result<usize> {
    let md =
        fs::symlink_metadata(root).with_context(|| format!("inspecting {}", root.display()))?;
    if !md.is_dir() {
        out.push(finding(
            "release_bad_symlink",
            None,
            format!("{} is not a directory", root.display()),
        ));
        return Ok(0);
    }
    let declared: BTreeSet<&str> = std::iter::once("wp-content/uploads")
        .chain(site.writable_paths())
        .collect();
    let mut seen = BTreeSet::new();
    let mut declared_seen = BTreeSet::new();
    let mut checked = 0;
    for e in WalkDir::new(root)
        .follow_links(false)
        .follow_root_links(false)
        .sort_by_file_name()
    {
        let e = e.with_context(|| format!("walking {}", root.display()))?;
        let rel = rel_string(
            e.path()
                .strip_prefix(root)
                .expect("walkdir yields paths under root"),
        );
        let shown = if rel.is_empty() {
            ".".to_string()
        } else {
            rel.clone()
        };
        let ft = e.file_type();
        if declared.contains(rel.as_str()) {
            declared_seen.insert(rel.clone());
            if !ft.is_symlink() {
                out.push(finding(
                    "release_bad_symlink",
                    Some(rel.clone()),
                    format!("declared symlink {rel} is not a symlink"),
                ));
            }
        }
        if ft.is_symlink() {
            let target = fs::read_link(e.path())
                .with_context(|| format!("reading link {}", e.path().display()))?;
            let target = rel_string(&target);
            if !declared.contains(rel.as_str()) {
                out.push(finding(
                    "release_bad_symlink",
                    Some(rel),
                    format!("undeclared symlink to {target}"),
                ));
            } else {
                let want = crate::build::symlink_target(&rel);
                if target != want {
                    out.push(finding(
                        "release_bad_symlink",
                        Some(rel),
                        format!("points to {target}, expected {want}"),
                    ));
                }
            }
            continue;
        }
        let mode = e
            .metadata()
            .with_context(|| format!("inspecting {}", e.path().display()))?
            .permissions()
            .mode();
        if (ft.is_dir() || ft.is_file()) && mode & 0o222 != 0 {
            out.push(finding(
                "release_writable",
                Some(shown),
                format!("mode {:04o} has a write bit", mode & 0o7777),
            ));
        }
        if ft.is_dir() || rel == ".iwp-release.json" {
            continue;
        }
        if !ft.is_file() {
            out.push(finding(
                "release_extra",
                Some(rel),
                "special file (not a regular file, directory or symlink)",
            ));
            continue;
        }
        match manifest.files.get(&rel) {
            None => out.push(finding(
                "release_extra",
                Some(rel),
                "not in the release manifest",
            )),
            Some(want) => {
                let got = sha256_file(e.path())?;
                checked += 1;
                if &got != want {
                    out.push(finding(
                        "release_modified",
                        Some(rel.clone()),
                        format!("sha256 {got}, manifest {want}"),
                    ));
                }
                seen.insert(rel);
            }
        }
    }
    for rel in declared.iter().filter(|d| !declared_seen.contains(**d)) {
        out.push(finding(
            "release_bad_symlink",
            Some(rel.to_string()),
            "declared symlink missing",
        ));
    }
    for rel in manifest.files.keys().filter(|k| !seen.contains(*k)) {
        out.push(finding(
            "release_missing",
            Some(rel.clone()),
            "listed in the release manifest but not a regular file in the release",
        ));
    }
    Ok(checked)
}

static PHP_LIKE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\.(php\d?|phtml|phar|inc)$").unwrap());

/// A PHP "silence" stub: empty, or only an opening tag, at most one comment and an optional
/// closing tag. Parsed the way PHP ends comments, so nothing can hide behind one: `?>` ends a
/// line comment and the first `*/` ends a block comment.
fn is_silence_text(text: &str) -> bool {
    // An empty placeholder file runs nothing.
    if text.trim().is_empty() {
        return true;
    }
    let Some(rest) = text.trim_start().strip_prefix("<?php") else {
        return false;
    };
    // `<?php` must be followed by whitespace (or the end) to be the opening tag.
    if !rest.is_empty() && !rest.starts_with(char::is_whitespace) {
        return false;
    }
    let rest = rest.trim_start();
    // `#[` opens an attribute on PHP 8, so what follows it is code.
    let line_comment = rest.starts_with("//") || (rest.starts_with('#') && !rest.starts_with("#["));
    let rest = if line_comment {
        // PHP ends a line comment at CR as well as LF, and at `?>`.
        let end = rest.find(['\n', '\r']).unwrap_or(rest.len());
        if rest[..end].contains("?>") {
            return false;
        }
        &rest[end..]
    } else if let Some(body) = rest.strip_prefix("/*") {
        match body.split_once("*/") {
            Some((_, after)) => after,
            None => return false,
        }
    } else {
        rest
    };
    let rest = rest.trim();
    rest.is_empty() || rest == "?>"
}

/// Largest file that can count as a silence stub.
pub const STUB_MAX_BYTES: u64 = 128;

/// How a file under `shared/` (or the old uploads, for import) is treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedFile {
    /// `.htaccess` / `.user.ini`: inert under nginx; a note.
    Htaccess,
    /// A `.php` silence stub (≤ 128 bytes, an opening tag and at most one comment); a note.
    Stub,
    /// Any other PHP-like file; a finding.
    Php,
}

/// `None` when `name` is not PHP-like. `path` is read (never through a symlink, at most
/// `STUB_MAX_BYTES`) only to tell a silence stub from code; a symlink is never a stub.
pub fn classify_shared_file(name: &str, path: &Path, is_symlink: bool) -> Option<SharedFile> {
    if name.eq_ignore_ascii_case(".htaccess") || name.eq_ignore_ascii_case(".user.ini") {
        return Some(SharedFile::Htaccess);
    }
    if !PHP_LIKE.is_match(name) {
        return None;
    }
    let php_ext = name.len() > 4 && name[name.len() - 4..].eq_ignore_ascii_case(".php");
    if php_ext && !is_symlink && is_silence_stub(path) {
        return Some(SharedFile::Stub);
    }
    Some(SharedFile::Php)
}

fn is_silence_stub(path: &Path) -> bool {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let Ok(f) = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    else {
        return false;
    };
    match f.metadata() {
        Ok(m) if m.is_file() && m.len() <= STUB_MAX_BYTES => {}
        _ => return false,
    }
    let mut buf = Vec::new();
    if f.take(STUB_MAX_BYTES + 1).read_to_end(&mut buf).is_err()
        || buf.len() as u64 > STUB_MAX_BYTES
    {
        return false;
    }
    std::str::from_utf8(&buf).is_ok_and(is_silence_text)
}

/// Whether a relative symlink `target`, placed `depth` directories below the walk root, leaves
/// that root (judged on the text alone; nothing is resolved).
fn leaves_root(depth: usize, target: &Path) -> bool {
    let mut d = depth;
    for c in target.components() {
        match c {
            Component::Normal(_) => d += 1,
            Component::CurDir => {}
            Component::ParentDir => match d.checked_sub(1) {
                Some(n) => d = n,
                None => return true,
            },
            Component::RootDir | Component::Prefix(_) => return true,
        }
    }
    false
}

/// PHP-like files and escaping symlinks under `<base>/shared`. `.htaccess`/`.user.ini` files
/// and silence stubs are notes, not findings.
fn check_shared(
    site: &Site,
    shared: &Path,
    out: &mut Vec<Finding>,
    notes: &mut Vec<String>,
) -> Result<()> {
    match fs::symlink_metadata(shared) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("inspecting {}", shared.display())),
        Ok(m) if !m.is_dir() => {
            out.push(finding(
                "shared_php",
                Some("shared".into()),
                "shared/ is not a directory",
            ));
            return Ok(());
        }
        Ok(_) => {}
    }
    let allow: Vec<Regex> = site
        .verify
        .allow_php
        .iter()
        .filter_map(|g| allow_php_regex(g))
        .collect();
    for e in WalkDir::new(shared)
        .follow_links(false)
        .follow_root_links(false)
        .same_file_system(true)
        .sort_by_file_name()
    {
        let e = e.with_context(|| format!("walking {}", shared.display()))?;
        if e.depth() == 0 || e.file_type().is_dir() {
            continue;
        }
        let rel = e
            .path()
            .strip_prefix(shared)
            .expect("walkdir yields paths under root");
        let shown = format!("shared/{}", rel_string(rel));
        if e.file_type().is_symlink() {
            let target = fs::read_link(e.path())
                .with_context(|| format!("reading link {}", e.path().display()))?;
            if leaves_root(e.depth() - 1, &target) {
                out.push(finding("shared_php", Some(shown), "symlink leaves shared/"));
                continue;
            }
        }
        let name = e.file_name().to_string_lossy();
        let Some(class) = classify_shared_file(&name, e.path(), e.file_type().is_symlink()) else {
            continue;
        };
        // shared/<x> is wp-content/<x> (config::shared_rel); uploads are never allowlisted.
        let wp_rel = format!("wp-content/{}", rel_string(rel));
        let in_uploads = rel.starts_with("uploads");
        if !in_uploads && allow.iter().any(|re| re.is_match(&wp_rel)) {
            continue;
        }
        match class {
            SharedFile::Htaccess => notes.push(format!("shared_htaccess {shown}")),
            SharedFile::Stub => notes.push(format!("shared_php_stub {shown}")),
            SharedFile::Php => out.push(finding(
                "shared_php",
                Some(shown),
                "PHP-like file in shared data",
            )),
        }
    }
    Ok(())
}

/// Image IDs as podman prints them, with or without the `sha256:` prefix.
fn same_image(a: &str, b: &str) -> bool {
    let strip = |s: &str| s.trim().trim_start_matches("sha256:").to_string();
    strip(a) == strip(b)
}

fn check_container(
    site: &Site,
    manifest: &ReleaseManifest,
    ops: &dyn VerifyOps,
    out: &mut Vec<Finding>,
) -> Result<()> {
    match ops.running_image(&site.name)? {
        None => out.push(finding(
            "container_not_running",
            None,
            format!("iwp-{} is not running", site.name),
        )),
        Some(id) if !same_image(&id, &manifest.image_digest) => out.push(finding(
            "image_mismatch",
            None,
            format!(
                "iwp-{} runs image {id}, release {} expects {}",
                site.name, manifest.release, manifest.image_digest
            ),
        )),
        Some(_) => {}
    }
    Ok(())
}

/// Administrator accounts against `[verify] admins`. Code is read-only, so an account with the
/// administrator role is what an intruder with database access leaves behind.
fn check_admins(
    site: &Site,
    ops: &dyn VerifyOps,
    out: &mut Vec<Finding>,
    notes: &mut Vec<String>,
) -> Result<()> {
    let Some(found) = ops.admins(site)? else {
        notes.push("administrators not checked: the database has no WordPress tables".into());
        return Ok(());
    };
    let Some(declared) = &site.verify.admins else {
        notes.push(format!(
            "administrators: {}; list them in [verify] admins to have any other reported",
            if found.is_empty() {
                "none".to_string()
            } else {
                found.join(", ")
            }
        ));
        return Ok(());
    };
    for login in &found {
        if !declared.contains(login) {
            out.push(finding(
                "admin_unexpected",
                Some(login.clone()),
                "an administrator account that is not listed in [verify] admins",
            ));
        }
    }
    for login in declared {
        if !found.contains(login) {
            notes.push(format!(
                "[verify] admins lists {login}, which is not an administrator account"
            ));
        }
    }
    Ok(())
}

/// The release image's files outside wp-content/ against wordpress.org's core checksums.
fn check_core(
    manifest: &ReleaseManifest,
    ops: &dyn VerifyOps,
    out: &mut Vec<Finding>,
) -> Result<()> {
    let ver = &manifest.wordpress;
    let sums = ops.core_checksums(ver)?;
    let image = ops.image_core_md5(&manifest.image_digest)?;
    let core: BTreeMap<&str, &str> = sums
        .iter()
        .filter(|(p, _)| !p.starts_with("wp-content/"))
        .map(|(p, m)| (p.as_str(), m.as_str()))
        .collect();
    for (path, want) in &core {
        match image.get(*path) {
            None => out.push(finding(
                "core_modified",
                Some(path.to_string()),
                format!("missing from image {}", manifest.image_digest),
            )),
            Some(got) if !got.eq_ignore_ascii_case(want) => out.push(finding(
                "core_modified",
                Some(path.to_string()),
                format!("md5 {got} differs from WordPress {ver} ({want})"),
            )),
            Some(_) => {}
        }
    }
    for path in image.keys() {
        if path != "wp-config.php" && !core.contains_key(path.as_str()) {
            out.push(finding(
                "core_modified",
                Some(path.clone()),
                format!("not a WordPress {ver} core file"),
            ));
        }
    }
    Ok(())
}

/// Parses `md5sum` output (`<md5>  ./<path>`) into path -> md5.
fn parse_md5sum(out: &str) -> Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    for line in out.lines().filter(|l| !l.is_empty()) {
        let parsed = line.split_once("  ").and_then(|(md5, path)| {
            let ok = md5.len() == 32 && md5.bytes().all(|b| b.is_ascii_hexdigit());
            ok.then_some((md5, path.strip_prefix("./")?))
        });
        let Some((md5, path)) = parsed else {
            bail!("unexpected md5sum output line: {line:?}");
        };
        map.insert(path.to_string(), md5.to_ascii_lowercase());
    }
    Ok(map)
}

/// Upper bound on hashing an image's webroot.
const CORE_MD5_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const CORE_MD5_SCRIPT: &str =
    "cd /var/www/html && find . -path ./wp-content -prune -o -type f -print0 | xargs -0 md5sum";

/// The real checks: podman for the container and image, wordpress.org for core checksums.
pub struct SystemVerifyOps<'a> {
    pub host: &'a dyn Host,
    pub g: &'a GlobalConfig,
    pub wporg: crate::fetch::wporg::WpOrg<'a>,
}

impl VerifyOps for SystemVerifyOps<'_> {
    fn running_image(&self, site: &str) -> Result<Option<String>> {
        let name = format!("iwp-{site}");
        let cmd = Cmd::new("podman").args([
            "inspect",
            "--type",
            "container",
            "--format",
            "{{.Image}} {{.State.Running}}",
            name.as_str(),
        ]);
        let out = self.host.run(&cmd)?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        if out.status == 125 && stderr.to_ascii_lowercase().contains("no such container") {
            return Ok(None);
        }
        if out.status != 0 {
            bail!("{cmd}: exit {}: {}", out.status, stderr.trim());
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        match stdout.split_whitespace().collect::<Vec<_>>()[..] {
            [image, "true"] => Ok(Some(image.to_string())),
            [_, "false"] => Ok(None),
            _ => bail!("{cmd}: unexpected output {:?}", stdout.trim()),
        }
    }
    fn image_core_md5(&self, image: &str) -> Result<BTreeMap<String, String>> {
        let cmd = Cmd::new("podman")
            .args([
                "run",
                "--rm",
                "--pull=never",
                "--read-only",
                "--network=none",
                "--entrypoint",
                "bash",
                image,
                "-o",
                "pipefail",
                "-c",
                CORE_MD5_SCRIPT,
            ])
            .timeout(CORE_MD5_TIMEOUT);
        let out = crate::host::run_ok(self.host, &cmd)?;
        parse_md5sum(&out).with_context(|| format!("hashing core files of image {image}"))
    }
    fn core_checksums(&self, version: &str) -> Result<BTreeMap<String, String>> {
        self.wporg.core_checksums(version)
    }
    fn admins(&self, site: &Site) -> Result<Option<Vec<String>>> {
        let ident = crate::host::db::DbIdent::from_site(site)?;
        crate::host::db::admin_logins(
            self.host,
            self.g,
            &ident,
            site.db_prefix(),
            site.config.multisite.is_some(),
        )
        .context("listing administrator accounts")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build::remove_tree;
    use crate::config::parse_site;
    use crate::hash::md5_hex;
    use crate::testutil::RecordingHost;
    use std::cell::RefCell;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    const R: &str = "20261001-100000-aaaaaaa";

    struct FakeVerifyOps {
        running: Option<String>,
        image_core: BTreeMap<String, String>,
        sums: BTreeMap<String, String>,
        fail_sums: bool,
        admins: Option<Vec<String>>,
        calls: RefCell<Vec<String>>,
    }

    impl VerifyOps for FakeVerifyOps {
        fn running_image(&self, site: &str) -> Result<Option<String>> {
            self.calls.borrow_mut().push(format!("running {site}"));
            Ok(self.running.clone())
        }
        fn image_core_md5(&self, image: &str) -> Result<BTreeMap<String, String>> {
            self.calls.borrow_mut().push(format!("core_md5 {image}"));
            Ok(self.image_core.clone())
        }
        fn core_checksums(&self, version: &str) -> Result<BTreeMap<String, String>> {
            self.calls.borrow_mut().push(format!("checksums {version}"));
            if self.fail_sums {
                bail!("GET core checksums: network unreachable");
            }
            Ok(self.sums.clone())
        }
        fn admins(&self, _site: &Site) -> Result<Option<Vec<String>>> {
            Ok(self.admins.clone())
        }
    }

    struct Fx {
        host: RecordingHost,
        g: GlobalConfig,
        site: Site,
        base: PathBuf,
        ops: FakeVerifyOps,
    }

    impl Drop for Fx {
        fn drop(&mut self) {
            // Release dirs are 0555; make them removable before the temp dir goes.
            let _ = remove_tree(&self.base.join("releases"));
        }
    }

    impl Fx {
        fn root(&self) -> PathBuf {
            self.base.join("releases").join(R)
        }
        fn run(&self) -> VerifyReport {
            verify(&self.host, &self.g, &self.site, &self.ops).unwrap()
        }
        fn kinds(&self) -> Vec<(&'static str, Option<String>)> {
            self.run()
                .findings
                .into_iter()
                .map(|f| (f.kind, f.path))
                .collect()
        }
        /// Makes the release writable for a test mutation, runs `f`, then seals it again.
        fn mutate(&self, f: impl FnOnce(&Path)) {
            unseal(&self.root());
            f(&self.root());
            seal(&self.root());
        }
    }

    fn seal(root: &Path) {
        for e in WalkDir::new(root).follow_links(false).contents_first(true) {
            let e = e.unwrap();
            if e.file_type().is_symlink() {
                continue;
            }
            let exec = e.metadata().unwrap().permissions().mode() & 0o111 != 0;
            let mode = if e.file_type().is_dir() || exec {
                0o555
            } else {
                0o444
            };
            fs::set_permissions(e.path(), fs::Permissions::from_mode(mode)).unwrap();
        }
    }

    fn unseal(root: &Path) {
        for e in WalkDir::new(root).follow_links(false) {
            let e = e.unwrap();
            if !e.file_type().is_symlink() {
                let m = e.metadata().unwrap().permissions().mode();
                fs::set_permissions(e.path(), fs::Permissions::from_mode(m | 0o200)).unwrap();
            }
        }
    }

    fn core_files() -> BTreeMap<String, String> {
        [
            ("index.php", md5_hex(b"<?php // index")),
            ("wp-includes/version.php", md5_hex(b"<?php $wp_version;")),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect()
    }

    /// acme (writable wp-content/wflogs) with one clean release deployed as `current`.
    fn fixture() -> Fx {
        let host = RecordingHost::new(true);
        let g = GlobalConfig::default();
        let site = parse_site(include_str!("../../examples/acme.toml")).unwrap();
        let base = sys(&host, site.base_dir(&g));
        let root = base.join("releases").join(R);
        fs::create_dir_all(root.join("wp-content/plugins/p")).unwrap();
        fs::create_dir_all(base.join("shared/uploads/2026")).unwrap();
        fs::create_dir_all(base.join("shared/wflogs")).unwrap();
        fs::write(root.join("index.php"), "<?php // index").unwrap();
        fs::write(root.join("wp-content/plugins/p/p.php"), "<?php // p").unwrap();
        fs::write(root.join("wp-content/plugins/p/run.sh"), "#!/bin/sh").unwrap();
        fs::set_permissions(
            root.join("wp-content/plugins/p/run.sh"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::write(base.join("shared/uploads/2026/a.jpg"), "jpg").unwrap();
        symlink("../../../shared/uploads", root.join("wp-content/uploads")).unwrap();
        symlink("../../../shared/wflogs", root.join("wp-content/wflogs")).unwrap();
        let mut m = crate::build::tests::sample_manifest(&site, R);
        for rel in [
            "index.php",
            "wp-content/plugins/p/p.php",
            "wp-content/plugins/p/run.sh",
        ] {
            m.files
                .insert(rel.to_string(), sha256_file(&root.join(rel)).unwrap());
        }
        fs::write(
            root.join(".iwp-release.json"),
            serde_json::to_vec_pretty(&m).unwrap(),
        )
        .unwrap();
        seal(&root);
        releases::point(&base, "current", R).unwrap();
        let mut sums = core_files();
        // wp-content entries of the wordpress.org list are not part of the image check.
        sums.insert("wp-content/index.php".into(), md5_hex(b"<?php"));
        let ops = FakeVerifyOps {
            running: Some(m.image_digest.clone()),
            image_core: core_files(),
            sums,
            fail_sums: false,
            admins: None,
            calls: RefCell::new(Vec::new()),
        };
        Fx {
            host,
            g,
            site,
            base,
            ops,
        }
    }

    fn one(kind: &'static str, path: &str) -> Vec<(&'static str, Option<String>)> {
        vec![(kind, Some(path.to_string()))]
    }

    #[test]
    fn administrators_are_listed_or_checked_against_the_site_file() {
        let mut fx = fixture();
        let note = |fx: &Fx| fx.run().notes.last().cloned().unwrap();
        assert_eq!(
            note(&fx),
            "administrators not checked: the database has no WordPress tables"
        );
        fx.ops.admins = Some(vec!["alice".into(), "mallory".into()]);
        // Undeclared: listed, never a finding.
        assert!(fx.kinds().is_empty());
        assert_eq!(
            note(&fx),
            "administrators: alice, mallory; list them in [verify] admins to have any other reported"
        );
        fx.site.verify.admins = Some(vec!["alice".into(), "mara".into()]);
        let r = fx.run();
        assert_eq!(
            r.findings,
            vec![finding(
                "admin_unexpected",
                Some("mallory".into()),
                "an administrator account that is not listed in [verify] admins"
            )]
        );
        assert_eq!(
            r.notes.last().unwrap(),
            "[verify] admins lists mara, which is not an administrator account"
        );
        fx.ops.admins = Some(vec!["alice".into(), "mara".into()]);
        assert!(fx.kinds().is_empty());
    }

    #[test]
    fn clean_release_has_no_findings() {
        let fx = fixture();
        let r = fx.run();
        assert_eq!(r.findings, vec![]);
        assert_eq!(r.site, "acme");
        assert_eq!(r.release.as_deref(), Some(R));
        // Read-only: no host command was run (podman is behind VerifyOps).
        assert!(fx.host.calls().is_empty());
        assert_eq!(fx.host.chowns(), vec![]);
    }

    #[test]
    fn modified_missing_and_extra_files() {
        let fx = fixture();
        fx.mutate(|r| fs::write(r.join("index.php"), "<?php // indeX").unwrap());
        assert_eq!(fx.kinds(), one("release_modified", "index.php"));

        let fx = fixture();
        fx.mutate(|r| fs::remove_file(r.join("wp-content/plugins/p/p.php")).unwrap());
        assert_eq!(
            fx.kinds(),
            one("release_missing", "wp-content/plugins/p/p.php")
        );

        let fx = fixture();
        fx.mutate(|r| fs::write(r.join("wp-content/plugins/p/evil.php"), "<?php").unwrap());
        assert_eq!(
            fx.kinds(),
            one("release_extra", "wp-content/plugins/p/evil.php")
        );
    }

    #[test]
    fn write_bits_on_files_and_dirs() {
        let fx = fixture();
        let p = fx.root().join("wp-content/plugins/p/p.php");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        let r = fx.run();
        assert_eq!(r.findings.len(), 1, "{:?}", r.findings);
        assert_eq!(r.findings[0].kind, "release_writable");
        assert_eq!(
            r.findings[0].path.as_deref(),
            Some("wp-content/plugins/p/p.php")
        );
        assert!(r.findings[0].detail.contains("644"), "{:?}", r.findings[0]);
        fs::set_permissions(&p, fs::Permissions::from_mode(0o444)).unwrap();

        fs::set_permissions(
            fx.root().join("wp-content/plugins"),
            fs::Permissions::from_mode(0o575),
        )
        .unwrap();
        assert_eq!(fx.kinds(), one("release_writable", "wp-content/plugins"));
    }

    #[test]
    fn symlinks_declared_undeclared_and_retargeted() {
        let fx = fixture();
        fx.mutate(|r| {
            fs::remove_file(r.join("wp-content/uploads")).unwrap();
            symlink("/etc", r.join("wp-content/uploads")).unwrap();
        });
        assert_eq!(fx.kinds(), one("release_bad_symlink", "wp-content/uploads"));

        // One `../` short of the right depth.
        let fx = fixture();
        fx.mutate(|r| {
            fs::remove_file(r.join("wp-content/wflogs")).unwrap();
            symlink("../../shared/wflogs", r.join("wp-content/wflogs")).unwrap();
        });
        assert_eq!(fx.kinds(), one("release_bad_symlink", "wp-content/wflogs"));

        let fx = fixture();
        fx.mutate(|r| symlink("p.php", r.join("wp-content/plugins/p/alias.php")).unwrap());
        assert_eq!(
            fx.kinds(),
            one("release_bad_symlink", "wp-content/plugins/p/alias.php")
        );
    }

    #[test]
    fn symlinked_dir_is_not_followed() {
        let fx = fixture();
        // A link to a dir full of unlisted, writable files: only the link itself is reported.
        let outside = fx.host.sysroot().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("x.php"), "<?php").unwrap();
        fx.mutate(|r| symlink(&outside, r.join("wp-content/plugins/q")).unwrap());
        assert_eq!(
            fx.kinds(),
            one("release_bad_symlink", "wp-content/plugins/q")
        );
    }

    #[test]
    fn nested_writable_symlink_target_depth() {
        let mut fx = fixture();
        for p in &mut fx.site.plugins {
            p.writable.clear();
        }
        fx.site.plugins[0].writable = vec!["wp-content/cache/gt".into()];
        fx.mutate(|r| {
            fs::remove_file(r.join("wp-content/wflogs")).unwrap();
            fs::create_dir(r.join("wp-content/cache")).unwrap();
            symlink("../../../../shared/cache/gt", r.join("wp-content/cache/gt")).unwrap();
        });
        assert_eq!(fx.kinds(), vec![]);
    }

    #[test]
    fn shared_php_like_files() {
        for (rel, bad) in [
            ("uploads/x.php", true),
            ("uploads/2026/X.PhTmL", true),
            // Inert under nginx; notes, not findings.
            ("uploads/.htaccess", false),
            ("uploads/.user.ini", false),
            ("uploads/a.php7", true),
            ("uploads/a.phar", true),
            ("uploads/a.inc", true),
            ("uploads/a.php.jpg", false),
            ("uploads/php", false),
            ("wflogs/config.php", true),
        ] {
            let fx = fixture();
            fs::write(fx.base.join("shared").join(rel), "<?php echo 1;").unwrap();
            let want = if bad {
                one("shared_php", &format!("shared/{rel}"))
            } else {
                vec![]
            };
            assert_eq!(fx.kinds(), want, "{rel}");
        }
    }

    #[test]
    fn htaccess_and_silence_stubs_are_notes_not_findings() {
        let fx = fixture();
        let up = fx.base.join("shared/uploads");
        fs::create_dir_all(up.join("wpcf7_uploads")).unwrap();
        // Contact Form 7's deny file.
        fs::write(
            up.join("wpcf7_uploads/.htaccess"),
            "<Files ~ \".*\">\n  Require all denied\n</Files>\n",
        )
        .unwrap();
        fs::write(up.join("index.php"), "<?php\n// Silence is golden.\n").unwrap();
        fs::write(up.join("2026/index.php"), "<?php /* nothing */ ?>\n").unwrap();
        fs::write(up.join(".user.ini"), "x=1\n").unwrap();
        let r = fx.run();
        assert_eq!(r.findings, vec![], "{:?}", r.findings);
        for n in [
            "shared_htaccess shared/uploads/.user.ini",
            "shared_htaccess shared/uploads/wpcf7_uploads/.htaccess",
            "shared_php_stub shared/uploads/2026/index.php",
            "shared_php_stub shared/uploads/index.php",
        ] {
            assert!(r.notes.contains(&n.to_string()), "{n}: {:?}", r.notes);
        }

        // Anything with code is a finding; so is a stub over 128 bytes.
        let fx = fixture();
        let up = fx.base.join("shared/uploads");
        fs::write(up.join("index.php"), "<?php echo 1;").unwrap();
        let long = format!("<?php // {}", "x".repeat(120));
        assert_eq!(long.len(), 129);
        fs::write(up.join("big.php"), &long).unwrap();
        let ok = format!("<?php // {}", "x".repeat(119));
        fs::write(up.join("ok.php"), &ok).unwrap();
        fs::write(up.join("two.php"), "<?php // a\n// b\n").unwrap();
        fs::write(up.join("x.phtml"), "<?php").unwrap();
        assert_eq!(
            fx.kinds(),
            vec![
                ("shared_php", Some("shared/uploads/big.php".to_string())),
                ("shared_php", Some("shared/uploads/index.php".to_string())),
                ("shared_php", Some("shared/uploads/two.php".to_string())),
                ("shared_php", Some("shared/uploads/x.phtml".to_string())),
            ]
        );
        assert!(
            fx.run()
                .notes
                .contains(&"shared_php_stub shared/uploads/ok.php".to_string())
        );

        // Code hidden behind a comment is code: `?>` ends a line comment, and the first `*/`
        // ends a block comment, whatever follows on the line.
        let fx = fixture();
        let up = fx.base.join("shared/uploads");
        let shells = [
            ("a.php", "<?php // ?><?=system($_GET[0])?>"),
            ("b.php", "<?php # ?><?php system($_GET[0]);"),
            ("c.php", "<?php /* */ system($_GET[0]); /* */"),
            ("d.php", "<?php // x ?>\n<?php system($_GET[0]);"),
            ("e.php", "<?php /* x */ ?><?=`id`?>"),
            (
                "f.php",
                "<?php\n// a ?> <script language=php>system(1)</script>",
            ),
            ("g.php", "<?php ?>text <?=1?>"),
            // PHP ends a line comment at a bare CR too.
            ("h.php", "<?php //x\rsystem($_GET[0]);"),
            ("i.php", "<?php #x\rsystem($_GET[0]);\n"),
            // `#[` opens an attribute on PHP 8, not a comment.
            ("j.php", "<?php #[A] function f(){eval($_POST[1]);} f();"),
        ];
        for (name, body) in shells {
            assert!(body.len() as u64 <= STUB_MAX_BYTES);
            fs::write(up.join(name), body).unwrap();
        }
        let want: Vec<_> = shells
            .iter()
            .map(|(n, _)| ("shared_php", Some(format!("shared/uploads/{n}"))))
            .collect();
        assert_eq!(fx.kinds(), want);
        // Harmless variants stay notes.
        let fx = fixture();
        let up = fx.base.join("shared/uploads");
        for (name, body) in [
            ("s1.php", "<?php\n"),
            ("s2.php", "<?php # Silence is golden.\n?>\n"),
            ("s3.php", "\n<?php\n/* Silence\n is golden. */\n"),
            ("s4.php", "<?php // Silence is golden."),
            ("s5.php", "<?php\r\n// Silence is golden.\r\n"),
            // An empty placeholder, as many plugins drop into their upload directories.
            ("s6.php", ""),
            ("s7.php", "\n"),
        ] {
            fs::write(up.join(name), body).unwrap();
        }
        assert_eq!(fx.kinds(), vec![]);

        // A symlinked "stub" is never read: still a finding.
        let fx = fixture();
        let up = fx.base.join("shared/uploads");
        fs::write(up.join("real.txt"), "<?php").unwrap();
        symlink("real.txt", up.join("link.php")).unwrap();
        assert_eq!(fx.kinds(), one("shared_php", "shared/uploads/link.php"));
    }

    #[test]
    fn allow_php_globs_cover_writable_but_never_uploads() {
        let mut fx = fixture();
        fx.site.verify.allow_php = vec!["wp-content/wflogs/*.php".into()];
        fs::write(fx.base.join("shared/wflogs/config.php"), "<?php echo 1;").unwrap();
        assert_eq!(fx.kinds(), vec![]);
        fs::create_dir(fx.base.join("shared/wflogs/sub")).unwrap();
        fs::write(fx.base.join("shared/wflogs/sub/x.php"), "<?php echo 1;").unwrap();
        assert_eq!(fx.kinds(), one("shared_php", "shared/wflogs/sub/x.php"));

        // Even an (invalid, unvalidated) uploads glob never allows anything there.
        let mut fx = fixture();
        fx.site.verify.allow_php = vec!["wp-content/uploads/*.php".into()];
        fs::write(fx.base.join("shared/uploads/x.php"), "<?php echo 1;").unwrap();
        assert_eq!(fx.kinds(), one("shared_php", "shared/uploads/x.php"));
    }

    #[test]
    fn shared_symlinks_are_not_followed_and_escapes_are_reported() {
        let fx = fixture();
        let outside = fx.host.sysroot().join("etc-like");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("evil.php"), "<?php").unwrap();
        let up = fx.base.join("shared/uploads");
        symlink(&outside, up.join("link")).unwrap();
        symlink("../../../x", up.join("2026/rel")).unwrap();
        // Inside shared/: fine (and not followed either).
        symlink("../wflogs", up.join("ok")).unwrap();
        symlink("2026/a.jpg", up.join("ok2")).unwrap();
        let r = fx.run();
        let got: Vec<_> = r
            .findings
            .iter()
            .map(|f| (f.kind, f.path.clone().unwrap(), f.detail.clone()))
            .collect();
        assert_eq!(
            got,
            vec![
                (
                    "shared_php",
                    "shared/uploads/2026/rel".to_string(),
                    "symlink leaves shared/".to_string()
                ),
                (
                    "shared_php",
                    "shared/uploads/link".to_string(),
                    "symlink leaves shared/".to_string()
                ),
            ]
        );
    }

    #[test]
    fn container_image_checks() {
        let mut fx = fixture();
        fx.ops.running = Some("0123abcd".into());
        let r = fx.run();
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].kind, "image_mismatch");
        assert_eq!(r.findings[0].path, None);
        assert!(
            r.findings[0].detail.contains("0123abcd"),
            "{:?}",
            r.findings
        );

        fx.ops.running = None;
        let r = fx.run();
        assert_eq!(
            r.findings.iter().map(|f| f.kind).collect::<Vec<_>>(),
            vec!["container_not_running"]
        );

        // The same ID with or without the sha256: prefix is the same image.
        let digest = crate::build::tests::sample_manifest(&fx.site, R).image_digest;
        fx.ops.running = Some(digest.trim_start_matches("sha256:").to_string());
        assert_eq!(fx.kinds(), vec![]);
    }

    #[test]
    fn core_checks_against_wordpress_org() {
        let mut fx = fixture();
        let digest = crate::build::tests::sample_manifest(&fx.site, R).image_digest;
        fx.run();
        let calls = fx.ops.calls.borrow().clone();
        assert!(calls.contains(&format!("core_md5 {digest}")), "{calls:?}");
        assert!(
            calls.contains(&format!("checksums {}", fx.site.core.wordpress)),
            "{calls:?}"
        );

        fx.ops
            .image_core
            .insert("index.php".into(), md5_hex(b"<?php evil();"));
        assert_eq!(fx.kinds(), one("core_modified", "index.php"));

        let mut fx = fixture();
        fx.ops
            .image_core
            .insert("wp-config.php".into(), md5_hex(b"<?php"));
        assert_eq!(fx.kinds(), vec![]);
        fx.ops
            .image_core
            .insert("wp-admin/shell.php".into(), md5_hex(b"<?php"));
        assert_eq!(fx.kinds(), one("core_modified", "wp-admin/shell.php"));

        let mut fx = fixture();
        fx.ops.image_core.remove("wp-includes/version.php");
        assert_eq!(fx.kinds(), one("core_modified", "wp-includes/version.php"));
    }

    #[test]
    fn core_checksum_failure_is_an_error_not_a_finding() {
        let mut fx = fixture();
        fx.ops.fail_sums = true;
        let err = verify(&fx.host, &fx.g, &fx.site, &fx.ops).unwrap_err();
        assert!(
            format!("{err:#}").contains("network unreachable"),
            "{err:#}"
        );
    }

    #[test]
    fn no_current_release_still_checks_shared() {
        // PHP in shared/ (e.g. from an import) is reported before the first deploy.
        let fx = fixture();
        fs::remove_file(fx.base.join("current")).unwrap();
        fs::write(fx.base.join("shared/uploads/x.php"), "<?php echo 1;").unwrap();
        let r = fx.run();
        assert_eq!(
            r.findings
                .iter()
                .map(|f| (f.kind, f.path.clone()))
                .collect::<Vec<_>>(),
            one("shared_php", "shared/uploads/x.php")
        );
        assert_eq!(r.release, None);
        assert_eq!(r.notes, vec!["no release deployed yet".to_string()]);
        assert!(fx.ops.calls.borrow().is_empty());

        // Clean shared/: nothing.
        let fx = fixture();
        fs::remove_file(fx.base.join("current")).unwrap();
        let r = fx.run();
        assert_eq!(r.findings, vec![]);
        assert_eq!(r.release, None);
        assert_eq!(r.notes, vec!["no release deployed yet".to_string()]);
        assert!(fx.ops.calls.borrow().is_empty());

        // No shared/ at all: nothing.
        let fx = fixture();
        fs::remove_file(fx.base.join("current")).unwrap();
        fs::remove_dir_all(fx.base.join("shared")).unwrap();
        let r = fx.run();
        assert_eq!(r.findings, vec![]);
        assert_eq!(r.notes, vec!["no release deployed yet".to_string()]);
        assert!(fx.ops.calls.borrow().is_empty());
    }

    #[test]
    fn shared_multisite_and_empty_are_clean() {
        let fx = fixture();
        let d = fx.base.join("shared/uploads/sites/2/2026");
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("a.jpg"), "jpg").unwrap();
        assert_eq!(fx.kinds(), vec![]);

        let fx = fixture();
        fs::remove_dir_all(fx.base.join("shared")).unwrap();
        fs::create_dir(fx.base.join("shared")).unwrap();
        assert_eq!(fx.kinds(), vec![]);
    }

    #[test]
    fn shared_root_symlink_is_one_finding_and_not_walked() {
        let fx = fixture();
        let outside = fx.host.sysroot().join("etc-like");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("evil.php"), "<?php").unwrap();
        fs::remove_dir_all(fx.base.join("shared")).unwrap();
        symlink(&outside, fx.base.join("shared")).unwrap();
        assert_eq!(fx.kinds(), one("shared_php", "shared"));
    }

    #[test]
    fn declared_symlink_missing_or_replaced_by_dir() {
        let fx = fixture();
        fx.mutate(|r| fs::remove_file(r.join("wp-content/uploads")).unwrap());
        let r = fx.run();
        assert_eq!(r.findings.len(), 1, "{:?}", r.findings);
        assert_eq!(r.findings[0].kind, "release_bad_symlink");
        assert_eq!(r.findings[0].path.as_deref(), Some("wp-content/uploads"));
        assert_eq!(r.findings[0].detail, "declared symlink missing");

        let fx = fixture();
        fx.mutate(|r| {
            fs::remove_file(r.join("wp-content/wflogs")).unwrap();
            fs::create_dir(r.join("wp-content/wflogs")).unwrap();
        });
        let r = fx.run();
        assert_eq!(r.findings.len(), 1, "{:?}", r.findings);
        assert_eq!(r.findings[0].kind, "release_bad_symlink");
        assert_eq!(r.findings[0].path.as_deref(), Some("wp-content/wflogs"));
        assert!(
            r.findings[0].detail.contains("is not a symlink"),
            "{:?}",
            r.findings[0]
        );
    }

    #[test]
    fn md5sum_output_parser() {
        let out = "d41d8cd98f00b204e9800998ecf8427e  ./index.php\n\
                   0cc175b9c0f1b6a831c399e269772661  ./wp-admin/a b.php\n";
        let m = parse_md5sum(out).unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(m["index.php"], "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(m["wp-admin/a b.php"], "0cc175b9c0f1b6a831c399e269772661");
        assert!(parse_md5sum("").unwrap().is_empty());
        for bad in [
            "xyz  ./index.php",
            "d41d8cd98f00b204e9800998ecf8427e  index.php",
            "d41d8cd98f00b204e9800998ecf8427e ./index.php",
            "\\d41d8cd98f00b204e9800998ecf8427e  ./a\\nb",
            "d41d8cd98f00b204e9800998ecf8427e  -",
        ] {
            assert!(parse_md5sum(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn system_ops_running_image() {
        let h = RecordingHost::new(true)
            .respond(
                "podman inspect --type container --format {{.Image}} {{.State.Running}} iwp-a",
                0,
                "abc123 true\n",
                "",
            )
            .respond(
                "podman inspect --type container --format {{.Image}} {{.State.Running}} iwp-b",
                125,
                "",
                "Error: no such container iwp-b",
            )
            .respond(
                "podman inspect --type container --format {{.Image}} {{.State.Running}} iwp-c",
                0,
                "abc123 false\n",
                "",
            )
            .respond(
                "podman inspect --type container --format {{.Image}} {{.State.Running}} iwp-d",
                125,
                "",
                "Error: permission denied",
            )
            .respond(
                "podman inspect --type container --format {{.Image}} {{.State.Running}} iwp-e",
                0,
                "garbage\n",
                "",
            );
        let d = tempfile::tempdir().unwrap();
        let cache = crate::fetch::cache::Cache::new(d.path());
        let f = crate::testutil::FakeFetcher::new();
        let ops = SystemVerifyOps {
            host: &h,
            g: &GlobalConfig::default(),
            wporg: crate::fetch::wporg::WpOrg {
                fetcher: &f,
                cache: &cache,
            },
        };
        assert_eq!(ops.running_image("a").unwrap().as_deref(), Some("abc123"));
        assert_eq!(ops.running_image("b").unwrap(), None);
        assert_eq!(ops.running_image("c").unwrap(), None);
        assert!(ops.running_image("d").is_err());
        assert!(ops.running_image("e").is_err());
        assert_eq!(h.calls().len(), 5, "one inspect per site");
    }

    #[test]
    fn system_ops_image_core_md5_command() {
        let h = RecordingHost::new(true).respond(
            "podman run",
            0,
            "d41d8cd98f00b204e9800998ecf8427e  ./index.php\n",
            "",
        );
        let d = tempfile::tempdir().unwrap();
        let cache = crate::fetch::cache::Cache::new(d.path());
        let f = crate::testutil::FakeFetcher::new();
        let ops = SystemVerifyOps {
            host: &h,
            g: &GlobalConfig::default(),
            wporg: crate::fetch::wporg::WpOrg {
                fetcher: &f,
                cache: &cache,
            },
        };
        let m = ops.image_core_md5("abc123").unwrap();
        assert_eq!(m.keys().collect::<Vec<_>>(), vec!["index.php"]);
        let calls = h.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].args,
            [
                "run",
                "--rm",
                "--pull=never",
                "--read-only",
                "--network=none",
                "--entrypoint",
                "bash",
                "abc123",
                "-o",
                "pipefail",
                "-c",
                "cd /var/www/html && find . -path ./wp-content -prune -o -type f -print0 | xargs -0 md5sum",
            ]
        );
        assert_eq!(calls[0].timeout, Some(Duration::from_secs(600)));
    }
}
