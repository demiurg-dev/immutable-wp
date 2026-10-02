//! `iwp import`: adopt an existing classic WordPress webroot.
//!
//! Turns an old webroot into an iwp site: a site file, pinned copies of custom code, DB and
//! salts secrets (through `setup`) and a copy of the uploads. It never deploys, never writes
//! under `--from` and never touches the old site's database account at its existing host.

pub mod classify;
pub mod detect;
pub mod wpconfig;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use toml_edit::{Array, ArrayOfTables, DocumentMut, InlineTable, Item, Table, value};

use crate::config::{ConstValue, GlobalConfig, LoadedSite, parse_site, validate_core_versions};
use crate::error::UsageError;
use crate::fetch::wporg::WpOrg;
use crate::host::fsx::{FileSpec, write_atomic};
use crate::host::identity::Identity;
use crate::host::{Cmd, Host, sys};
use crate::lifecycle::setup::{
    SetupOpts, ensure_sites_dir, existing_sites, install_site_file, pick_id, setup, validate_new,
};
use classify::{Classified, Verdict};
use detect::{Kind, LocalPackage};
use wpconfig::OldConfig;

pub const DEFAULT_SRC_ROOT: &str = "/srv/iwp/src";
/// Upper bound on the uploads copy.
pub const RSYNC_TIMEOUT: Duration = Duration::from_secs(6 * 3600);
/// Pin used while validating the site text before the sources are copied.
const PENDING_PIN: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone)]
pub struct ImportArgs {
    pub site: String,
    pub from: PathBuf,
    pub domains: Vec<String>,
    pub base: Option<PathBuf>,
    pub php: String,
    pub new_db_user: bool,
    /// An explicit site id (`--id`); `None` takes the next free one.
    pub id: Option<u32>,
    /// Where pinned copies of custom code go (default `/srv/iwp/src`).
    pub src_root: PathBuf,
}

/// What `run` needs besides the host and global config: wordpress.org, for classification.
pub struct ImportCtx<'a> {
    pub wporg: WpOrg<'a>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PackageLine {
    /// `plugin`, `theme` or `mu-plugin`.
    pub kind: String,
    pub slug: String,
    /// Version from the old site's header, if any.
    pub local_version: Option<String>,
    /// `wporg` (a `version` entry), `source` (a pinned `path` copy) or `skipped`.
    pub verdict: String,
    /// Why it became a `source`, or why it was skipped.
    pub reason: Option<String>,
    /// Where the copy was written (the `path` source).
    pub path: Option<PathBuf>,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportReport {
    pub site: String,
    pub from: PathBuf,
    pub site_file: PathBuf,
    pub wordpress: String,
    pub db_user: String,
    pub packages: Vec<PackageLine>,
    /// Drop-ins in the old wp-content: map them via `[dropins]` or they will not exist.
    pub dropins: Vec<String>,
    /// Unknown wp-content directories: candidates for a package's `writable`.
    pub other_content_dirs: Vec<String>,
    /// Top-level webroot entries that are not core, wp-config.php or wp-content, with a hint.
    pub other_root_files: Vec<String>,
    /// Translation files that are not carried: under `languages/{plugins,themes}` for slugs
    /// that are not wordpress.org entries, and everything under `languages/loco` (up to 50).
    pub custom_translations: Vec<String>,
    /// wp-config.php constants that were not carried over (names only, never values).
    pub not_carried: Vec<String>,
    pub warnings: Vec<String>,
    /// Paths import created.
    pub written: Vec<PathBuf>,
    /// Old uploads that were not copied (up to 20 lines).
    pub uploads_not_copied: Vec<String>,
    /// PHP-like files and `.htaccess`/`.user.ini` in the old uploads (up to 50), each marked
    /// with how `iwp verify` will treat it.
    pub uploads_php: Vec<String>,
    /// Set when a step after the site file was installed failed.
    pub error: Option<String>,
    /// Commands that finish the import by hand after a late failure.
    pub recovery: Vec<String>,
}

/// A failure after the site file was installed; carries the (already written) report.
#[derive(Debug)]
pub struct ImportError {
    pub report: Box<ImportReport>,
    pub error: anyhow::Error,
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "import of {} stopped after {} was written",
            self.report.site,
            self.report.site_file.display()
        )
    }
}

impl std::error::Error for ImportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.error.as_ref())
    }
}

impl ImportReport {
    /// The human summary printed by `iwp import`.
    pub fn summary(&self) -> String {
        let mut o = format!(
            "imported {} from {} (WordPress {}, database user {})\nsite file: {}\npackages:\n",
            self.site,
            self.from.display(),
            self.wordpress,
            self.db_user,
            self.site_file.display()
        );
        for p in &self.packages {
            let what = match (p.verdict.as_str(), &p.reason) {
                ("wporg", _) => format!(
                    "wordpress.org {}",
                    p.local_version.as_deref().unwrap_or("?")
                ),
                ("source", Some(r)) => format!("pinned copy ({r})"),
                (v, Some(r)) => format!("{v}: {r}"),
                (v, None) => v.to_string(),
            };
            o.push_str(&format!("  {} {}: {what}\n", p.kind, p.slug));
        }
        if !self.dropins.is_empty() {
            o.push_str(&format!(
                "drop-ins (map them via [dropins] or they will not exist): {}\n",
                self.dropins.join(", ")
            ));
        }
        if !self.other_content_dirs.is_empty() {
            o.push_str(&format!(
                "other wp-content directories (candidates for `writable`): {}\n",
                self.other_content_dirs.join(", ")
            ));
        }
        if !self.other_root_files.is_empty() {
            o.push_str("other webroot entries (not carried):\n");
            for f in &self.other_root_files {
                o.push_str(&format!("  {f}\n"));
            }
        }
        if !self.custom_translations.is_empty() {
            o.push_str("custom translations (not carried):\n");
            for f in &self.custom_translations {
                o.push_str(&format!("  {f}\n"));
            }
        }
        if !self.not_carried.is_empty() {
            o.push_str("wp-config.php constants not carried over:\n");
            for n in &self.not_carried {
                o.push_str(&format!("  {n}\n"));
            }
        }
        for w in &self.warnings {
            o.push_str(&format!("warning: {w}\n"));
        }
        for u in &self.uploads_not_copied {
            o.push_str(&format!("{u}\n"));
        }
        if !self.uploads_php.is_empty() {
            o.push_str("PHP-like files in the old uploads:\n");
            for u in &self.uploads_php {
                o.push_str(&format!("  {u}\n"));
            }
        }
        if let Some(e) = &self.error {
            o.push_str(&format!("error: {e}\nto finish by hand:\n"));
            for r in &self.recovery {
                o.push_str(&format!("  {r}\n"));
            }
        }
        o.push_str(&format!(
            "not deployed; review the site file, then run: iwp deploy {}",
            self.site
        ));
        o
    }
}

fn usage(msg: impl Into<String>) -> anyhow::Error {
    UsageError(msg.into()).into()
}

fn kind_name(k: Kind) -> &'static str {
    match k {
        Kind::Plugin => "plugin",
        Kind::Theme => "theme",
        Kind::MuPlugin => "mu-plugin",
    }
}

/// A package's place in the new site file.
#[derive(Debug, Clone)]
enum Plan {
    Wporg(String),
    /// A pinned copy at this (real, not sysroot) path.
    Source(PathBuf),
}

#[derive(Debug, Clone)]
struct Entry {
    pkg: LocalPackage,
    plan: Plan,
    /// Index into the report's package lines.
    line: usize,
}

/// `p` with its deepest existing ancestor canonicalized (symlinks resolved).
fn real_path(p: &Path) -> PathBuf {
    let mut existing = p.to_path_buf();
    let mut rest = Vec::new();
    while fs::symlink_metadata(&existing).is_err() {
        match (existing.file_name(), existing.parent()) {
            (Some(n), Some(parent)) => {
                rest.push(n.to_os_string());
                existing = parent.to_path_buf();
            }
            _ => break,
        }
    }
    let mut out = fs::canonicalize(&existing).unwrap_or(existing);
    out.extend(rest.iter().rev());
    out
}

fn overlaps(a: &Path, b: &Path) -> bool {
    let (a, b) = (real_path(a), real_path(b));
    a.starts_with(&b) || b.starts_with(&a)
}

/// `wp-config.php` in the root, or one level up (as WordPress allows) when that directory is
/// not itself a WordPress root. Both are reached from the canonical root through directory
/// handles and opened `O_NOFOLLOW` (regular files only): root never reads it through a symlink
/// (a symlink is a usage error naming the path). Returns the path, the text and the uids of the
/// file and of the webroot directory.
fn read_wp_config(from_real: &Path) -> Result<(PathBuf, String, u32, u32)> {
    use crate::host::fsx::{NofollowEntry, entry_nofollow, open_dir_nofollow};
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    let refuse = |p: &Path| {
        usage(format!(
            "{} is a symlink; import never reads wp-config.php through a symlink: replace it with the real file (or a regular, root-readable copy) and re-run iwp import",
            p.display()
        ))
    };
    let open = |dir: &Path| -> Result<fs::File> {
        open_dir_nofollow(dir, Path::new(""))?
            .with_context(|| format!("{} vanished", dir.display()))
    };
    let root = open(from_real)?;
    let root_uid = root.metadata()?.uid();
    let name = std::ffi::OsStr::new("wp-config.php");
    let here = from_real.join(name);
    let mut found = match entry_nofollow(&root, name, &here)? {
        NofollowEntry::Regular(f) => Some((here, f)),
        NofollowEntry::Symlink => return Err(refuse(&here)),
        NofollowEntry::Missing | NofollowEntry::Other => None,
    };
    if found.is_none()
        && let Some(parent) = from_real.parent()
    {
        let pd = open(parent)?;
        let up = parent.join(name);
        let settings = crate::host::fsx::lstat_at(&pd, std::ffi::OsStr::new("wp-settings.php"))?;
        if settings.is_err() {
            found = match entry_nofollow(&pd, name, &up)? {
                NofollowEntry::Regular(f) => Some((up, f)),
                NofollowEntry::Symlink => return Err(refuse(&up)),
                NofollowEntry::Missing | NofollowEntry::Other => None,
            };
        }
    }
    let Some((path, mut f)) = found else {
        return Err(usage(format!(
            "no wp-config.php in {} (or one level up)",
            from_real.display()
        )));
    };
    let uid = f.metadata()?.uid();
    let mut text = String::new();
    f.read_to_string(&mut text)
        .with_context(|| format!("reading {}", path.display()))?;
    Ok((path, text, uid, root_uid))
}

/// A warning when wp-config.php is owned by someone other than the webroot's owner.
fn wp_config_owner_warning(path: &Path, file_uid: u32, root_uid: u32) -> Option<String> {
    (file_uid != root_uid).then(|| {
        format!(
            "{} is owned by uid {file_uid} but the webroot by uid {root_uid}; make sure it is this site's real configuration",
            path.display()
        )
    })
}

fn str_path(p: &Path) -> Result<&str> {
    p.to_str()
        .ok_or_else(|| usage(format!("{} is not valid UTF-8", p.display())))
}

fn const_value(v: &ConstValue) -> toml_edit::Value {
    match v {
        ConstValue::Bool(b) => (*b).into(),
        ConstValue::Int(n) => (*n).into(),
        ConstValue::Str(s) => s.as_str().into(),
    }
}

struct SiteText<'a> {
    args: &'a ImportArgs,
    id: u32,
    domains: &'a [String],
    wordpress: &'a str,
    languages: &'a [String],
    old: &'a OldConfig,
    db_user: &'a str,
    entries: &'a [Entry],
}

/// The site file, written with `toml_edit` so every value taken from the old site is escaped
/// correctly. `pin(i)` is the sha256 of entry `i`. Never contains a secret.
fn site_text(t: &SiteText, pin: &dyn Fn(usize) -> String) -> Result<String> {
    let mut doc = DocumentMut::new();
    doc["name"] = value(t.args.site.as_str());
    if let Some(b) = &t.args.base {
        doc["base"] = value(str_path(b)?);
    }
    doc["domains"] = value(Array::from_iter(t.domains.iter().map(String::as_str)));
    doc["id"] = value(i64::from(t.id));

    let mut core = Table::new();
    core["wordpress"] = value(t.wordpress);
    core["php"] = value(t.args.php.as_str());
    core["languages"] = value(Array::from_iter(t.languages.iter().map(String::as_str)));
    doc["core"] = Item::Table(core);

    let mut config = Table::new();
    config.set_implicit(true);
    if let Some(m) = &t.old.multisite {
        let mut ms = InlineTable::new();
        ms.insert("subdomain", m.subdomain.into());
        ms.insert("domain", m.domain.as_str().into());
        if m.path != "/" {
            ms.insert("path", m.path.as_str().into());
        }
        for (k, v) in [("site_id", m.site_id), ("blog_id", m.blog_id)] {
            if v != 1 {
                ms.insert(k, i64::from(v).into());
            }
        }
        config["multisite"] = value(ms);
    }
    if !t.old.constants.is_empty() {
        let mut c = Table::new();
        for (k, v) in &t.old.constants {
            c[k.as_str()] = value(const_value(v));
        }
        config["constants"] = Item::Table(c);
    }
    doc["config"] = Item::Table(config);

    let mut db = Table::new();
    db["name"] = value(t.old.db_name.as_str());
    db["user"] = value(t.db_user);
    db["prefix"] = value(t.old.table_prefix.as_str());
    if let Some(c) = &t.old.db_charset {
        db["charset"] = value(c.as_str());
    }
    if let Some(c) = &t.old.db_collate {
        db["collate"] = value(c.as_str());
    }
    doc["database"] = Item::Table(db);

    let mut plugins = ArrayOfTables::new();
    let mut themes = ArrayOfTables::new();
    for (i, e) in t.entries.iter().enumerate() {
        let mut tb = Table::new();
        tb["slug"] = value(e.pkg.slug.as_str());
        match &e.plan {
            Plan::Wporg(v) => tb["version"] = value(v.as_str()),
            Plan::Source(dest) => {
                let mut src = InlineTable::new();
                src.insert("path", str_path(dest)?.into());
                tb["source"] = value(src);
                tb["sha256"] = value(pin(i));
                if e.pkg.kind == Kind::MuPlugin {
                    tb["mu"] = value(true);
                }
            }
        }
        if e.pkg.kind == Kind::Theme {
            themes.push(tb);
        } else {
            plugins.push(tb);
        }
    }
    if !plugins.is_empty() {
        doc["plugin"] = Item::ArrayOfTables(plugins);
    }
    if !themes.is_empty() {
        doc["theme"] = Item::ArrayOfTables(themes);
    }
    Ok(format!(
        "# Created by `iwp import`. Review it, then `iwp deploy {}`.\n{doc}",
        t.args.site
    ))
}

/// Why a classified package cannot become a site-file entry, if it cannot.
fn unusable(
    p: &LocalPackage,
    verdict: &Verdict,
    plugin_slugs: &BTreeSet<String>,
) -> Option<String> {
    if !crate::config::validate::valid_slug(&p.slug) {
        return Some(format!(
            "slug {:?} is not usable (must match ^[a-z0-9][a-z0-9._-]{{0,99}}$); rename it and add it by hand",
            p.slug
        ));
    }
    if p.kind == Kind::MuPlugin && p.slug == "iwp" {
        return Some("the mu-plugin name `iwp` is reserved; rename it and add it by hand".into());
    }
    if p.kind == Kind::MuPlugin && plugin_slugs.contains(&p.slug) {
        return Some("a plugin has the same slug; rename the mu-plugin and add it by hand".into());
    }
    if matches!(verdict, Verdict::Source { .. }) {
        // A source tree with symlinks or special files is refused.
        let bad = if p.single_file {
            (!fs::symlink_metadata(&p.dir).is_ok_and(|m| m.is_file()))
                .then(|| "not a regular file".to_string())
        } else {
            crate::hash::list_files(&p.dir)
                .err()
                .map(|e| format!("{e:#}"))
        };
        if let Some(why) = bad {
            return Some(format!(
                "cannot be copied ({why}); replace symlinks with real files, then add it by hand"
            ));
        }
    }
    None
}

/// Decides each classified package's fate. Packages that cannot become a valid entry are
/// skipped with a report line and never reach the site file.
fn plan_entries(
    args: &ImportArgs,
    classified: Vec<Classified>,
    lines: &mut Vec<PackageLine>,
    warnings: &mut Vec<String>,
) -> Vec<Entry> {
    let site_src = args.src_root.join(&args.site);
    let plugin_slugs: BTreeSet<String> = classified
        .iter()
        .filter(|c| c.pkg.kind == Kind::Plugin)
        .map(|c| c.pkg.slug.clone())
        .collect();
    let mut out = Vec::new();
    for Classified { pkg: p, verdict } in classified {
        let mut line = PackageLine {
            kind: kind_name(p.kind).into(),
            slug: p.slug.clone(),
            local_version: p.version.clone(),
            verdict: String::new(),
            reason: None,
            path: None,
            sha256: None,
        };
        if let Some(why) = unusable(&p, &verdict, &plugin_slugs) {
            warnings.push(format!(
                "{} {} skipped (not in the site file): {why}",
                kind_name(p.kind),
                p.slug
            ));
            line.verdict = "skipped".into();
            line.reason = Some(why);
            lines.push(line);
            continue;
        }
        let plan = match verdict {
            Verdict::Wporg {
                version,
                local_only,
            } => {
                if !local_only.is_empty() {
                    let shown: Vec<&str> = local_only.iter().take(5).map(String::as_str).collect();
                    let more = local_only.len() - shown.len();
                    warnings.push(format!(
                        "{} {}: {} local-only file(s) are not carried (runtime files): {}{}",
                        kind_name(p.kind),
                        p.slug,
                        local_only.len(),
                        shown.join(", "),
                        if more > 0 {
                            format!(" (and {more} more)")
                        } else {
                            String::new()
                        }
                    ));
                }
                line.verdict = "wporg".into();
                Plan::Wporg(version)
            }
            Verdict::Source { reason } => {
                if p.kind == Kind::Plugin && p.single_file {
                    warnings.push(format!(
                        "plugins/{s}.php is installed as plugins/{s}/{s}.php: its plugin file changes, so re-activate it after the first deploy",
                        s = p.slug
                    ));
                }
                line.verdict = "source".into();
                line.reason = Some(reason);
                let rel = match p.kind {
                    Kind::Plugin => format!("plugins/{}", p.slug),
                    Kind::Theme => format!("themes/{}", p.slug),
                    Kind::MuPlugin => format!("mu-plugins/{}.php", p.slug),
                };
                Plan::Source(site_src.join(rel))
            }
        };
        out.push(Entry {
            pkg: p,
            plan,
            line: lines.len(),
        });
        lines.push(line);
    }
    out
}

/// Most source files listed by name in the report.
const LIST_MAX: usize = 20;

/// What the copies noticed: source files other users could not read in the old tree.
#[derive(Default)]
struct CopyLog {
    not_world_readable: Vec<String>,
    not_world_readable_count: usize,
}

/// Copies the open regular file `from` to the new file `dst`: created 0600, then root-owned
/// and 0755 when the source has an executable bit, 0644 otherwise.
fn copy_file(
    host: &dyn Host,
    mut from: fs::File,
    src: &Path,
    dst: &Path,
    log: &mut CopyLog,
) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let m = from.metadata()?;
    if !m.is_file() {
        bail!("{}: not a regular file", src.display());
    }
    let src_mode = m.permissions().mode();
    if src_mode & 0o004 == 0 {
        log.not_world_readable_count += 1;
        if log.not_world_readable.len() < LIST_MAX {
            log.not_world_readable.push(src.display().to_string());
        }
    }
    let mode = if src_mode & 0o111 != 0 { 0o755 } else { 0o644 };
    let mut to = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dst)
        .with_context(|| format!("creating {}", dst.display()))?;
    std::io::copy(&mut from, &mut to).with_context(|| format!("copying {}", src.display()))?;
    host.fchown(&to, dst, 0, 0)?;
    to.set_permissions(fs::Permissions::from_mode(mode))?;
    to.sync_all()?;
    Ok(())
}

/// Creates the directory `p` (0700 at first), then root-owned 0755.
fn make_dir(host: &dyn Host, p: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    fs::DirBuilder::new()
        .mode(0o700)
        .create(p)
        .with_context(|| format!("creating {}", p.display()))?;
    let d = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(p)
        .with_context(|| format!("opening {}", p.display()))?;
    host.fchown(&d, p, 0, 0)?;
    d.set_permissions(fs::Permissions::from_mode(0o755))?;
    Ok(())
}

/// Copies the directory open as `src` (named `src_full`) into the new directory `dst`. The
/// source is read only through directory handles: subdirectories with
/// `openat(O_NOFOLLOW|O_DIRECTORY)`, files with `openat(O_NOFOLLOW)`, so a symlink swapped in
/// anywhere is refused rather than followed. Special files are refused too.
fn copy_tree(
    host: &dyn Host,
    src: &fs::File,
    src_full: &Path,
    dst: &Path,
    log: &mut CopyLog,
) -> Result<()> {
    make_dir(host, dst)?;
    let mut names = crate::host::fsx::dir_entries(src, src_full)?;
    names.sort();
    for name in names {
        let (s, d) = (src_full.join(&name), dst.join(&name));
        let st = crate::host::fsx::lstat_at(src, &name)?
            .with_context(|| format!("stat {}", s.display()))?;
        match st.st_mode & libc::S_IFMT {
            libc::S_IFLNK => bail!("{}: symlink refused", s.display()),
            libc::S_IFDIR => {
                let sub = crate::host::fsx::open_dir_at_raw(src, &name)?
                    .map_err(|e| crate::host::fsx::nofollow_err(e, &s))?;
                copy_tree(host, &sub, &s, &d, log)?;
            }
            libc::S_IFREG => {
                let f = crate::host::fsx::open_file_at(src, &name, &s)?;
                copy_file(host, f, &s, &d, log)?;
            }
            _ => bail!("{}: special file refused", s.display()),
        }
    }
    Ok(())
}

/// Creates `dir` and its missing parents; those strictly below `top` are root-owned 0755.
fn ensure_dirs(host: &dyn Host, top: &Path, dir: &Path) -> Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(m) if m.is_dir() => return Ok(()),
        Ok(_) => bail!("{} exists and is not a directory", dir.display()),
        Err(_) => {}
    }
    if dir.starts_with(top) && dir != top {
        ensure_dirs(host, top, dir.parent().context("no parent")?)?;
        make_dir(host, dir)
    } else {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))
    }
}

/// Opens the directory `from_real/rel` without following a symlink at any component.
fn open_src_dir(from_real: &Path, rel: &Path) -> Result<fs::File> {
    crate::host::fsx::open_dir_nofollow(from_real, rel)?
        .with_context(|| format!("{} vanished", from_real.join(rel).display()))
}

/// Copies one package to `dest` (a sysroot path), replacing a leftover copy from an earlier
/// failed import, and returns its pin computed from the copy. The old tree is read from the
/// canonical root `from_real` down, never through a symlink.
fn copy_package(
    host: &dyn Host,
    top: &Path,
    from_real: &Path,
    from: &Path,
    p: &LocalPackage,
    dest: &Path,
    log: &mut CopyLog,
) -> Result<String> {
    let mut run = || -> Result<String> {
        let rel = p
            .dir
            .strip_prefix(from)
            .with_context(|| format!("{} is outside {}", p.dir.display(), from.display()))?;
        match fs::symlink_metadata(dest) {
            Ok(m) if m.is_dir() => fs::remove_dir_all(dest)?,
            Ok(_) => fs::remove_file(dest)?,
            Err(_) => {}
        }
        ensure_dirs(host, top, dest.parent().context("no parent")?)?;
        if p.single_file {
            let parent = open_src_dir(from_real, rel.parent().context("no parent")?)?;
            let name = rel.file_name().context("no file name")?;
            let f = crate::host::fsx::open_file_at(&parent, name, &p.dir)?;
            if p.kind == Kind::MuPlugin {
                copy_file(host, f, &p.dir, dest, log)?;
                crate::hash::sha256_file(dest)
            } else {
                make_dir(host, dest)?;
                copy_file(host, f, &p.dir, &dest.join(format!("{}.php", p.slug)), log)?;
                crate::hash::tree_hash(dest)
            }
        } else {
            let dir = open_src_dir(from_real, rel)?;
            copy_tree(host, &dir, &p.dir, dest, log)?;
            crate::hash::tree_hash(dest)
        }
    };
    run().with_context(|| format!("copying {} to {}", p.dir.display(), dest.display()))
}

/// Checks the arguments and that `--from` looks like a WordPress root; returns the site file
/// path (which must not exist yet).
fn check_args(g: &GlobalConfig, args: &ImportArgs) -> Result<PathBuf> {
    if !crate::config::validate::valid_site_name(&args.site) {
        return Err(usage(format!(
            "invalid site name {:?} (must match ^[a-z][a-z0-9-]{{0,30}}$)",
            args.site
        )));
    }
    if !args.from.is_absolute() || !args.src_root.is_absolute() {
        return Err(usage("--from and the source root must be absolute paths"));
    }
    if args.base.as_ref().is_some_and(|b| !b.is_absolute()) {
        return Err(usage("--base must be an absolute path"));
    }
    let site_file = g.sites_dir.join(format!("{}.toml", args.site));
    if fs::symlink_metadata(&site_file).is_ok() {
        return Err(usage(format!(
            "site file {} already exists",
            site_file.display()
        )));
    }
    if !fs::symlink_metadata(args.from.join("wp-includes/version.php")).is_ok_and(|m| m.is_file()) {
        return Err(usage(format!(
            "{} is not a WordPress root (no wp-includes/version.php)",
            args.from.display()
        )));
    }
    Ok(site_file)
}

/// Imports the classic WordPress webroot `args.from` as site `args.site` (see the module docs).
/// Never deploys. Nothing is written before every wordpress.org lookup has succeeded and the
/// generated site file has validated.
pub fn run(
    host: &dyn Host,
    g: &GlobalConfig,
    ctx: &ImportCtx,
    args: ImportArgs,
) -> Result<ImportReport> {
    // 1–2. Arguments and refusals; root before anything is read, fetched or cached.
    let site_file = check_args(g, &args)?;
    if !host.is_root() {
        return Err(usage("iwp import must be run as root"));
    }
    // Read-only; before detection, lookups and writes, rather than late inside `setup`.
    crate::host::nginx::check_worker_group(host, g)?;
    let name = args.site.clone();
    // The old tree is read from its canonical root down, never through a symlink below it.
    let from_real = fs::canonicalize(&args.from)
        .with_context(|| format!("resolving {}", args.from.display()))?;
    // 3. Scan (read-only).
    let det = detect::detect(&args.from)?;
    // 4. wp-config.php; its values never reach errors.
    let (cfg_path, php, cfg_uid, root_uid) = read_wp_config(&from_real)?;
    let old = wpconfig::parse(&php).with_context(|| format!("parsing {}", cfg_path.display()))?;
    drop(php);
    // 5. Classify; a failed lookup is never "clean" and aborts before anything is written.
    let mut classified = Vec::new();
    let mut failed = Vec::new();
    for r in classify::classify(&ctx.wporg, &det.packages) {
        match r {
            Ok(c) => classified.push(c),
            Err(e) => failed.push(format!("{e:#}")),
        }
    }
    if !failed.is_empty() {
        bail!(
            "wordpress.org lookups failed; nothing was written:\n  {}",
            failed.join("\n  ")
        );
    }
    // 6. The site text, in memory.
    let issues = validate_core_versions(&det.wordpress, &args.php);
    if !issues.is_empty() {
        let msg: Vec<String> = issues.iter().map(|i| i.to_string()).collect();
        return Err(usage(msg.join("; ")));
    }
    let domains = if !args.domains.is_empty() {
        args.domains.clone()
    } else if let Some(m) = &old.multisite {
        vec![m.domain.clone()]
    } else {
        return Err(usage(
            "no domain given and wp-config.php has no DOMAIN_CURRENT_SITE; pass --domain <d> (repeatable)",
        ));
    };
    let mut warnings: Vec<String> = det.warnings.clone();
    warnings.extend(wp_config_owner_warning(&cfg_path, cfg_uid, root_uid));
    warnings.extend(old.warnings.iter().cloned());
    let mut lines = Vec::new();
    let entries = plan_entries(&args, classified, &mut lines, &mut warnings);
    let db_user = if args.new_db_user {
        crate::host::db::db_user(&name)
    } else {
        old.db_user.clone()
    };
    // The host-wide sites lock covers the id assignment until the site file is installed, so
    // a concurrent `new` or `import` cannot take the same id (released right after step 9).
    let sites_lock = crate::host::lock::SitesLock::acquire(host)?;
    let existing = existing_sites(g)?;
    if !args.new_db_user {
        check_old_db_user(&db_user, &existing)?;
    }
    let st = SiteText {
        args: &args,
        // Free in /etc/subuid and /etc/subgid too, so `setup` below cannot refuse it.
        id: pick_id(host, g, &existing, args.id)?,
        domains: &domains,
        wordpress: &det.wordpress,
        languages: &det.languages,
        old: &old,
        db_user: &db_user,
        entries: &entries,
    };
    let draft = site_text(&st, &|_| PENDING_PIN.to_string())?;
    // 7. Validate in memory (site file and secrets), then the site lock.
    let site = validate_new(g, existing, &name, &draft, &site_file)?;
    let base = site.base_dir(g);
    for (what, p) in [
        ("base", sys(host, &base)),
        ("source root", sys(host, args.src_root.join(&name))),
        ("sites_dir", g.sites_dir.clone()),
    ] {
        if overlaps(&p, &args.from) {
            return Err(usage(format!(
                "{what} {} overlaps the old webroot {}; import never writes there",
                p.display(),
                args.from.display()
            )));
        }
    }
    crate::host::secrets::DbSecret {
        name: old.db_name.clone(),
        user: db_user.clone(),
        password: if args.new_db_user {
            "generated".into()
        } else {
            old.db_password.clone()
        },
        host: "iwp-db-host".into(),
        prefix: old.table_prefix.clone(),
    }
    .render()
    .and_then(|_| crate::host::secrets::render_salts(&old.salts))
    .context(
        "the old wp-config.php values cannot be stored as podman secrets; nothing was written",
    )?;
    let _lock = lock_site(host, &name, &site_file)?;
    // The uploads are copied as the site's www user: make sure it can read them before
    // anything is written.
    let www = Identity::for_site(site.id, g.id_offset).www_uid;
    let up_src = from_real.join("wp-content/uploads");
    let has_uploads = fs::symlink_metadata(&up_src).is_ok_and(|m| m.is_dir());
    if has_uploads {
        check_copy_tools(host)?;
        check_uploads_readable(host, www, &up_src)?;
    }
    let mut uploads_php = Vec::new();
    if has_uploads {
        let (n_php, listed) = uploads_php_files(&up_src);
        uploads_php = listed;
        if n_php > 0 {
            warnings.push(format!(
                "{n_php} PHP file(s) in wp-content/uploads (listed under uploads_php): they are copied, and `iwp verify` reports each as shared_php until deleted; uploads can never be allowlisted"
            ));
        }
    }
    let net = crate::host::db::podman_network(host, &g.podman_network)?;
    // setup checks this too, but only after the site file exists: refuse before any write.
    let stored = crate::lifecycle::setup::stored_db_secret(host, &name)?;
    crate::lifecycle::setup::check_db_user_free(host, g, &db_user, stored.as_ref(), &net)?;
    drop(stored);
    let mut written = Vec::new();

    // 8. Pinned copies of custom code; the pins come from the copies.
    let top = sys(host, &args.src_root);
    let mut pins = vec![String::new(); entries.len()];
    let mut log = CopyLog::default();
    for (i, e) in entries.iter().enumerate() {
        if let Plan::Source(dest) = &e.plan {
            pins[i] = copy_package(
                host,
                &top,
                &from_real,
                &args.from,
                &e.pkg,
                &sys(host, dest),
                &mut log,
            )?;
            lines[e.line].path = Some(dest.clone());
            lines[e.line].sha256 = Some(pins[i].clone());
            written.push(dest.clone());
        }
    }
    if log.not_world_readable_count > 0 {
        let more = log.not_world_readable_count - log.not_world_readable.len();
        warnings.push(format!(
            "{} copied source file(s) were not world-readable in the old tree (the copies are 0644; check they hold no secrets): {}{}",
            log.not_world_readable_count,
            log.not_world_readable.join(", "),
            if more > 0 {
                format!(" (and {more} more)")
            } else {
                String::new()
            }
        ));
    }
    let text = site_text(&st, &|i| pins[i].clone())?;
    let site = parse_site(&text).context("parsing the generated site file")?;

    // 9. The site file, never clobbering.
    ensure_sites_dir(host, g)?;
    install_site_file(g, &name, &text, &site_file)?;
    drop(sites_lock);
    written.insert(0, site_file.clone());
    eprintln!("[{name}] wrote {}", site_file.display());

    // 10–11. Provisioning and uploads. A failure from here on still writes the report.
    let report_path = base.join("config/import-report.json");
    let up_dst = base.join("shared/uploads");
    let mut uploads_not_copied = Vec::new();
    let mut stage = "setup";
    let late = (|| -> Result<()> {
        let opts = SetupOpts {
            salts_from: None,
            salts: Some(old.salts.clone()),
            db_password: (!args.new_db_user).then(|| old.db_password.clone()),
        };
        setup(host, g, &site, &opts, &net)?;
        drop(opts);
        stage = "copying uploads";
        if !has_uploads {
            warnings.push(
                "wp-content/uploads is missing or not a real directory; no uploads were copied"
                    .into(),
            );
            return Ok(());
        }
        eprintln!("[{name}] uploads");
        let (n, listed) = uploads_symlinks(&up_src);
        uploads_not_copied = listed;
        if n > 0 {
            warnings.push(format!(
                "{n} symlink(s) in wp-content/uploads were not copied (listed under uploads_not_copied, at most {LIST_MAX})"
            ));
        }
        // The site user cannot enter <base> (0750 root:<nginx_group>, no groups for it): a
        // search-only ACL for the copy, revoked on every path once it was granted.
        // Every command is built first, so nothing fallible sits between grant and revoke.
        let grant = acl_grant(www, &base)?;
        let rsync = uploads_cmd(www, &up_src, &up_dst)?.timeout(RSYNC_TIMEOUT);
        let revoke = acl_revoke(www, &base)?;
        let mask = acl_mask_remove(&base)?;
        eprintln!("[{name}] {}", interrupt_hint(&revoke, &mask));
        crate::host::run_ok(host, &grant)?;
        let out = host.run(&rsync);
        match run_status(host, &revoke) {
            Ok(()) => {
                // The mask entry setfacl added stays after the revoke; without it the base
                // has its minimal ACL again. Best effort.
                if let Err(e) = run_status(host, &mask) {
                    warnings.push(format!(
                        "could not remove the leftover ACL mask on {} ({e:#}); remove it by hand: {mask}",
                        base.display()
                    ));
                }
            }
            Err(e) => warnings.push(format!(
                "could not remove the temporary ACL for the site user on {} ({e:#}); remove it by hand: {revoke}; {mask}",
                base.display()
            )),
        }
        let out = out?;
        match out.status {
            0 => {}
            23 => {
                // Partial copy: fail unless at least 90% of the regular files arrived.
                let total = count_files(&up_src);
                let copied = count_files(&sys(host, &up_dst));
                let stderr = String::from_utf8_lossy(&out.stderr);
                if copied * 10 < total * 9 {
                    bail!(
                        "only {copied} of {total} upload files were copied (rsync exit 23: files not readable by the site user; at least 90% are required): {}",
                        stderr.trim()
                    );
                }
                warnings.push(format!(
                    "some uploads were not readable by the site user and were not copied (see rsync output); {} of {total} files were not copied: {}",
                    total.saturating_sub(copied),
                    stderr.trim()
                ));
            }
            24 => warnings.push(
                "some uploads vanished during the copy (rsync exit 24); re-run the rsync before switching over".into(),
            ),
            s => bail!(
                "rsync exit {s}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        }
        stage = "changing the uploads owner";
        crate::host::fsx::chown_tree_nofollow(host, &sys(host, &up_dst), www, www)?;
        crate::host::layout::prepare_site_dirs(host, g, &site)?;
        stage = "relabelling the uploads";
        crate::host::selinux::relabel(host, &[up_dst.as_path()])?;
        written.push(up_dst.clone());
        Ok(())
    })();

    // 12. The report (root 0600), also after a late failure.
    written.push(report_path.clone());
    let mut report = ImportReport {
        site: name.clone(),
        from: args.from.clone(),
        site_file: site_file.clone(),
        wordpress: det.wordpress,
        db_user,
        packages: lines,
        dropins: det.dropins,
        other_content_dirs: det.other_content_dirs,
        custom_translations: custom_translations(&args.from, &entries),
        other_root_files: det
            .other_root_files
            .iter()
            .map(|n| root_entry_line(&args.from, n))
            .collect(),
        not_carried: old.not_carried.clone(),
        warnings,
        written,
        uploads_not_copied,
        uploads_php,
        error: None,
        recovery: Vec::new(),
    };
    if let Err(e) = late {
        // Where the report goes when <base>/config cannot be written (setup failed before
        // creating it): the recovery commands must not exist on stdout only.
        let fallback = g.cache_dir.join(format!("import-report-{name}.json"));
        let cause = format!("{e:#}");
        let failed = |at: Option<&Path>| {
            let report = match at {
                Some(p) => format!("recovery commands are in {}", p.display()),
                None => {
                    "the report could not be written; the recovery commands are only in this output"
                        .to_string()
                }
            };
            format!(
                "{stage} failed; {} and the source copies were kept ({report})",
                site_file.display()
            )
        };
        report.error = Some(format!("{}: {cause}", failed(Some(&report_path))));
        if stage == "setup" {
            report.recovery.push(format!(
                "iwp setup {name} --salts-from {}",
                cfg_path.display()
            ));
            report.recovery.push(
                "note: --salts-from must name a regular, root-readable file (a symlink is refused); if the old wp-config.php has since been replaced by a symlink, point it at a regular copy".into(),
            );
            if !args.new_db_user {
                report.recovery.push(
                    "note: `iwp setup` keeps the stored DB password or generates a new one; it does not reuse the old site's password (the old site's own DB account is untouched)".into(),
                );
            }
        }
        if has_uploads {
            report.recovery.push(acl_grant(www, &base)?.to_string());
            report
                .recovery
                .push(uploads_cmd(www, &up_src, &up_dst)?.to_string());
            report.recovery.push(acl_revoke(www, &base)?.to_string());
            report.recovery.push(acl_mask_remove(&base)?.to_string());
            report
                .recovery
                .push(format!("chown -R -h {www}:{www} {}", up_dst.display()));
            report
                .recovery
                .push(format!("restorecon -RF {}", up_dst.display()));
        }
        let mut at = Some(report_path.clone());
        if let Err(we) = write_report(host, &sys(host, &report_path), &report) {
            // The report names itself (`error`, `written`), so each is set before the write.
            report.written.retain(|p| p != &report_path);
            report.written.push(fallback.clone());
            report.error = Some(format!("{}: {cause}", failed(Some(&fallback))));
            report.warnings.push(format!(
                "the report is in {} ({} could not be written: {we:#})",
                fallback.display(),
                report_path.display()
            ));
            let to = sys(host, &fallback);
            let written = fs::create_dir_all(to.parent().expect("cache_dir is absolute"))
                .map_err(anyhow::Error::from)
                .and_then(|()| write_report(host, &to, &report));
            match written {
                Ok(()) => at = Some(fallback),
                Err(fe) => {
                    at = None;
                    report.written.pop();
                    report.warnings.pop();
                    report.error = Some(format!("{}: {cause}", failed(None)));
                    report.warnings.push(format!(
                        "the report could not be written to {} ({we:#}) or to {} ({fe:#})",
                        report_path.display(),
                        fallback.display()
                    ));
                }
            }
        }
        return Err(anyhow::Error::new(ImportError {
            report: Box::new(report),
            error: e.context(failed(at.as_deref())),
        }));
    }
    write_report(host, &sys(host, &report_path), &report)?;
    Ok(report)
}

/// MariaDB system accounts an import must never take over.
const SYSTEM_DB_USERS: [&str; 4] = ["root", "mysql", "mariadb.sys", "debian-sys-maint"];

/// Refuses keeping the old DB user when it is a system account or another site's user.
fn check_old_db_user(user: &str, existing: &[LoadedSite]) -> Result<()> {
    if SYSTEM_DB_USERS.iter().any(|s| s.eq_ignore_ascii_case(user)) {
        return Err(usage(format!(
            "the old site connects as the MariaDB system account {user:?}; iwp will not take it over: re-run with --new-db-user"
        )));
    }
    let owners: Vec<String> = existing
        .iter()
        .filter(|l| {
            l.site
                .database
                .user
                .clone()
                .unwrap_or_else(|| crate::host::db::db_user(&l.site.name))
                == user
        })
        .map(|l| l.path.display().to_string())
        .collect();
    if !owners.is_empty() {
        return Err(usage(format!(
            "the old site's database user {user:?} is already used by {}; sites must not share a MariaDB account: re-run with --new-db-user",
            owners.join(", ")
        )));
    }
    Ok(())
}

/// Takes the site lock, then re-checks that no site file appeared meanwhile (another `new` or
/// `import` racing this one) before anything is written.
fn lock_site(host: &dyn Host, name: &str, site_file: &Path) -> Result<crate::host::lock::SiteLock> {
    let lock = crate::host::lock::SiteLock::acquire(host, name)?;
    if fs::symlink_metadata(site_file).is_ok() {
        return Err(usage(format!(
            "site file {} already exists",
            site_file.display()
        )));
    }
    Ok(lock)
}

/// Fails with setfacl guidance unless the site's www user (no supplementary groups) can read
/// and enter `up` (which must be the canonical path).
fn check_uploads_readable(host: &dyn Host, www: u32, up: &Path) -> Result<()> {
    let p = str_path(up)?;
    let out = host.run(&Cmd::new("setpriv").args([
        format!("--reuid={www}"),
        format!("--regid={www}"),
        "--clear-groups".into(),
        "--".into(),
        "test".into(),
        "-r".into(),
        p.into(),
        "-a".into(),
        "-x".into(),
        p.into(),
    ]))?;
    if out.status == 0 {
        return Ok(());
    }
    // Ancestors (from / down) that the site user could only enter through "other" x.
    let mut cmds: Vec<String> = up
        .ancestors()
        .skip(1)
        .filter(|a| {
            use std::os::unix::fs::MetadataExt;
            fs::metadata(a).is_ok_and(|m| m.mode() & 0o001 == 0 && m.uid() != www)
        })
        .map(|a| format!("setfacl -m u:{www}:x {}", a.display()))
        .collect();
    cmds.reverse();
    cmds.push(format!("setfacl -R -m u:{www}:rX {p}"));
    Err(usage(format!(
        "the new site user (uid {www}) cannot read {p}; grant read access for the import, e.g. setfacl -R -m u:{www}:rX <path-to-each-ancestor-and-uploads> (or setfacl -m u:{www}:x on each ancestor directory and setfacl -R -m u:{www}:rX on uploads), then re-run iwp import; minimal commands: {}",
        cmds.join("; ")
    )))
}

/// Regular files under `dir` (no-follow walk).
fn count_files(dir: &Path) -> usize {
    walkdir::WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file())
        .count()
}

/// The unprivileged uploads copy: as the site's www user with no supplementary groups,
/// without symlinks, ACLs or xattrs, with fixed modes.
fn uploads_cmd(www: u32, src: &Path, dst: &Path) -> Result<Cmd> {
    Ok(Cmd::new("setpriv")
        .args([
            format!("--reuid={www}"),
            format!("--regid={www}"),
            "--clear-groups".into(),
            "--".into(),
            "rsync".into(),
            "-rtH".into(),
            "--no-links".into(),
            "--chmod=D2755,F0644".into(),
        ])
        .arg(format!("{}/", str_path(src)?))
        .arg(format!("{}/", str_path(dst)?)))
}

/// Printed before the uploads copy: an interrupted import (Ctrl-C, a dropped SSH session)
/// cannot revoke the temporary ACL itself.
fn interrupt_hint(revoke: &Cmd, mask: &Cmd) -> String {
    format!(
        "copying uploads; if this is interrupted, remove the temporary ACL by hand: {revoke}; {mask}"
    )
}

/// Lets the site's www user search (only) the root-owned `base` for the uploads copy.
fn acl_grant(www: u32, base: &Path) -> Result<Cmd> {
    Ok(Cmd::new("setfacl").args(["-m".into(), format!("u:{www}:x"), str_path(base)?.into()]))
}

/// Removes the ACL entry `acl_grant` added.
fn acl_revoke(www: u32, base: &Path) -> Result<Cmd> {
    Ok(Cmd::new("setfacl").args(["-x".into(), format!("u:{www}"), str_path(base)?.into()]))
}

/// Removes the mask entry `acl_grant` created (a separate call: setfacl refuses to drop the
/// mask while a named entry still needs it).
fn acl_mask_remove(base: &Path) -> Result<Cmd> {
    Ok(Cmd::new("setfacl").args(["-x", "m::", str_path(base)?]))
}

/// Runs `cmd`; a non-zero exit is an error with its stderr.
fn run_status(host: &dyn Host, cmd: &Cmd) -> Result<()> {
    let o = host.run(cmd)?;
    if o.status != 0 {
        bail!(
            "exit {}: {}",
            o.status,
            String::from_utf8_lossy(&o.stderr).trim()
        );
    }
    Ok(())
}

/// The uploads copy needs `setfacl` and `rsync` on the host; refuses before any write.
fn check_copy_tools(host: &dyn Host) -> Result<()> {
    let missing: Vec<String> = [("setfacl", "acl"), ("rsync", "rsync")]
        .into_iter()
        .filter(|(tool, _)| run_status(host, &Cmd::new(*tool).arg("--version")).is_err())
        .map(|(tool, pkg)| format!("{tool} ({pkg})"))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    Err(usage(format!(
        "the uploads copy needs {}; install the package(s) in parentheses, then re-run iwp import",
        missing.join(" and ")
    )))
}

/// Symlinks under the old uploads (no-follow walk): their count and up to `LIST_MAX` lines.
fn uploads_symlinks(up_src: &Path) -> (usize, Vec<String>) {
    let mut n = 0;
    let mut listed = Vec::new();
    for e in walkdir::WalkDir::new(up_src)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .flatten()
    {
        if e.path_is_symlink() && e.depth() > 0 {
            n += 1;
            if listed.len() < LIST_MAX {
                let rel = e.path().strip_prefix(up_src).unwrap_or(e.path());
                listed.push(format!(
                    "not copied: symlink wp-content/uploads/{}",
                    rel.display()
                ));
            }
        }
    }
    (n, listed)
}

/// Most `custom_translations` lines.
const TRANSLATIONS_MAX: usize = 50;

/// Translation files the new site will not have (no-follow walks): under
/// `languages/{plugins,themes}` those not named `<slug>-…` for a wordpress.org entry of that
/// kind (whose language packs the build installs), and everything under `languages/loco`.
fn custom_translations(from: &Path, entries: &[Entry]) -> Vec<String> {
    let wporg = |k: Kind| -> Vec<String> {
        entries
            .iter()
            .filter(|e| e.pkg.kind == k && matches!(e.plan, Plan::Wporg(_)))
            .map(|e| format!("{}-", e.pkg.slug))
            .collect()
    };
    let lang = from.join("wp-content/languages");
    let mut out = Vec::new();
    for (sub, known) in [
        ("loco", Vec::new()),
        ("plugins", wporg(Kind::Plugin)),
        ("themes", wporg(Kind::Theme)),
    ] {
        let dir = lang.join(sub);
        if !fs::symlink_metadata(&dir).is_ok_and(|m| m.is_dir()) {
            continue;
        }
        for e in walkdir::WalkDir::new(&dir)
            .follow_links(false)
            .sort_by_file_name()
            .into_iter()
            .flatten()
        {
            if !e.file_type().is_file() {
                continue;
            }
            let name = e.file_name().to_string_lossy();
            if sub != "loco" && known.iter().any(|k| name.starts_with(k.as_str())) {
                continue;
            }
            let rel = e.path().strip_prefix(from).unwrap_or(e.path());
            out.push(rel.display().to_string());
        }
    }
    if out.len() > TRANSLATIONS_MAX {
        let more = out.len() - TRANSLATIONS_MAX;
        out.truncate(TRANSLATIONS_MAX);
        out.push(format!("(and {more} more)"));
    }
    out
}

/// A report line for a top-level webroot entry that is not carried (no-follow stat).
fn root_entry_line(from: &Path, name: &str) -> String {
    let m = fs::symlink_metadata(from.join(name));
    let hint = match m {
        Ok(m) if m.file_type().is_symlink() => "symlink: not carried; review".to_string(),
        Ok(m) if m.is_dir() => {
            "directory: not carried; serve what you need from the server block".to_string()
        }
        _ if name.eq_ignore_ascii_case(".htaccess") || name.eq_ignore_ascii_case(".user.ini") => {
            "Apache/PHP per-directory config: not used under iwp; review its rules".to_string()
        }
        _ if crate::lifecycle::verify::classify_shared_file(
            name,
            Path::new("/nonexistent"),
            true,
        )
        .is_some() =>
        {
            "PHP: not supported; review".to_string()
        }
        _ => format!("static file: not carried; serve it with a server-level `location = /{name}`"),
    };
    format!("{name} ({hint})")
}

/// Most `uploads_php` lines.
const UPLOADS_PHP_MAX: usize = 50;

/// PHP-like files and `.htaccess`/`.user.ini` under the old uploads (no-follow walk), classified
/// as `iwp verify` will see them: the number of real PHP files and up to `UPLOADS_PHP_MAX` lines.
fn uploads_php_files(up_src: &Path) -> (usize, Vec<String>) {
    use crate::lifecycle::verify::{SharedFile, classify_shared_file};
    let mut n_php = 0;
    let mut listed = Vec::new();
    for e in walkdir::WalkDir::new(up_src)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .flatten()
    {
        if e.depth() == 0 || e.file_type().is_dir() {
            continue;
        }
        let name = e.file_name().to_string_lossy();
        let Some(class) = classify_shared_file(&name, e.path(), e.path_is_symlink()) else {
            continue;
        };
        let what = match class {
            SharedFile::Htaccess => {
                ".htaccess/.user.ini: inert under nginx; `iwp verify` only notes it"
            }
            SharedFile::Stub => "silence stub: `iwp verify` only notes it",
            SharedFile::Php => {
                n_php += 1;
                "PHP: `iwp verify` reports it as shared_php; delete it before the first deploy"
            }
        };
        if listed.len() < UPLOADS_PHP_MAX {
            let rel = e.path().strip_prefix(up_src).unwrap_or(e.path());
            listed.push(format!("wp-content/uploads/{} ({what})", rel.display()));
        }
    }
    (n_php, listed)
}

fn write_report(host: &dyn Host, path: &Path, report: &ImportReport) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    write_atomic(
        host,
        path,
        format!("{json}\n").as_bytes(),
        &FileSpec {
            mode: Some(0o600),
            owner: Some((0, 0)),
        },
    )?;
    Ok(())
}

#[cfg(test)]
mod tests;
