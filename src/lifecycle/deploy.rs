//! Deploy and rollback orchestration.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::build::sources::Origin;
use crate::build::{BuildEnv, BuiltRelease, ImageOps, ReleaseManifest, remove_tree};
use crate::config::{GlobalConfig, Site};
use crate::fetch::net::Fetcher;
use crate::host::{Cmd, CmdOutput, Host, run_ok, sys};
use crate::lifecycle::fcgi::SmokeOutcome;
use crate::render::{RenderEnv, render_site};

/// The effects of a deploy that are not plain host commands, so tests can script them.
pub trait DeployOps {
    fn build(&self, site: &Site) -> Result<BuiltRelease>;
    fn dump(&self, site: &Site, dest: &Path) -> Result<()>;
    /// Runs wp-cli non-interactively (Entry::Capture) and returns its output.
    fn wp(&self, site: &Site, args: &[String]) -> Result<CmdOutput>;
    /// `first_deploy`: the site had no current release before this deploy.
    fn smoke(&self, site: &Site, first_deploy: bool) -> SmokeOutcome;
    /// Waits until the FPM socket exists and the unit is active (60 s).
    fn wait_ready(&self, site: &Site) -> Result<()>;
    fn gateway(&self) -> Result<std::net::Ipv4Addr>;
    /// Tables in the site's database that carry its table prefix.
    fn count_prefixed_tables(&self, site: &Site) -> Result<u64>;
}

#[derive(Debug, Clone)]
pub struct DeployReport {
    pub site: String,
    pub release: String,
    pub dry_run_diff: Option<Vec<String>>,
    /// Problems from update-db / smoke on the new release, and from a failed automatic
    /// rollback (empty = success).
    pub problems: Vec<String>,
    /// Some(..) when an automatic rollback put `current` back: (release now live, its problems).
    pub rolled_back: Option<(String, Vec<String>)>,
    pub dump: Option<PathBuf>,
    pub gc_removed: Vec<String>,
    /// Non-fatal issues (cache emptying, GC, missing site snapshots).
    pub warnings: Vec<String>,
}

impl DeployReport {
    /// The command that restores the pre-deploy database, when an automatic rollback put the
    /// previous release back live. The database is never restored automatically.
    pub fn restore_hint(&self) -> Option<String> {
        match (&self.rolled_back, &self.dump) {
            (Some(_), Some(d)) => Some(format!(
                "iwp db restore {} {} --yes",
                self.site,
                d.display()
            )),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RollbackReport {
    pub release: String,
    /// Smoke-test problems on the release rolled back to (empty = healthy).
    pub problems: Vec<String>,
    pub warnings: Vec<String>,
}

fn step(site: &Site, what: &str) {
    eprintln!("[{}] {what}", site.name);
}

fn warn(site: &Site, warnings: &mut Vec<String>, msg: String) {
    eprintln!("[{}] warning: {msg}", site.name);
    warnings.push(msg);
}

/// Records the resolved site file a release is deployed with (`config/releases/<name>.json`,
/// 0644 root in a 0755 root directory), so a rollback renders exactly what that release had.
fn write_snapshot(host: &dyn Host, base: &Path, site: &Site, name: &str) -> Result<()> {
    let path = crate::lifecycle::releases::snapshot_path(base, name);
    let dir = path.parent().expect("snapshot path has a parent");
    crate::host::fsx::ensure_dir(host, dir, 0o755, Some((0, 0)))?;
    let body = serde_json::to_vec_pretty(site).context("serializing site snapshot")?;
    crate::host::fsx::write_atomic(
        host,
        &path,
        &body,
        &crate::host::fsx::FileSpec {
            mode: Some(0o644),
            owner: Some((0, 0)),
        },
    )
    .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// The snapshot of release `name`, if it has one. A snapshot that does not parse (e.g. written
/// by a newer iwp) counts as missing, with a warning naming it; one that belongs to
/// another site is an error.
pub(crate) fn read_snapshot(
    base: &Path,
    site: &Site,
    name: &str,
    warnings: &mut Vec<String>,
) -> Result<Option<Site>> {
    let path = crate::lifecycle::releases::snapshot_path(base, name);
    match std::fs::read(&path) {
        Ok(b) => {
            let snap: Site = match serde_json::from_slice(&b) {
                Ok(s) => s,
                Err(e) => {
                    warn(
                        site,
                        warnings,
                        format!(
                            "site snapshot {} cannot be parsed ({e}); using the current site file for release {name}",
                            path.display()
                        ),
                    );
                    return Ok(None);
                }
            };
            if snap.name != site.name {
                bail!("{} is a snapshot of site {}", path.display(), snap.name);
            }
            Ok(Some(snap))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// The site as release `name` was deployed: its snapshot, or (with a warning) `site`.
fn release_site(base: &Path, site: &Site, name: &str, warnings: &mut Vec<String>) -> Result<Site> {
    let path = crate::lifecycle::releases::snapshot_path(base, name);
    let had_file = path.exists();
    match read_snapshot(base, site, name, warnings)? {
        Some(snap) => Ok(snap),
        None => {
            if !had_file {
                warn(
                    site,
                    warnings,
                    format!(
                        "no site snapshot for release {name}; rendering it from the current site file"
                    ),
                );
            }
            Ok(site.clone())
        }
    }
}

/// The site as it is running: the current release's snapshot, so `iwp wp`, `iwp shell` and
/// `iwp cron` match the live container even when the site file has edits that are not deployed
/// yet. `[wpcli]` is an operator setting, not release content, and always comes from `site`.
/// Without a current release (or without a readable snapshot of it) this is `site` itself.
pub fn deployed_site(
    host: &dyn Host,
    g: &GlobalConfig,
    site: &Site,
    warnings: &mut Vec<String>,
) -> Result<Site> {
    let base = sys(host, site.base_dir(g));
    let Some(current) = crate::lifecycle::releases::current(&base)? else {
        return Ok(site.clone());
    };
    Ok(match read_snapshot(&base, site, &current, warnings)? {
        Some(mut snap) => {
            snap.wpcli = site.wpcli.clone();
            snap
        }
        None => site.clone(),
    })
}

/// Gives the release's symlinks into shared/ (uploads and the declared writable dirs) to the
/// site's www UID, which owns their targets. The nginx include only follows a symlink whose
/// owner also owns its target, so links a site plants in its writable dirs lead nowhere.
fn own_release_links(host: &dyn Host, g: &GlobalConfig, site: &Site, name: &str) -> Result<()> {
    let release = sys(host, site.base_dir(g)).join("releases").join(name);
    let www = crate::host::identity::Identity::for_site(site.id, g.id_offset).www_uid;
    for rel in std::iter::once("wp-content/uploads").chain(site.writable_paths()) {
        let link = release.join(rel);
        if std::fs::symlink_metadata(&link).is_ok_and(|m| m.file_type().is_symlink()) {
            host.lchown(&link, www, www)?;
        }
    }
    Ok(())
}

/// `own_release_links` for the release that is live, if any (for `iwp nginx apply`, which
/// installs the include without activating a release).
pub fn own_current_links(
    host: &dyn Host,
    g: &GlobalConfig,
    site: &Site,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let base = sys(host, site.base_dir(g));
    let Some(current) = crate::lifecycle::releases::current(&base)? else {
        return Ok(());
    };
    // The live release's own definition says which writable dirs it links.
    let live = read_snapshot(&base, site, &current, warnings)?.unwrap_or_else(|| site.clone());
    own_release_links(host, g, &live, &current)
}

/// Points `current` at `name` and (re)starts the site on that release's image, rendered from
/// that release's site snapshot. Returns the site as deployed in that release.
fn activate(
    host: &dyn Host,
    g: &GlobalConfig,
    site: &Site,
    ops: &dyn DeployOps,
    name: &str,
    warnings: &mut Vec<String>,
) -> Result<Site> {
    let base = sys(host, site.base_dir(g));
    let manifest = crate::lifecycle::releases::read_manifest(&base, name)?;
    let rsite = release_site(&base, site, name, warnings)?;
    let site = &rsite;
    let env = RenderEnv {
        db_host_ip: ops.gateway()?,
        image: Some(manifest.image_digest.clone()),
        ..RenderEnv::default()
    };
    let rendered = render_site(g, site, &env)?;
    // Both must be in place before the include is applied, or uploads answer 403.
    crate::host::selinux::install_module(host)?;
    own_release_links(host, g, site, name)?;
    // `current` still points at the live release while the include is swapped.
    own_current_links(host, g, site, warnings)?;
    crate::host::selinux::relabel(
        host,
        &[site.base_dir(g).join("releases").join(name).as_path()],
    )?;
    {
        step(site, "nginx");
        let _l = crate::host::lock::NginxLock::acquire(host)?;
        crate::host::nginx::apply(host, g, site, &rendered)?;
    }
    step(site, &format!("activating {name}"));
    crate::lifecycle::releases::swap_current(&base, name)?;
    crate::host::install::install_rendered(host, g, site, &rendered, &|_| true)?;
    run_ok(host, &Cmd::new("systemctl").arg("daemon-reload"))?;
    run_ok(
        host,
        &Cmd::new("systemd-tmpfiles").args([
            "--create".to_string(),
            format!("/etc/tmpfiles.d/iwp-{}.conf", site.name),
        ]),
    )?;
    let run_dir = PathBuf::from(format!("/run/iwp/{}", site.name));
    crate::host::selinux::relabel(host, &[run_dir.as_path()])?;
    run_ok(
        host,
        &Cmd::new("systemctl").args(["restart".to_string(), format!("iwp-{}.service", site.name)]),
    )?;
    run_ok(
        host,
        &Cmd::new("systemctl").args([
            "enable".to_string(),
            "--now".into(),
            format!("iwp-{}-cron.timer", site.name),
        ]),
    )?;
    run_ok(
        host,
        &Cmd::new("systemctl").args([
            "enable".to_string(),
            "--now".into(),
            format!("iwp-{}-verify.timer", site.name),
        ]),
    )?;
    ops.wait_ready(site)?;
    empty_caches(host, g, site, warnings);
    Ok(rsite)
}

/// Empties declared cache dirs (contents only) through a no-follow handle walk. Failures are
/// warnings: a stale cache never fails an activation. A missing dir is fine.
fn empty_caches(host: &dyn Host, g: &GlobalConfig, site: &Site, warnings: &mut Vec<String>) {
    let base = sys(host, site.base_dir(g));
    for p in site
        .plugins
        .iter()
        .chain(&site.themes)
        .flat_map(|p| &p.cache)
    {
        let rel = Path::new("shared").join(crate::config::shared_rel(p));
        if let Err(e) = crate::host::fsx::empty_dir_nofollow(&base, &rel) {
            warn(site, warnings, format!("emptying cache {p}: {e:#}"));
        }
    }
}

/// Health checks; returns problems (empty = healthy). Forward deploys run `wp core update-db`
/// then the smoke test; rollbacks run the smoke test only: an older core must never
/// "upgrade" a database a newer core already migrated. `first_deploy` turns a redirect
/// to install.php into a warning: only a site's first deploy may find WordPress not installed.
fn check(
    site: &Site,
    ops: &dyn DeployOps,
    update_db: bool,
    first_deploy: bool,
    warnings: &mut Vec<String>,
) -> Vec<String> {
    let mut problems = Vec::new();
    if update_db {
        update_db_all(site, ops, &mut problems);
    }
    if problems.is_empty() {
        step(site, "smoke test");
        let o = ops.smoke(site, first_deploy);
        problems.extend(o.problems);
        for w in o.warnings {
            warn(site, warnings, w);
        }
    }
    problems
}

/// `wp core update-db` for the site, or for every site of a network. A network is not
/// upgraded with `--network`: wp-cli then launches a subprocess per site, which needs
/// `proc_open`, and the site's `disable_functions` (mounted into the cli container as well)
/// usually forbids it. Listing the sites and upgrading each in its own run needs no subprocess.
fn update_db_all(site: &Site, ops: &dyn DeployOps, problems: &mut Vec<String>) {
    let failed = |what: &str, r: Result<CmdOutput>| -> std::result::Result<CmdOutput, String> {
        match r {
            Ok(o) if o.status == 0 => Ok(o),
            Ok(o) => Err(format!(
                "{what} exited {}: {}",
                o.status,
                String::from_utf8_lossy(&o.stderr).trim()
            )),
            Err(e) => Err(format!("{what}: {e:#}")),
        }
    };
    let urls: Vec<Option<String>> = if site.config.multisite.is_some() {
        step(site, "wp site list");
        let list = crate::lifecycle::wpcli::SITE_LIST.map(String::from);
        match failed("wp site list", ops.wp(site, &list)) {
            Err(p) => return problems.push(p),
            Ok(o) => {
                let urls = crate::lifecycle::wpcli::site_urls(&o.stdout);
                if urls.is_empty() {
                    return problems.push(
                        "wp site list returned no sites; the network's databases were not upgraded"
                            .into(),
                    );
                }
                urls.into_iter().map(Some).collect()
            }
        }
    } else {
        vec![None]
    };
    for url in urls {
        let mut args = vec!["core".to_string(), "update-db".into()];
        let what = match &url {
            Some(u) => {
                args.push(format!("--url={u}"));
                format!("wp core update-db --url={u}")
            }
            None => "wp core update-db".to_string(),
        };
        step(site, &what);
        if let Err(p) = failed(&what, ops.wp(site, &args)) {
            problems.push(p);
        }
    }
}

/// Removes old releases (with their site snapshots) and old DB dumps; returns what was removed.
pub fn gc(base: &Path, g: &GlobalConfig) -> Result<Vec<String>> {
    let mut removed = crate::lifecycle::releases::gc_releases(base, g.keep_releases as usize)?;
    for r in &removed {
        crate::lifecycle::releases::remove_snapshot(base, r)?;
    }
    removed.extend(
        crate::lifecycle::releases::gc_dumps(base, g.keep_db_dumps as usize)?
            .into_iter()
            .map(|p| p.display().to_string()),
    );
    Ok(removed)
}

pub fn deploy(
    host: &dyn Host,
    g: &GlobalConfig,
    site: &Site,
    ops: &dyn DeployOps,
    dry_run: bool,
) -> Result<DeployReport> {
    let _lock = crate::host::lock::SiteLock::acquire(host, &site.name)?;
    deploy_locked(host, g, site, ops, dry_run)
}

/// `deploy` for a caller that already holds the site lock (`update::update_site`).
pub fn deploy_locked(
    host: &dyn Host,
    g: &GlobalConfig,
    site: &Site,
    ops: &dyn DeployOps,
    dry_run: bool,
) -> Result<DeployReport> {
    // Before anything (build, images, TOFU, shared dirs): the include would be useless to
    // workers outside nginx_group. A dry run changes nothing, so it skips the check.
    if !dry_run {
        crate::host::nginx::check_worker_group(host, g)?;
    }
    let base = sys(host, site.base_dir(g));
    let built = ops.build(site)?;
    let mut report = DeployReport {
        site: site.name.clone(),
        release: built.name.clone(),
        dry_run_diff: None,
        problems: Vec::new(),
        rolled_back: None,
        dump: None,
        gc_removed: Vec::new(),
        warnings: Vec::new(),
    };

    if dry_run {
        let diff = (|| -> Result<Vec<String>> {
            let old = match crate::lifecycle::releases::current(&base)? {
                Some(c) => Some(crate::lifecycle::releases::read_manifest(&base, &c)?),
                None => None,
            };
            Ok(diff_manifests(old.as_ref(), &built.manifest))
        })();
        remove_tree(&built.path)?;
        report.dry_run_diff = Some(diff?);
        return Ok(report);
    }

    // Before anything live changes; on failure the unused build is removed again.
    let prepared = (|| -> Result<PathBuf> {
        // build_release leaves new shared/ dirs 0700 root; give them www ownership (idempotent).
        crate::host::layout::prepare_site_dirs(host, g, site)?;
        write_snapshot(host, &base, site, &built.name)?;
        let dump = base
            .join("backups")
            .join(format!("db-{}.sql.gz", built.name));
        step(site, &format!("dumping database to {}", dump.display()));
        ops.dump(site, &dump)
            .with_context(|| format!("database dump before deploying {}", built.name))?;
        Ok(dump)
    })();
    let dump = match prepared {
        Ok(d) => d,
        Err(e) => {
            let _ = remove_tree(&built.path);
            let _ = crate::lifecycle::releases::remove_snapshot(&base, &built.name);
            return Err(e);
        }
    };
    report.dump = Some(dump);

    let prev = crate::lifecycle::releases::current(&base)?;
    let mut warnings = Vec::new();
    // Only a site whose database holds none of its tables may be "not installed yet".
    // Counted before anything touches the database; a failed count is not a fresh install.
    let fresh_install = prev.is_none()
        && match ops.count_prefixed_tables(site) {
            Ok(n) => n == 0,
            Err(e) => {
                warn(
                    site,
                    &mut warnings,
                    format!("counting the tables of {}: {e:#}", site.name),
                );
                false
            }
        };
    let live = match activate(host, g, site, ops, &built.name, &mut warnings) {
        Ok(s) => s,
        Err(e) => {
            // Nothing live changed unless `current` moved (nginx::apply restores its own files).
            let now = crate::lifecycle::releases::current(&base).unwrap_or(None);
            return match prev {
                Some(p) if now.as_deref() != Some(p.as_str()) => {
                    step(site, &format!("activation failed; reactivating {p}"));
                    let outcome = match activate(host, g, site, ops, &p, &mut warnings) {
                        Ok(_) => format!("rolled back to {p}"),
                        Err(re) => format!("rollback to {p} FAILED: {re:#}"),
                    };
                    let now = crate::lifecycle::releases::current(&base)
                        .ok()
                        .flatten()
                        .unwrap_or_else(|| "nothing".into());
                    Err(e.context(format!(
                        "activating {} failed; {outcome}; {now} is current",
                        built.name
                    )))
                }
                _ => Err(e.context(format!("activating {} failed", built.name))),
            };
        }
    };

    report.problems = check(&live, ops, true, fresh_install, &mut warnings);
    if !report.problems.is_empty()
        && let Some(p) = prev
    {
        step(site, &format!("checks failed; rolling back to {p}"));
        let p_problems = match activate(host, g, site, ops, &p, &mut warnings) {
            Ok(psite) => check(&psite, ops, false, false, &mut warnings),
            Err(e) => vec![format!("reactivating {p} failed: {e:#}")],
        };
        // Report what is actually live, not what was attempted.
        let now = crate::lifecycle::releases::current(&base);
        match now {
            Ok(Some(n)) if n == p => report.rolled_back = Some((p, p_problems)),
            other => {
                let now = match other {
                    Ok(Some(n)) => n,
                    Ok(None) => "no release".into(),
                    Err(e) => format!("unknown ({e:#})"),
                };
                report.problems.push(format!(
                    "automatic rollback to {p} failed; {now} is still current: {}",
                    p_problems.join("; ")
                ));
            }
        }
    }

    step(site, "garbage collection");
    match gc(&base, g) {
        Ok(removed) => report.gc_removed = removed,
        Err(e) => warn(
            site,
            &mut warnings,
            format!("garbage collection after deploying {}: {e:#}", built.name),
        ),
    }
    report.warnings = warnings;
    Ok(report)
}

/// Re-activates an existing release (smoke test only). `before_activate`
/// runs under the site lock with the resolved target before anything changes; it returns the
/// dump it restored, if any (the CLI's `--with-db`), so a later failure can say so.
pub fn rollback(
    host: &dyn Host,
    g: &GlobalConfig,
    site: &Site,
    ops: &dyn DeployOps,
    target: Option<&str>,
    before_activate: &dyn Fn(&str) -> Result<Option<PathBuf>>,
) -> Result<RollbackReport> {
    let _lock = crate::host::lock::SiteLock::acquire(host, &site.name)?;
    let base = sys(host, site.base_dir(g));
    let target = match target {
        Some(t) => {
            if !crate::lifecycle::releases::is_release_name(t) {
                bail!("{t:?} is not a release name");
            }
            if !crate::lifecycle::releases::list(&base)?
                .iter()
                .any(|r| r == t)
            {
                bail!("release {t} does not exist for site {}", site.name);
            }
            t.to_string()
        }
        None => {
            let p = crate::lifecycle::releases::previous(&base)?.with_context(|| {
                format!("site {} has no previous release to roll back to", site.name)
            })?;
            // After a rollback `previous` is the newer release that was left: going there is
            // not a rollback, and repeating the command would toggle between the two.
            if let Some(c) = crate::lifecycle::releases::current(&base)?
                && p > c
            {
                return Err(crate::error::UsageError(format!(
                    "the previous release {p} is newer than the current release {c} (the last change was a rollback); name the release to roll back to: iwp rollback {} <release>",
                    site.name
                ))
                .into());
            }
            p
        }
    };
    if crate::lifecycle::releases::current(&base)?.as_deref() == Some(target.as_str()) {
        bail!("release {target} is already current");
    }
    let restored = before_activate(&target)?;
    let mut warnings = Vec::new();
    let tsite = match activate(host, g, site, ops, &target, &mut warnings) {
        Ok(s) => s,
        Err(e) => {
            let e = e.context(format!("activating {target} failed"));
            return Err(match restored {
                Some(d) => e.context(format!("database was restored to {}", d.display())),
                None => e,
            });
        }
    };
    let problems = check(&tsite, ops, false, false, &mut warnings);
    Ok(RollbackReport {
        release: target,
        problems,
        warnings,
    })
}

fn origin(o: &Origin) -> String {
    match o {
        Origin::Wporg { version } => format!("wporg {version}"),
        Origin::Path { path } => format!("path {path}"),
        Origin::Git { url, rev } => format!("git {url}@{}", rev.get(..7).unwrap_or(rev)),
        Origin::Url { url } => format!("url {url}"),
    }
}

fn languages(m: &ReleaseManifest) -> BTreeSet<String> {
    m.languages
        .iter()
        .map(|l| match &l.slug {
            Some(s) => format!("{}[{s}]:{}", l.kind, l.language),
            None => format!("{}:{}", l.kind, l.language),
        })
        .collect()
}

/// Human-readable differences between the current release's manifest and a new one.
pub fn diff_manifests(old: Option<&ReleaseManifest>, new: &ReleaseManifest) -> Vec<String> {
    let Some(old) = old else {
        return vec!["first release".to_string()];
    };
    let mut out = Vec::new();
    for (what, a, b) in [
        ("wordpress", &old.wordpress, &new.wordpress),
        ("php", &old.php, &new.php),
        ("image", &old.image_digest, &new.image_digest),
    ] {
        if a != b {
            out.push(format!("{what}: {a} -> {b}"));
        }
    }
    let key = |m: &ReleaseManifest| -> BTreeMap<String, String> {
        m.packages
            .iter()
            .map(|p| (format!("{}[{}]", p.kind, p.slug), origin(&p.origin)))
            .collect()
    };
    let (a, b) = (key(old), key(new));
    for (k, o) in &a {
        match b.get(k) {
            None => out.push(format!("removed {k} {o}")),
            Some(n) if n != o => out.push(format!("changed {k}: {o} -> {n}")),
            Some(_) => {}
        }
    }
    for (k, n) in &b {
        if !a.contains_key(k) {
            out.push(format!("added {k} {n}"));
        }
    }
    let (la, lb) = (languages(old), languages(new));
    if la != lb {
        let fmt = |s: &BTreeSet<String>| {
            if s.is_empty() {
                "(none)".to_string()
            } else {
                s.iter().cloned().collect::<Vec<_>>().join(", ")
            }
        };
        out.push(format!("languages: {} -> {}", fmt(&la), fmt(&lb)));
    }
    out
}

/// Upper bound on a non-interactive wp-cli run during a deploy (`wp core update-db`).
pub const WP_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// The real deploy effects: build, dump, wp-cli, FastCGI smoke test, readiness and network.
pub struct SystemOps<'a> {
    pub host: &'a dyn Host,
    pub g: &'a GlobalConfig,
    pub fetcher: &'a dyn Fetcher,
    pub images: &'a dyn ImageOps,
}

impl DeployOps for SystemOps<'_> {
    fn build(&self, site: &Site) -> Result<BuiltRelease> {
        // build_release works on plain paths; map them through the host's sysroot.
        let global = GlobalConfig {
            base_root: sys(self.host, &self.g.base_root),
            cache_dir: sys(self.host, &self.g.cache_dir),
            ..self.g.clone()
        };
        let mut site = site.clone();
        if let Some(b) = &site.base {
            site.base = Some(sys(self.host, b));
        }
        crate::build::build_release(
            &BuildEnv {
                global: &global,
                fetcher: self.fetcher,
                images: self.images,
                now: jiff::Timestamp::now(),
                quiet: false,
            },
            &site,
        )
    }
    fn dump(&self, site: &Site, dest: &Path) -> Result<()> {
        crate::host::db::dump(
            self.host,
            self.g,
            &crate::host::db::DbIdent::from_site(site)?,
            dest,
        )
    }
    fn wp(&self, site: &Site, args: &[String]) -> Result<CmdOutput> {
        self.host.run(
            &crate::lifecycle::wpcli::podman_cmd(
                self.g,
                site,
                self.gateway()?,
                crate::lifecycle::wpcli::Entry::Capture(args),
                false,
                Some(WP_TIMEOUT),
            )
            // Podman's own `--timeout` fires first; this is the backstop for a hung client.
            .timeout(WP_TIMEOUT + Duration::from_secs(60)),
        )
    }
    fn smoke(&self, site: &Site, first_deploy: bool) -> SmokeOutcome {
        crate::lifecycle::fcgi::smoke(
            &sys(self.host, format!("/run/iwp/{}/php.sock", site.name)),
            site,
            first_deploy,
        )
    }
    fn wait_ready(&self, site: &Site) -> Result<()> {
        let sock = sys(self.host, format!("/run/iwp/{}/php.sock", site.name));
        let unit = format!("iwp-{}.service", site.name);
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let out = self
                .host
                .run(&Cmd::new("systemctl").args(["is-active", unit.as_str()]))?;
            let state = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if state == "failed" {
                bail!(
                    "{unit} failed to start; see journalctl -u iwp-{}",
                    site.name
                );
            }
            // Ready means FPM accepts connections, not merely that the socket file exists.
            let connect = std::os::unix::net::UnixStream::connect(&sock);
            if state == "active" && connect.is_ok() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                let sock_state = match connect {
                    Ok(_) => "accepting".to_string(),
                    Err(e) => format!("not accepting: {e}"),
                };
                bail!(
                    "{unit} not ready after 60 s (systemctl is-active: {state:?}; socket {} {sock_state}); see journalctl -u iwp-{}",
                    sock.display(),
                    site.name
                );
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    fn gateway(&self) -> Result<std::net::Ipv4Addr> {
        Ok(crate::host::db::podman_network(self.host, &self.g.podman_network)?.gateway)
    }
    fn count_prefixed_tables(&self, site: &Site) -> Result<u64> {
        crate::host::db::count_prefixed_tables(
            self.host,
            self.g,
            &crate::host::db::DbIdent::from_site(site)?,
            site.db_prefix(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_site;
    use crate::host::sys;
    use crate::testutil::RecordingHost;
    use std::cell::{Cell, RefCell};
    use std::os::unix::fs::PermissionsExt;

    struct FakeOps<'a> {
        h: &'a RecordingHost,
        g: GlobalConfig,
        names: RefCell<Vec<&'static str>>,
        smoke_fail_for: RefCell<Vec<String>>, // release names whose smoke fails
        /// Release names whose smoke sees WordPress's redirect to install.php (empty DB).
        install_redirect_for: RefCell<Vec<String>>,
        /// The `first_deploy` flag of every smoke call.
        smoke_first: RefCell<Vec<bool>>,
        dump_fails: bool,
        build_fails: bool,
        built: Cell<usize>,
        /// (release current at the time, args) of every wp call.
        wp_calls: RefCell<Vec<(String, Vec<String>)>>,
        /// stdout of `wp site list --field=url`.
        site_list: RefCell<String>,
        wp_exit_for: RefCell<Vec<String>>,
        wp_err_for: RefCell<Vec<String>>,
        ready_fail_for: RefCell<Vec<String>>,
        /// (release current at the time, domains) of every smoke call.
        smoke_calls: RefCell<Vec<(String, Vec<String>)>>,
        /// Runs at every smoke test (after activation, before GC).
        on_smoke: RefCell<Option<Box<dyn Fn()>>>,
        /// What `count_prefixed_tables` answers (Err: the query fails).
        tables: RefCell<Result<u64, String>>,
    }

    impl FakeOps<'_> {
        fn cur(&self, site: &Site) -> String {
            crate::lifecycle::releases::current(&sys(self.h, site.base_dir(&self.g)))
                .unwrap()
                .unwrap()
        }
    }

    impl DeployOps for FakeOps<'_> {
        fn build(&self, site: &Site) -> Result<BuiltRelease> {
            if self.build_fails {
                anyhow::bail!("build boom");
            }
            let name = self.names.borrow_mut().remove(0);
            let base = sys(self.h, site.base_dir(&self.g));
            let path = base.join("releases").join(name);
            std::fs::create_dir_all(path.join("wp-content")).unwrap();
            // Like build_release: new shared/ dirs are created 0700 and left for deploy to own.
            for w in site.writable_paths() {
                let d = base.join("shared").join(crate::config::shared_rel(w));
                if !d.exists() {
                    std::fs::create_dir_all(&d).unwrap();
                    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
                }
            }
            // Like build_release: the release links its writable dirs into shared/.
            std::os::unix::fs::symlink("../../../shared/uploads", path.join("wp-content/uploads"))
                .unwrap();
            let m = crate::build::tests::sample_manifest(site, name);
            std::fs::write(
                path.join(".iwp-release.json"),
                serde_json::to_vec(&m).unwrap(),
            )
            .unwrap();
            self.built.set(self.built.get() + 1);
            Ok(BuiltRelease {
                name: name.into(),
                path,
                manifest: m,
            })
        }
        fn dump(&self, _s: &Site, dest: &Path) -> Result<()> {
            if self.dump_fails {
                anyhow::bail!("dump boom");
            }
            std::fs::write(dest, b"x").map_err(Into::into)
        }
        fn wp(&self, site: &Site, a: &[String]) -> Result<CmdOutput> {
            let cur = self.cur(site);
            self.wp_calls.borrow_mut().push((cur.clone(), a.to_vec()));
            if self.wp_err_for.borrow().contains(&cur) {
                anyhow::bail!("podman boom");
            }
            let status = i32::from(self.wp_exit_for.borrow().contains(&cur));
            let stdout = if a.first().is_some_and(|x| x == "site") {
                self.site_list.borrow().clone().into_bytes()
            } else {
                vec![]
            };
            Ok(CmdOutput {
                status,
                stdout,
                stderr: b"db error".to_vec(),
            })
        }
        fn smoke(&self, site: &Site, first_deploy: bool) -> SmokeOutcome {
            let cur = self.cur(site);
            self.smoke_calls
                .borrow_mut()
                .push((cur.clone(), site.domains.clone()));
            self.smoke_first.borrow_mut().push(first_deploy);
            if let Some(f) = &*self.on_smoke.borrow() {
                f();
            }
            let mut o = SmokeOutcome::default();
            if self.smoke_fail_for.borrow().contains(&cur) {
                o.problems.push(format!("{cur}: 500"));
            }
            // Same classification as fcgi::smoke_with (tested there).
            if self.install_redirect_for.borrow().contains(&cur) {
                if first_deploy {
                    o.warnings.push("WordPress is not installed yet".into());
                } else {
                    o.problems.push(format!("{cur}: 302 to install.php"));
                }
            }
            o
        }
        fn wait_ready(&self, site: &Site) -> Result<()> {
            let cur = self.cur(site);
            if self.ready_fail_for.borrow().contains(&cur) {
                anyhow::bail!("{cur} not ready");
            }
            Ok(())
        }
        fn gateway(&self) -> Result<std::net::Ipv4Addr> {
            Ok("10.88.0.1".parse().unwrap())
        }
        fn count_prefixed_tables(&self, _site: &Site) -> Result<u64> {
            self.tables.borrow().clone().map_err(anyhow::Error::msg)
        }
    }

    const R1: &str = "20261001-100000-aaaaaaa";
    const R2: &str = "20261001-110000-bbbbbbb";
    const SITE: &str = "name = \"a\"\ndomains = [\"a.example\"]\nid = 1\n[core]\nwordpress = \"7.1.2\"\nphp = \"8.3\"\n";

    fn env() -> (RecordingHost, GlobalConfig, Site) {
        let h = RecordingHost::new(true);
        let g = GlobalConfig {
            base_root: "/srv/www".into(),
            ..GlobalConfig::default()
        };
        let site = parse_site(SITE).unwrap();
        crate::host::layout::prepare_site_dirs(&h, &g, &site).unwrap();
        (h, g, site)
    }
    fn ops<'a>(h: &'a RecordingHost, g: &GlobalConfig, names: &[&'static str]) -> FakeOps<'a> {
        FakeOps {
            h,
            g: g.clone(),
            names: RefCell::new(names.to_vec()),
            smoke_fail_for: RefCell::new(vec![]),
            install_redirect_for: RefCell::new(vec![]),
            smoke_first: RefCell::new(vec![]),
            dump_fails: false,
            build_fails: false,
            built: Cell::new(0),
            wp_calls: RefCell::new(vec![]),
            site_list: RefCell::new("https://a.example/\nhttp://b.a.example/\n".into()),
            wp_exit_for: RefCell::new(vec![]),
            wp_err_for: RefCell::new(vec![]),
            ready_fail_for: RefCell::new(vec![]),
            smoke_calls: RefCell::new(vec![]),
            on_smoke: RefCell::new(None),
            tables: RefCell::new(Ok(0)),
        }
    }
    /// The read-only `check_worker_group` lookups every non-dry-run deploy starts with.
    const WORKER_LOOKUPS: [&str; 5] = [
        "nginx -T",
        "getent group nginx",
        "getent group nginx",
        "id -g nginx",
        "id -G nginx",
    ];
    fn calls(h: &RecordingHost) -> Vec<String> {
        h.calls().iter().map(|c| c.to_string()).collect()
    }
    fn base(h: &RecordingHost, g: &GlobalConfig, site: &Site) -> std::path::PathBuf {
        sys(h, site.base_dir(g))
    }

    fn digest(name: &str) -> String {
        crate::build::tests::sample_manifest(&parse_site(SITE).unwrap(), name).image_digest
    }
    fn quadlet(h: &RecordingHost) -> String {
        std::fs::read_to_string(sys(h, "/etc/containers/systemd/iwp-a.container")).unwrap()
    }
    fn quadlet_image(h: &RecordingHost) -> String {
        quadlet(h)
            .lines()
            .find_map(|l| l.strip_prefix("Image="))
            .unwrap()
            .to_string()
    }

    #[test]
    fn own_current_links_covers_the_live_release_only() {
        let (h, g, site) = env();
        own_current_links(&h, &g, &site, &mut vec![]).unwrap(); // nothing deployed: nothing to do
        let o = ops(&h, &g, &[R1]);
        deploy(&h, &g, &site, &o, false).unwrap();
        let h2 = RecordingHost::sharing(&h);
        own_current_links(&h2, &g, &site, &mut vec![]).unwrap();
        let www = crate::host::identity::Identity::for_site(site.id, g.id_offset).www_uid;
        let link = base(&h, &g, &site)
            .join("releases")
            .join(R1)
            .join("wp-content/uploads");
        assert_eq!(h2.chowns(), vec![(link, www, www)]);
    }

    #[test]
    fn deployed_site_is_the_current_snapshot_with_live_wpcli_mounts() {
        let (h, g, site) = env();
        // Nothing deployed yet: the site file itself.
        assert_eq!(deployed_site(&h, &g, &site, &mut vec![]).unwrap(), site);
        let o = ops(&h, &g, &[R1]);
        deploy(&h, &g, &site, &o, false).unwrap();
        // Edited but not deployed: the running release wins, except for [wpcli].
        let mut edited = site.clone();
        edited.core.wordpress = "7.2".into();
        edited.wpcli.mounts = vec!["/srv/iwp/migration".into()];
        let d = deployed_site(&h, &g, &edited, &mut vec![]).unwrap();
        assert_eq!(d.core.wordpress, "7.1.2");
        assert_eq!(d.wpcli, edited.wpcli);
        // A release without a snapshot falls back to the site file.
        crate::lifecycle::releases::remove_snapshot(&base(&h, &g, &site), R1).unwrap();
        assert_eq!(deployed_site(&h, &g, &edited, &mut vec![]).unwrap(), edited);
    }

    #[test]
    fn unparsable_snapshots_fall_back_to_the_site_file_with_a_warning() {
        // E.g. written by a newer iwp with a field this one does not know (deny_unknown_fields).
        let (h, g, site) = env();
        let o = ops(&h, &g, &[R1, R2]);
        deploy(&h, &g, &site, &o, false).unwrap();
        let snap1 = crate::lifecycle::releases::snapshot_path(&base(&h, &g, &site), R1);
        std::fs::write(&snap1, br#"{"name":"a","from_a_newer_iwp":1}"#).unwrap();
        let path = snap1.display().to_string();
        let named = |w: &[String]| w.iter().any(|x| x.contains(&path));
        // iwp wp / shell / cron
        let mut w = vec![];
        assert_eq!(deployed_site(&h, &g, &site, &mut w).unwrap(), site);
        assert!(named(&w), "{w:?}");
        // deploy activation (the live release's links are owned from its snapshot)
        let r = deploy(&h, &g, &site, &o, false).unwrap();
        assert!(r.problems.is_empty(), "{:?}", r.problems);
        assert!(named(&r.warnings), "{:?}", r.warnings);
        // rollback renders R1 from the site file
        let r = rollback(&h, &g, &site, &o, None, &|_| Ok(None)).unwrap();
        assert_eq!(r.release, R1);
        assert!(r.problems.is_empty(), "{:?}", r.problems);
        assert!(named(&r.warnings), "{:?}", r.warnings);
    }

    #[test]
    fn activation_gives_release_links_to_the_site_uid() {
        // nginx only follows symlinks whose owner also owns the target (disable_symlinks
        // if_not_owner), so the links into shared/ must belong to the site's www UID.
        let (h, g, site) = env();
        let o = ops(&h, &g, &[R1, R2]);
        deploy(&h, &g, &site, &o, false).unwrap();
        let www = crate::host::identity::Identity::for_site(site.id, g.id_offset).www_uid;
        let link = |r: &str| {
            base(&h, &g, &site)
                .join("releases")
                .join(r)
                .join("wp-content/uploads")
        };
        assert!(
            h.chowns().contains(&(link(R1), www, www)),
            "{:?}",
            h.chowns()
        );
        // The include needs the current policy module (lnk_file getattr) before it goes live.
        let c = calls(&h);
        let pos = |p: &str| {
            c.iter()
                .position(|x| x.starts_with(p))
                .unwrap_or_else(|| panic!("{p}: {c:#?}"))
        };
        assert!(pos("semodule -i") < pos("nginx -t"));
        // Re-activating an older release (built before this rule) fixes its links too.
        deploy(&h, &g, &site, &o, false).unwrap();
        let h2 = RecordingHost::sharing(&h);
        let o2 = ops(&h2, &g, &[]);
        rollback(&h2, &g, &site, &o2, None, &|_| Ok(None)).unwrap();
        assert!(
            h2.chowns().contains(&(link(R1), www, www)),
            "{:?}",
            h2.chowns()
        );
    }

    #[test]
    fn deploy_owns_the_live_release_links_before_the_include_changes() {
        // The first deploy with a new iwp installs the stricter include while `current` still
        // points at a release built before: its links must already belong to the site.
        let (h, g, site) = env();
        let o = ops(&h, &g, &[R1]);
        deploy(&h, &g, &site, &o, false).unwrap();
        let h2 = RecordingHost::sharing(&h);
        let o2 = ops(&h2, &g, &[R2]);
        deploy(&h2, &g, &site, &o2, false).unwrap();
        let www = crate::host::identity::Identity::for_site(site.id, g.id_offset).www_uid;
        let link = |r: &str| {
            base(&h, &g, &site)
                .join("releases")
                .join(r)
                .join("wp-content/uploads")
        };
        let c = h2.chowns();
        let pos = |r: &str| {
            c.iter()
                .position(|x| x == &(link(r), www, www))
                .unwrap_or_else(|| panic!("{r}: {c:?}"))
        };
        // Both are owned in this deploy (`activate` does it before `nginx::apply`).
        pos(R1);
        pos(R2);
    }

    #[test]
    fn own_current_links_uses_the_live_release_definition() {
        let (h, g, _) = env();
        let live = parse_site(&format!(
            "{SITE}[[plugin]]\nslug = \"wf\"\nversion = \"1\"\nwritable = [\"wp-content/wflogs\"]\n"
        ))
        .unwrap();
        let o = ops(&h, &g, &[R1]);
        deploy(&h, &g, &live, &o, false).unwrap();
        let rel = base(&h, &g, &live).join("releases").join(R1);
        std::os::unix::fs::symlink("../../../shared/wflogs", rel.join("wp-content/wflogs"))
            .unwrap();
        // The site file no longer declares the writable dir, the live release still links it.
        let edited = parse_site(SITE).unwrap();
        let h2 = RecordingHost::sharing(&h);
        own_current_links(&h2, &g, &edited, &mut vec![]).unwrap();
        assert!(
            h2.chowns()
                .iter()
                .any(|(p, _, _)| p == &rel.join("wp-content/wflogs")),
            "{:?}",
            h2.chowns()
        );
    }

    #[test]
    fn first_deploy_activates_in_order() {
        let (h, g, site) = env();
        let o = ops(&h, &g, &[R1]);
        let r = deploy(&h, &g, &site, &o, false).unwrap();
        assert!(r.problems.is_empty() && r.rolled_back.is_none());
        assert_eq!(r.site, "a");
        assert_eq!(r.release, R1);
        assert!(r.restore_hint().is_none());
        let base = base(&h, &g, &site);
        assert_eq!(
            crate::lifecycle::releases::current(&base)
                .unwrap()
                .as_deref(),
            Some(R1)
        );
        assert!(base.join(format!("backups/db-{R1}.sql.gz")).exists());
        let c = calls(&h);
        let pos = |p: &str| {
            c.iter()
                .position(|x| x.starts_with(p))
                .unwrap_or_else(|| panic!("{p}: {c:#?}"))
        };
        assert!(pos("nginx -t") < pos("systemctl daemon-reload"));
        assert!(pos("systemd-tmpfiles --create") < pos("restorecon -RF /run/iwp/a"));
        assert!(pos("restorecon -RF /run/iwp/a") < pos("systemctl restart iwp-a.service"));
        assert!(pos("systemctl daemon-reload") < pos("systemctl restart iwp-a.service"));
        assert!(
            pos("systemctl restart iwp-a.service") < pos("systemctl enable --now iwp-a-cron.timer")
        );
        assert!(
            c.iter()
                .any(|x| x == "restorecon -RF /srv/www/a/releases/20261001-100000-aaaaaaa"),
            "{c:#?}"
        );
        let quadlet =
            std::fs::read_to_string(sys(&h, "/etc/containers/systemd/iwp-a.container")).unwrap();
        assert!(quadlet.contains("Image=sha256:"), "{quadlet}");
        assert!(
            pos("systemctl enable --now iwp-a-cron.timer")
                < pos("systemctl enable --now iwp-a-verify.timer"),
            "{c:#?}"
        );
    }

    #[test]
    fn deploy_owns_shared_dirs_created_by_the_build() {
        let (h, g, _) = env();
        let site = parse_site(&format!(
            "{SITE}[[plugin]]\nslug = \"wf\"\nversion = \"1.0\"\nwritable = [\"wp-content/wflogs\"]\n"
        ))
        .unwrap();
        let o = ops(&h, &g, &[R1]);
        deploy(&h, &g, &site, &o, false).unwrap();
        let d = base(&h, &g, &site).join("shared/wflogs");
        let mode = std::fs::metadata(&d).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o2755);
        let www = crate::host::identity::Identity::for_site(site.id, g.id_offset).www_uid;
        assert!(h.chowns().iter().any(|(p, u, _)| p == &d && *u == www));
    }

    #[test]
    fn smoke_failure_rolls_back_and_reports_restore_command() {
        let (h, g, site) = env();
        let o = ops(&h, &g, &[R1, R2]);
        deploy(&h, &g, &site, &o, false).unwrap();
        o.smoke_fail_for.borrow_mut().push(R2.into());
        let r = deploy(&h, &g, &site, &o, false).unwrap();
        assert_eq!(r.problems, vec![format!("{R2}: 500")]);
        let (back, p) = r.rolled_back.clone().unwrap();
        assert_eq!(back, R1);
        assert!(p.is_empty());
        let base = base(&h, &g, &site);
        assert_eq!(
            crate::lifecycle::releases::current(&base)
                .unwrap()
                .as_deref(),
            Some(R1)
        );
        assert_eq!(
            crate::lifecycle::releases::previous(&base)
                .unwrap()
                .as_deref(),
            Some(R2)
        );
        assert_eq!(
            r.restore_hint().unwrap(),
            format!(
                "iwp db restore a {} --yes",
                base.join(format!("backups/db-{R2}.sql.gz")).display()
            )
        );
        // The rollback re-runs only the smoke test, never update-db.
        assert_eq!(
            o.wp_calls
                .borrow()
                .iter()
                .map(|(c, _)| c.as_str())
                .collect::<Vec<_>>(),
            vec![R1, R2]
        );
        assert_eq!(
            o.smoke_calls
                .borrow()
                .iter()
                .map(|(c, _)| c.as_str())
                .collect::<Vec<_>>(),
            vec![R1, R2, R1]
        );
        assert_eq!(quadlet_image(&h), digest(R1));
        assert_eq!(
            calls(&h)
                .iter()
                .filter(|c| c.starts_with("systemctl restart iwp-a.service"))
                .count(),
            3
        );
    }

    #[test]
    fn first_deploy_install_redirect_is_a_warning() {
        let (h, g, site) = env();
        let o = ops(&h, &g, &[R1]);
        o.install_redirect_for.borrow_mut().push(R1.into());
        let r = deploy(&h, &g, &site, &o, false).unwrap();
        assert!(r.problems.is_empty(), "{:?}", r.problems);
        assert!(r.rolled_back.is_none());
        assert_eq!(*o.smoke_first.borrow(), vec![true]);
        assert!(
            r.warnings
                .iter()
                .any(|w| w.starts_with("WordPress is not installed yet")),
            "{:?}",
            r.warnings
        );
        let base = base(&h, &g, &site);
        assert_eq!(
            crate::lifecycle::releases::current(&base)
                .unwrap()
                .as_deref(),
            Some(R1)
        );
    }

    #[test]
    fn first_deploy_install_redirect_over_existing_tables_is_a_problem() {
        // An imported database under the wrong name or prefix: WordPress finds
        // no installation although the database is not empty.
        let (h, g, site) = env();
        let o = ops(&h, &g, &[R1]);
        *o.tables.borrow_mut() = Ok(42);
        o.install_redirect_for.borrow_mut().push(R1.into());
        let r = deploy(&h, &g, &site, &o, false).unwrap();
        assert_eq!(r.problems, vec![format!("{R1}: 302 to install.php")]);
        assert_eq!(*o.smoke_first.borrow(), vec![false]);
        assert!(
            !r.warnings.iter().any(|w| w.contains("not installed yet")),
            "{:?}",
            r.warnings
        );
    }

    #[test]
    fn first_deploy_table_count_failure_is_not_a_first_deploy() {
        let (h, g, site) = env();
        let o = ops(&h, &g, &[R1]);
        *o.tables.borrow_mut() = Err("access denied".into());
        o.install_redirect_for.borrow_mut().push(R1.into());
        let r = deploy(&h, &g, &site, &o, false).unwrap();
        assert_eq!(r.problems, vec![format!("{R1}: 302 to install.php")]);
        assert!(
            r.warnings.iter().any(|w| w.contains("access denied")),
            "{:?}",
            r.warnings
        );
    }

    #[test]
    fn later_deploy_install_redirect_is_a_problem_and_rolls_back() {
        let (h, g, site) = env();
        let o = ops(&h, &g, &[R1, R2]);
        deploy(&h, &g, &site, &o, false).unwrap();
        o.install_redirect_for.borrow_mut().push(R2.into());
        let r = deploy(&h, &g, &site, &o, false).unwrap();
        assert_eq!(r.problems, vec![format!("{R2}: 302 to install.php")]);
        assert_eq!(r.rolled_back.as_ref().map(|x| x.0.as_str()), Some(R1));
        // first deploy, second deploy, its automatic rollback: only the first is "first".
        assert_eq!(*o.smoke_first.borrow(), vec![true, false, false]);
        let base = base(&h, &g, &site);
        assert_eq!(
            crate::lifecycle::releases::current(&base)
                .unwrap()
                .as_deref(),
            Some(R1)
        );
    }

    #[test]
    fn rollback_smoke_is_never_a_first_deploy() {
        let (h, g, site) = env();
        let o = ops(&h, &g, &[R1, R2]);
        deploy(&h, &g, &site, &o, false).unwrap();
        deploy(&h, &g, &site, &o, false).unwrap();
        o.install_redirect_for.borrow_mut().push(R1.into());
        let r = rollback(&h, &g, &site, &o, None, &|_| Ok(None)).unwrap();
        assert_eq!(r.problems, vec![format!("{R1}: 302 to install.php")]);
        assert_eq!(o.smoke_first.borrow().last(), Some(&false));
    }

    #[test]
    fn failures_before_swap_touch_nothing_live() {
        let (h, g, site) = env();
        let o = ops(&h, &g, &[R1]);
        deploy(&h, &g, &site, &o, false).unwrap();
        let before = calls(&h).len();
        let mut o2 = ops(&h, &g, &[R2]);
        o2.dump_fails = true;
        assert!(deploy(&h, &g, &site, &o2, false).is_err());
        let b = base(&h, &g, &site);
        assert!(
            !b.join("releases").join(R2).exists(),
            "unused build removed"
        );
        assert!(!b.join(format!("config/releases/{R2}.json")).exists());
        assert_eq!(
            crate::lifecycle::releases::current(&base(&h, &g, &site))
                .unwrap()
                .as_deref(),
            Some(R1)
        );
        assert!(
            !calls(&h)[before..]
                .iter()
                .any(|c| c.starts_with("systemctl restart"))
        );
    }

    #[test]
    fn build_failure_is_an_error() {
        let (h, g, site) = env();
        let mut o = ops(&h, &g, &[R1]);
        o.build_fails = true;
        assert!(deploy(&h, &g, &site, &o, false).is_err());
        assert_eq!(calls(&h), WORKER_LOOKUPS);
    }

    #[test]
    fn nginx_test_failure_aborts_before_swap() {
        let (h0, g, site) = env();
        drop(h0);
        let h = RecordingHost::new(true).respond("nginx -t", 1, "", "emerg");
        crate::host::layout::prepare_site_dirs(&h, &g, &site).unwrap();
        let o = ops(&h, &g, &[R1]);
        assert!(deploy(&h, &g, &site, &o, false).is_err());
        assert_eq!(
            crate::lifecycle::releases::current(&base(&h, &g, &site)).unwrap(),
            None
        );
        assert!(!calls(&h).iter().any(|c| c.starts_with("systemctl restart")));
    }

    #[test]
    fn nginx_failure_on_later_deploy_leaves_live_release_running() {
        let (h, g, site) = env();
        let o = ops(&h, &g, &[R1]);
        deploy(&h, &g, &site, &o, false).unwrap();
        let h2 = RecordingHost::sharing(&h).respond("nginx -t", 1, "", "emerg");
        let o2 = ops(&h2, &g, &[R2]);
        assert!(deploy(&h2, &g, &site, &o2, false).is_err());
        assert_eq!(
            crate::lifecycle::releases::current(&base(&h, &g, &site))
                .unwrap()
                .as_deref(),
            Some(R1)
        );
        assert!(
            !calls(&h2)
                .iter()
                .any(|c| c.starts_with("systemctl restart"))
        );
    }

    #[test]
    fn activation_failure_after_swap_reactivates_previous() {
        let (h, g, site) = env();
        let o = ops(&h, &g, &[R1]);
        deploy(&h, &g, &site, &o, false).unwrap();
        let h2 = RecordingHost::sharing(&h).respond_once("systemctl restart", 1, "", "boom");
        let o2 = ops(&h2, &g, &[R2]);
        let e = deploy(&h2, &g, &site, &o2, false).unwrap_err();
        let m = format!("{e:#}");
        assert!(m.contains("boom") && m.contains(R1), "{m}");
        assert_eq!(
            crate::lifecycle::releases::current(&base(&h, &g, &site))
                .unwrap()
                .as_deref(),
            Some(R1)
        );
        assert_eq!(
            calls(&h2)
                .iter()
                .filter(|c| c.starts_with("systemctl restart iwp-a.service"))
                .count(),
            2
        );
    }

    #[test]
    fn dry_run_diffs_and_removes_the_build() {
        let (h, g, site) = env();
        let o = ops(&h, &g, &[R1, R2]);
        deploy(&h, &g, &site, &o, false).unwrap();
        let n = calls(&h).len();
        let r = deploy(&h, &g, &site, &o, true).unwrap();
        assert!(r.dry_run_diff.is_some());
        assert!(!base(&h, &g, &site).join("releases").join(R2).exists());
        assert_eq!(calls(&h).len(), n, "dry run must not run host commands");
    }

    #[test]
    fn concurrent_deploy_is_refused() {
        let (h, g, site) = env();
        let _held = crate::host::lock::SiteLock::acquire(&h, "a").unwrap();
        let o = ops(&h, &g, &[R1]);
        let e = deploy(&h, &g, &site, &o, false).unwrap_err();
        assert!(format!("{e}").contains("in progress"));
        assert_eq!(o.built.get(), 0);
    }

    #[test]
    fn rollback_to_previous_and_explicit_target() {
        let (h, g, site) = env();
        let o = ops(&h, &g, &[R1, R2]);
        deploy(&h, &g, &site, &o, false).unwrap();
        deploy(&h, &g, &site, &o, false).unwrap();
        let seen = RefCell::new(Vec::new());
        let r = rollback(&h, &g, &site, &o, None, &|t| {
            seen.borrow_mut().push(t.to_string());
            Ok(None)
        })
        .unwrap();
        assert_eq!(r.release, R1);
        assert_eq!(*seen.borrow(), vec![R1.to_string()]);
        let base = base(&h, &g, &site);
        assert_eq!(
            crate::lifecycle::releases::current(&base)
                .unwrap()
                .as_deref(),
            Some(R1)
        );
        assert!(
            rollback(&h, &g, &site, &o, Some(R1), &|_| Ok(None)).is_err(),
            "already current"
        );
        assert!(rollback(&h, &g, &site, &o, Some("../x"), &|_| Ok(None)).is_err());
        assert!(
            rollback(&h, &g, &site, &o, Some("20261001-120000-ccccccc"), &|_| Ok(
                None
            ))
            .is_err(),
            "missing release"
        );
        assert_eq!(quadlet_image(&h), digest(R1));
        let r = rollback(&h, &g, &site, &o, Some(R2), &|_| Ok(None)).unwrap();
        assert!(r.problems.is_empty());
        assert_eq!(quadlet_image(&h), digest(R2));
        // Manual rollbacks never run update-db either: only the two deploys did.
        assert_eq!(o.wp_calls.borrow().len(), 2);
        assert_eq!(o.smoke_calls.borrow().len(), 4);
    }

    #[test]
    fn rollback_without_target_refuses_after_a_rollback() {
        // After R2 -> R1, `previous` is R2: a bare `iwp rollback` would toggle forward again.
        let (h, g, site) = env();
        let o = ops(&h, &g, &[R1, R2]);
        deploy(&h, &g, &site, &o, false).unwrap();
        deploy(&h, &g, &site, &o, false).unwrap();
        rollback(&h, &g, &site, &o, None, &|_| Ok(None)).unwrap();
        let n = calls(&h).len();
        let e = rollback(&h, &g, &site, &o, None, &|_| unreachable!()).unwrap_err();
        assert!(
            e.downcast_ref::<crate::error::UsageError>().is_some(),
            "{e:#}"
        );
        let m = e.to_string();
        assert!(m.contains(R1) && m.contains(R2), "{m}");
        assert!(m.contains("name the release"), "{m}");
        assert_eq!(calls(&h).len(), n);
        // Naming it explicitly still works.
        let r = rollback(&h, &g, &site, &o, Some(R2), &|_| Ok(None)).unwrap();
        assert_eq!(r.release, R2);
    }

    #[test]
    fn rollback_hook_failure_changes_nothing() {
        let (h, g, site) = env();
        let o = ops(&h, &g, &[R1, R2]);
        deploy(&h, &g, &site, &o, false).unwrap();
        deploy(&h, &g, &site, &o, false).unwrap();
        let n = calls(&h).len();
        assert!(rollback(&h, &g, &site, &o, None, &|_| anyhow::bail!("no")).is_err());
        assert_eq!(calls(&h).len(), n);
        assert_eq!(
            crate::lifecycle::releases::current(&base(&h, &g, &site))
                .unwrap()
                .as_deref(),
            Some(R2)
        );
    }

    #[test]
    fn diff_lists_changes() {
        let site = parse_site(SITE).unwrap();
        let old = crate::build::tests::sample_manifest(&site, R1);
        let mut new = old.clone();
        new.wordpress = "7.1.3".into();
        let d = diff_manifests(Some(&old), &new);
        assert!(d.iter().any(|l| l == "wordpress: 7.1.2 -> 7.1.3"), "{d:?}");
        assert!(
            diff_manifests(None, &new)
                .iter()
                .any(|l| l.contains("first release"))
        );
    }

    #[test]
    fn diff_lists_package_and_language_changes() {
        use crate::build::sources::Origin;
        use crate::build::{LanguageRecord, PackageRecord};
        let site = parse_site(SITE).unwrap();
        let pkg = |slug: &str, origin: Origin| PackageRecord {
            kind: "plugin".into(),
            slug: slug.into(),
            mu: false,
            origin,
            sha256: String::new(),
            files_verified: 0,
            unlisted_files: vec![],
            tree_sha256: String::new(),
        };
        let mut old = crate::build::tests::sample_manifest(&site, R1);
        old.packages = vec![
            pkg(
                "a",
                Origin::Wporg {
                    version: "1.0".into(),
                },
            ),
            pkg(
                "b",
                Origin::Path {
                    path: "/src/b".into(),
                },
            ),
        ];
        let mut new = old.clone();
        new.packages = vec![
            pkg(
                "a",
                Origin::Wporg {
                    version: "1.1".into(),
                },
            ),
            pkg(
                "c",
                Origin::Git {
                    url: "https://git.example/c".into(),
                    rev: "0123456789abcdef".into(),
                },
            ),
        ];
        new.languages = vec![LanguageRecord {
            kind: "core".into(),
            slug: None,
            language: "hr".into(),
            version: "7.1.2".into(),
            url: String::new(),
            sha256: String::new(),
            tree_sha256: String::new(),
        }];
        let d = diff_manifests(Some(&old), &new);
        for want in [
            "changed plugin[a]: wporg 1.0 -> wporg 1.1",
            "removed plugin[b] path /src/b",
            "added plugin[c] git https://git.example/c@0123456",
            "languages: (none) -> core:hr",
        ] {
            assert!(d.iter().any(|l| l == want), "{want}: {d:?}");
        }
        assert!(!d.iter().any(|l| l.starts_with("wordpress")), "{d:?}");
    }

    #[test]
    fn update_db_failure_or_error_rolls_back() {
        for exit in [true, false] {
            let (h, g, site) = env();
            let o = ops(&h, &g, &[R1, R2]);
            deploy(&h, &g, &site, &o, false).unwrap();
            if exit {
                o.wp_exit_for.borrow_mut().push(R2.into());
            } else {
                o.wp_err_for.borrow_mut().push(R2.into());
            }
            let r = deploy(&h, &g, &site, &o, false).unwrap();
            let want = if exit {
                "wp core update-db exited 1: db error"
            } else {
                "wp core update-db: podman boom"
            };
            assert_eq!(r.problems, vec![want.to_string()]);
            assert_eq!(r.rolled_back, Some((R1.to_string(), vec![])));
            // No smoke test of the broken release; the rollback target is smoke-tested.
            assert_eq!(
                o.smoke_calls
                    .borrow()
                    .iter()
                    .map(|(c, _)| c.as_str())
                    .collect::<Vec<_>>(),
                vec![R1, R1]
            );
        }
    }

    fn multisite() -> Site {
        parse_site(&format!(
            "{SITE}[config]\nmultisite = {{ subdomain = true, domain = \"a.example\" }}\n"
        ))
        .unwrap()
    }

    #[test]
    fn multisite_update_db_runs_once_per_site_without_network() {
        // `--network` makes wp-cli launch a subprocess per site, which needs proc_open; the
        // site's disable_functions (mounted into the cli container too) forbids it.
        let (h, g, _) = env();
        let o = ops(&h, &g, &[R1]);
        let r = deploy(&h, &g, &multisite(), &o, false).unwrap();
        assert!(r.problems.is_empty(), "{:?}", r.problems);
        let calls: Vec<String> = o.wp_calls.borrow().iter().map(|c| c.1.join(" ")).collect();
        assert_eq!(
            calls,
            [
                "site list --field=url",
                "core update-db --url=https://a.example/",
                "core update-db --url=http://b.a.example/"
            ]
        );
    }

    #[test]
    fn multisite_without_a_site_list_is_a_problem() {
        let (h, g, _) = env();
        let o = ops(&h, &g, &[R1]);
        *o.site_list.borrow_mut() = String::new();
        let r = deploy(&h, &g, &multisite(), &o, false).unwrap();
        assert!(
            r.problems
                .iter()
                .any(|p| p.contains("wp site list") && p.contains("no sites")),
            "{:?}",
            r.problems
        );
        assert_eq!(o.wp_calls.borrow().len(), 1);
    }

    #[test]
    fn prepare_failure_removes_the_build() {
        let (h, g, site) = env();
        let b = base(&h, &g, &site);
        std::fs::remove_dir(b.join("shared/uploads")).unwrap();
        let elsewhere = crate::testutil::tmp();
        std::os::unix::fs::symlink(elsewhere.path(), b.join("shared/uploads")).unwrap();
        let o = ops(&h, &g, &[R1]);
        assert!(deploy(&h, &g, &site, &o, false).is_err());
        assert!(!b.join("releases").join(R1).exists());
        assert_eq!(crate::lifecycle::releases::current(&b).unwrap(), None);
        // Only the read-only nginx worker lookups (deploy's first step) ran.
        assert_eq!(calls(&h), WORKER_LOOKUPS);
    }

    #[test]
    fn nginx_workers_outside_nginx_group_fail_the_deploy_before_anything_live() {
        let (h, g, site) = env();
        let h = h
            .respond("nginx -T", 0, "user nginx www-users;\n", "")
            .respond("getent group www-users", 0, "www-users:x:2000:\n", "");
        let b = base(&h, &g, &site);
        let o = ops(&h, &g, &[R1]);
        let e = format!("{:#}", deploy(&h, &g, &site, &o, false).unwrap_err());
        assert!(e.contains("not in group nginx"), "{e}");
        assert_eq!(o.built.get(), 0, "no build before the check");
        assert!(!b.join("releases").join(R1).exists());
        assert_eq!(crate::lifecycle::releases::current(&b).unwrap(), None);
        assert!(o.wp_calls.borrow().is_empty());
        assert!(
            calls(&h).iter().all(|c| c.starts_with("nginx -T")
                || c.starts_with("getent ")
                || c.starts_with("id ")),
            "{:?}",
            calls(&h)
        );
    }

    #[test]
    fn rollback_uses_the_release_snapshot_not_the_new_site_file() {
        let (h, g, site) = env();
        let o = ops(&h, &g, &[R1, R2]);
        deploy(&h, &g, &site, &o, false).unwrap();
        let b = base(&h, &g, &site);
        let snap = b.join(format!("config/releases/{R1}.json"));
        assert_eq!(
            std::fs::metadata(&snap).unwrap().permissions().mode() & 0o7777,
            0o644
        );
        assert_eq!(
            std::fs::metadata(snap.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o755
        );
        let site2 = parse_site(&format!(
            "{}[[plugin]]\nslug = \"redis-cache\"\nversion = \"2.6.0\"\n[dropins.\"object-cache.php\"]\nplugin = \"redis-cache\"\nfile = \"includes/object-cache.php\"\n",
            SITE.replace("[\"a.example\"]", "[\"a.example\", \"b.example\"]")
        ))
        .unwrap();
        o.smoke_fail_for.borrow_mut().push(R2.into());
        let r = deploy(&h, &g, &site2, &o, false).unwrap();
        assert_eq!(r.rolled_back, Some((R1.to_string(), vec![])));
        let q = quadlet(&h);
        assert!(!q.contains("object-cache.php"), "{q}");
        assert_eq!(quadlet_image(&h), digest(R1));
        let smokes = o.smoke_calls.borrow();
        assert_eq!(smokes[1], (R2.to_string(), site2.domains.clone()));
        assert_eq!(smokes[2], (R1.to_string(), vec!["a.example".to_string()]));
    }

    #[test]
    fn failed_reactivation_before_swap_is_reported_truthfully() {
        let (h, g, site) = env();
        let o = ops(&h, &g, &[R1, R2]);
        deploy(&h, &g, &site, &o, false).unwrap();
        let b = base(&h, &g, &site);
        // Make R1 unusable: activating it fails before `current` moves.
        let rel = b.join("releases").join(R1);
        std::fs::remove_file(rel.join(".iwp-release.json")).unwrap();
        o.smoke_fail_for.borrow_mut().push(R2.into());
        let r = deploy(&h, &g, &site, &o, false).unwrap();
        assert_eq!(r.rolled_back, None);
        assert_eq!(r.problems.len(), 2, "{:?}", r.problems);
        assert!(
            r.problems[1].contains(&format!("automatic rollback to {R1} failed"))
                && r.problems[1].contains(&format!("{R2} is still current")),
            "{:?}",
            r.problems
        );
        assert_eq!(r.restore_hint(), None);
        assert_eq!(
            crate::lifecycle::releases::current(&b).unwrap().as_deref(),
            Some(R2)
        );
    }

    #[test]
    fn failed_reactivation_after_swap_is_reported_as_rolled_back_with_problems() {
        let (h, g, site) = env();
        let o = ops(&h, &g, &[R1, R2]);
        deploy(&h, &g, &site, &o, false).unwrap();
        o.smoke_fail_for.borrow_mut().push(R2.into());
        o.ready_fail_for.borrow_mut().push(R1.into());
        let r = deploy(&h, &g, &site, &o, false).unwrap();
        let (back, p) = r.rolled_back.clone().unwrap();
        assert_eq!(back, R1);
        assert!(p.len() == 1 && p[0].contains("not ready"), "{p:?}");
        assert!(r.restore_hint().is_some());
    }

    #[test]
    fn gc_runs_after_deploy_and_reports_what_it_removed() {
        let (h, g, site) = env();
        let g = GlobalConfig {
            keep_releases: 1,
            keep_db_dumps: 1,
            ..g
        };
        const R3: &str = "20261001-120000-ccccccc";
        let o = ops(&h, &g, &[R1, R2, R3]);
        deploy(&h, &g, &site, &o, false).unwrap();
        let r2 = deploy(&h, &g, &site, &o, false).unwrap();
        let b = base(&h, &g, &site);
        assert_eq!(
            r2.gc_removed,
            vec![
                b.join(format!("backups/db-{R1}.sql.gz"))
                    .display()
                    .to_string()
            ]
        );
        let r3 = deploy(&h, &g, &site, &o, false).unwrap();
        assert_eq!(
            r3.gc_removed,
            vec![
                R1.to_string(),
                b.join(format!("backups/db-{R2}.sql.gz"))
                    .display()
                    .to_string()
            ]
        );
        assert!(!b.join(format!("config/releases/{R1}.json")).exists());
        assert!(b.join(format!("config/releases/{R2}.json")).exists());
        assert!(r3.warnings.is_empty());
    }

    #[test]
    fn gc_failure_is_a_warning_not_an_error() {
        let (h, g, site) = env();
        let o = ops(&h, &g, &[R1, R2]);
        deploy(&h, &g, &site, &o, false).unwrap();
        // Removal fails once backups/ is read-only (root ignores modes, so skip as root).
        if crate::testutil::skip_if_root() {
            return;
        }
        let backups = base(&h, &g, &site).join("backups");
        let g2 = GlobalConfig {
            keep_db_dumps: 0,
            ..g.clone()
        };
        let b2 = backups.clone();
        *o.on_smoke.borrow_mut() = Some(Box::new(move || {
            std::fs::set_permissions(&b2, std::fs::Permissions::from_mode(0o500)).unwrap();
        }));
        o.smoke_fail_for.borrow_mut().push(R2.into());
        let r = deploy(&h, &g2, &site, &o, false);
        std::fs::set_permissions(&backups, std::fs::Permissions::from_mode(0o700)).unwrap();
        let r = r.unwrap();
        assert!(r.rolled_back.is_some());
        assert!(r.restore_hint().is_some());
        assert!(
            r.warnings.iter().any(|w| w.contains("garbage collection")),
            "{:?}",
            r.warnings
        );
    }

    #[test]
    fn cache_dirs_are_emptied_and_failures_are_warnings() {
        let (h, g, _) = env();
        let site = parse_site(&format!(
            "{SITE}[[plugin]]\nslug = \"wf\"\nversion = \"1.0\"\nwritable = [\"wp-content/cache\"]\ncache = [\"wp-content/cache/pages\"]\n"
        ))
        .unwrap();
        crate::host::layout::prepare_site_dirs(&h, &g, &site).unwrap();
        let b = base(&h, &g, &site);
        let pages = b.join("shared/cache/pages");
        std::fs::create_dir_all(pages.join("x")).unwrap();
        std::fs::write(pages.join("x/p.html"), b"x").unwrap();
        let o = ops(&h, &g, &[R1, R2]);
        let r = deploy(&h, &g, &site, &o, false).unwrap();
        assert!(pages.is_dir() && std::fs::read_dir(&pages).unwrap().count() == 0);
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        // A symlinked cache dir is refused (target untouched) and only warned about.
        std::fs::remove_dir(&pages).unwrap();
        let target = crate::testutil::tmp();
        std::fs::write(target.path().join("keep"), b"k").unwrap();
        std::os::unix::fs::symlink(target.path(), &pages).unwrap();
        let r = deploy(&h, &g, &site, &o, false).unwrap();
        assert!(r.problems.is_empty() && r.rolled_back.is_none());
        assert!(target.path().join("keep").exists());
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains("refusing to follow symlink")),
            "{:?}",
            r.warnings
        );
    }

    #[test]
    fn rollback_activation_failure_mentions_restored_database() {
        let (h, g, site) = env();
        let o = ops(&h, &g, &[R1, R2]);
        deploy(&h, &g, &site, &o, false).unwrap();
        deploy(&h, &g, &site, &o, false).unwrap();
        let b = base(&h, &g, &site);
        std::fs::remove_file(b.join("releases").join(R1).join(".iwp-release.json")).unwrap();
        let dump = b.join(format!("backups/db-{R1}.sql.gz"));
        let e = rollback(&h, &g, &site, &o, None, &|_| Ok(Some(dump.clone()))).unwrap_err();
        let m = format!("{e:#}");
        assert!(
            m.contains(&format!("database was restored to {}", dump.display())),
            "{m}"
        );
    }

    struct NoImages;
    impl crate::build::ImageOps for NoImages {
        fn ensure(&self, _: &str, _: &str) -> Result<String> {
            anyhow::bail!("unused")
        }
        fn export_webroot(&self, _: &str, _: &Path) -> Result<()> {
            anyhow::bail!("unused")
        }
    }

    #[test]
    fn system_ops_bound_update_db_and_count_tables_over_the_admin_socket() {
        let g = GlobalConfig::default();
        let site = parse_site(SITE).unwrap();
        let f = crate::testutil::FakeFetcher::new();
        let h = RecordingHost::new(true)
            .respond("podman network inspect", 0, "10.88.0.0/16 10.88.0.1\n", "")
            .respond("mariadb", 0, "0\n", "");
        let o = SystemOps {
            host: &h,
            g: &g,
            fetcher: &f,
            images: &NoImages,
        };
        o.wp(&site, &["core".into(), "update-db".into()]).unwrap();
        let wp = h
            .calls()
            .into_iter()
            .find(|c| c.to_string().starts_with("podman run"))
            .unwrap();
        // Podman's own limit fires first; the host-side kill is the backstop.
        assert_eq!(wp.timeout, Some(WP_TIMEOUT + Duration::from_secs(60)));
        assert!(wp.args.contains(&"--timeout=1800".to_string()), "{wp}");
        assert_eq!(WP_TIMEOUT, Duration::from_secs(30 * 60));
        assert_eq!(o.count_prefixed_tables(&site).unwrap(), 0);
        let q = h.calls().last().unwrap().clone();
        assert!(
            String::from_utf8(q.stdin.unwrap())
                .unwrap()
                .contains("table_schema = 'wp_a' AND table_name LIKE 'wp!_%' ESCAPE '!'")
        );
    }

    #[test]
    fn wait_ready_needs_a_connectable_socket_and_stops_on_failed() {
        let g = GlobalConfig::default();
        let site = parse_site(SITE).unwrap();
        let f = crate::testutil::FakeFetcher::new();
        let h = RecordingHost::new(true).respond("systemctl is-active", 3, "failed\n", "");
        let o = SystemOps {
            host: &h,
            g: &g,
            fetcher: &f,
            images: &NoImages,
        };
        let t = std::time::Instant::now();
        let e = o.wait_ready(&site).unwrap_err();
        assert!(format!("{e:#}").contains("failed to start"), "{e:#}");
        assert!(t.elapsed() < Duration::from_secs(5));

        let h = RecordingHost::new(true).respond("systemctl is-active", 0, "active\n", "");
        let sock = sys(&h, "/run/iwp/a/php.sock");
        std::fs::create_dir_all(sock.parent().unwrap()).unwrap();
        let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let o = SystemOps {
            host: &h,
            g: &g,
            fetcher: &f,
            images: &NoImages,
        };
        o.wait_ready(&site).unwrap();
    }
}
