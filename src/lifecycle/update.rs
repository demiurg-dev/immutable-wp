//! `iwp update`: move a site to newer wordpress.org versions and deploy them, unattended-safe.

use std::cmp::Ordering;
use std::path::Path;

use anyhow::{Context, Result};

use crate::config::edit::{PackageKind, SiteDocument};
use crate::config::{CorePolicy, GlobalConfig, LoadedSite, PackagePolicy, Site};
use crate::fetch::wporg::WpOrg;
use crate::host::{Host, sys};
use crate::lifecycle::deploy::DeployReport;
use crate::lifecycle::outdated::version_cmp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// "core", "plugin" or "theme".
    pub kind: String,
    pub slug: String,
    pub from: String,
    pub to: String,
}

impl std::fmt::Display for Change {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {} -> {}",
            self.kind, self.slug, self.from, self.to
        )
    }
}

#[derive(Debug, Default)]
pub struct Plan {
    pub changes: Vec<Change>,
    /// Updates deliberately not taken (e.g. they need a newer PHP).
    pub skipped: Vec<String>,
    /// Lookups that failed; the site may be missing updates.
    pub errors: Vec<String>,
    /// What each `skipped` entry holds back: ("plugin <slug>" or "core wordpress", version).
    pub blocked: Vec<(String, String)>,
    /// Skipped updates and unreviewed `source` packages past their deadline ([update]
    /// overdue_days, source_review_days); they fail the run. Filled by `update_site`.
    pub overdue: Vec<String>,
}

#[derive(Debug)]
pub enum Outcome {
    UpToDate,
    /// Nothing was touched. `benign`: an expected state (e.g. never deployed), not something
    /// an operator has to fix; `iwp update --all` exits 0 for it.
    Skipped {
        why: String,
        benign: bool,
    },
    DryRun {
        changes: Vec<Change>,
        image_changed: bool,
    },
    Updated {
        changes: Vec<Change>,
        image_changed: bool,
        release: String,
        /// Non-fatal deploy warnings (cache emptying, GC).
        warnings: Vec<String>,
    },
    /// The deploy failed. `previous_live`: the release from before the update is live (the
    /// site file was not changed); otherwise the new release stayed live and the site file
    /// was updated to describe it.
    Failed {
        changes: Vec<Change>,
        problems: Vec<String>,
        previous_live: bool,
    },
}

impl Outcome {
    fn skipped(why: String) -> Self {
        Outcome::Skipped { why, benign: false }
    }
}

/// The effects `update_site` needs besides files, so tests can script them.
pub struct Effects<'a> {
    /// ID of the site's fpm image tag as it is now (`None`: no such image yet).
    pub image_id: &'a dyn Fn(&Site) -> Result<Option<String>>,
    pub deploy: &'a dyn Fn(&Site) -> Result<DeployReport>,
}

fn branch(v: &str) -> String {
    v.split('.').take(2).collect::<Vec<_>>().join(".")
}

/// The core version `policy` allows moving to from `current`, if it is newer.
pub fn pick_core(current: &str, offers: &[String], policy: CorePolicy) -> Option<String> {
    let newest = |it: &mut dyn Iterator<Item = &String>| {
        it.max_by(|a, b| version_cmp(a, b))
            .filter(|v| version_cmp(v, current) == Ordering::Greater)
            .cloned()
    };
    match policy {
        CorePolicy::None => None,
        CorePolicy::Major => newest(&mut offers.iter()),
        CorePolicy::Minor => {
            let b = branch(current);
            newest(&mut offers.iter().filter(|v| branch(v) == b))
        }
    }
}

/// Whether `from` -> `to` changes the first version number. A version that is not plain
/// dotted numbers (e.g. "2.0-beta1") counts as a major change: it cannot be judged.
pub fn is_major(from: &str, to: &str) -> bool {
    fn first(v: &str) -> Option<u64> {
        let parts: Vec<&str> = v.split('.').collect();
        if parts
            .iter()
            .any(|p| p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()))
        {
            return None;
        }
        parts[0].parse().ok()
    }
    match (first(from), first(to)) {
        (Some(a), Some(b)) => a != b,
        _ => true,
    }
}

/// What wordpress.org has that `site` could move to. Never fails as a whole.
pub fn plan(w: &WpOrg, site: &Site) -> Plan {
    let mut p = Plan::default();
    match w.core_offers(&site.core.wordpress) {
        Ok(offers) => {
            let now = &site.core.wordpress;
            if let Some(to) = pick_core(now, &offers, site.update.core) {
                p.changes.push(Change {
                    kind: "core".into(),
                    slug: "wordpress".into(),
                    from: now.clone(),
                    to,
                });
            }
            if site.update.core == CorePolicy::Minor
                && let Some(to) = pick_core(now, &offers, CorePolicy::Major)
                && branch(&to) != branch(now)
            {
                p.skipped.push(format!(
                    "core wordpress {now} -> {to}: a new branch; [update] core = \"minor\" takes only patch releases (set [core] wordpress and run `iwp deploy`, or set core = \"major\")"
                ));
                p.blocked.push(("core wordpress".into(), to));
            }
        }
        Err(e) if site.update.core != CorePolicy::None => p.errors.push(format!("core: {e:#}")),
        Err(_) => {}
    }
    // The core version packages will run on once this plan is deployed.
    let core = p
        .changes
        .first()
        .map_or_else(|| site.core.wordpress.clone(), |c| c.to.clone());
    let packages: [(PackageKind, &[crate::config::Package]); 2] = match site.update.plugins {
        PackagePolicy::None => [(PackageKind::Plugin, &[]), (PackageKind::Theme, &[])],
        _ => [
            (PackageKind::Plugin, &site.plugins),
            (PackageKind::Theme, &site.themes),
        ],
    };
    for (kind, list) in packages {
        for pkg in list.iter().filter(|pkg| !pkg.hold) {
            let Some(from) = &pkg.version else { continue };
            let what = format!("{} {}", kind.table(), pkg.slug);
            let info = match kind {
                PackageKind::Plugin => w.plugin_info(&pkg.slug),
                PackageKind::Theme => w.theme_info(&pkg.slug),
            };
            match info {
                Err(e) => p.errors.push(format!("{what}: {e:#}")),
                Ok(i) if version_cmp(&i.version, from) != Ordering::Greater => {}
                Ok(i) => {
                    let newer = |req: &Option<String>, have: &str| {
                        req.as_deref()
                            .filter(|r| version_cmp(r, have) == Ordering::Greater)
                            .map(str::to_string)
                    };
                    let before = p.skipped.len();
                    if site.update.plugins == PackagePolicy::Minor && is_major(from, &i.version) {
                        p.skipped.push(format!(
                            "{what} {from} -> {}: a major update; [update] plugins = \"minor\" takes only updates with the same first version number (update it with `iwp plugin`/`iwp theme` and `iwp deploy`, or set plugins = \"major\")",
                            i.version
                        ));
                    } else if let Some(req) = newer(&i.requires_php, &site.core.php) {
                        p.skipped.push(format!(
                            "{what} {from} -> {}: needs PHP {req}, the site runs {}",
                            i.version, site.core.php
                        ));
                    } else if let Some(req) = newer(&i.requires, &core) {
                        p.skipped.push(format!(
                            "{what} {from} -> {}: needs WordPress {req}, the site will run {core}",
                            i.version
                        ));
                    } else {
                        p.changes.push(Change {
                            kind: kind.table().into(),
                            slug: pkg.slug.clone(),
                            from: from.clone(),
                            to: i.version.clone(),
                        });
                    }
                    if p.skipped.len() > before {
                        p.blocked.push((what, i.version));
                    }
                }
            }
        }
    }
    p
}

/// `text` (a site file) with `changes` applied, comments and layout kept.
pub fn apply(text: &str, changes: &[Change]) -> Result<String> {
    let mut doc = SiteDocument::parse(text)?;
    for c in changes {
        match c.kind.as_str() {
            "core" => doc.set_core_wordpress(&c.to)?,
            "plugin" => doc.set_version(PackageKind::Plugin, &c.slug, &c.to)?,
            "theme" => doc.set_version(PackageKind::Theme, &c.slug, &c.to)?,
            other => anyhow::bail!("unknown change kind {other:?}"),
        }
    }
    Ok(doc.render())
}

/// Whether two site definitions deploy the same thing ([wpcli], [update], `hold` and
/// [verify] admins are operator settings, not release content).
pub fn same_deployable(a: &Site, b: &Site) -> bool {
    let norm = |s: &Site| {
        let mut s = s.clone();
        s.wpcli = Default::default();
        s.update = Default::default();
        s.verify.admins = None;
        for p in s.plugins.iter_mut().chain(s.themes.iter_mut()) {
            p.hold = false;
        }
        s
    };
    norm(a) == norm(b)
}

/// Updates one site: deploys it with newer versions (or as-is when only the image changed) and
/// then bumps the versions in its site file. A site whose file has edits nobody deployed is
/// left alone, so an unattended run never activates them. The file is only written once the
/// new versions are live.
pub fn update_site(
    host: &dyn Host,
    g: &GlobalConfig,
    loaded: &LoadedSite,
    w: &WpOrg,
    fx: &Effects,
    dry_run: bool,
    retry_failed: bool,
) -> Result<(Outcome, Plan)> {
    let site = &loaded.site;
    let base = sys(host, site.base_dir(g));
    // Held from the snapshot check until the site file is written, so a concurrent `iwp deploy`
    // cannot interleave with the update. `fx.deploy` must therefore not take the lock itself
    // (`deploy::deploy_locked`).
    let _lock = crate::host::lock::SiteLock::acquire(host, &site.name)?;
    let Some(live) = crate::lifecycle::releases::current(&base)? else {
        return Ok((
            Outcome::Skipped {
                why: "not deployed yet; run `iwp deploy` first".into(),
                benign: true,
            },
            Plan::default(),
        ));
    };
    let mut unreadable = Vec::new();
    match crate::lifecycle::deploy::read_snapshot(&base, site, &live, &mut unreadable)? {
        Some(snap) if same_deployable(&snap, site) => {}
        Some(_) => {
            return Ok((
                Outcome::skipped(format!(
                    "the site file has changes that are not deployed (live: {live}); run `iwp deploy` first"
                )),
                Plan::default(),
            ));
        }
        None => {
            let why = unreadable
                .first()
                .cloned()
                .unwrap_or_else(|| format!("release {live} has no site snapshot"));
            return Ok((
                Outcome::skipped(format!("{why}; run `iwp deploy` once")),
                Plan::default(),
            ));
        }
    }
    let mut plan = plan(w, site);
    plan.overdue = track(host, g, site, &plan, now_secs(), !dry_run)?;
    let changes = std::mem::take(&mut plan.changes);
    let live_image = crate::lifecycle::releases::read_manifest(&base, &live)?.image_digest;
    let image_changed = (fx.image_id)(site)?.is_some_and(|id| id != live_image);
    if changes.is_empty() && !image_changed {
        return Ok((Outcome::UpToDate, plan));
    }
    if dry_run {
        return Ok((
            Outcome::DryRun {
                changes,
                image_changed,
            },
            plan,
        ));
    }
    // An update that failed is not deployed (and rolled back) again every night.
    let signature = signature(&changes, image_changed);
    if !retry_failed && read_marker(host, g, site)?.is_some_and(|m| m == signature) {
        let what: Vec<String> = signature.lines().map(str::to_string).collect();
        return Ok((
            Outcome::skipped(format!(
                "the same update failed before ({}); fix the cause, or retry with `iwp update {}`",
                what.join(", "),
                site.name
            )),
            plan,
        ));
    }
    // The edited site is deployed from memory; the file is only rewritten once its versions
    // are live, so a run that fails or is killed never leaves it describing undeployed code.
    let new_site = if changes.is_empty() {
        site.clone()
    } else {
        let original = std::fs::read_to_string(&loaded.path)
            .with_context(|| format!("reading {}", loaded.path.display()))?;
        checked_site(&loaded.path, &apply(&original, &changes)?)?
    };
    let problems = match (fx.deploy)(&new_site) {
        Ok(r) if r.problems.is_empty() => {
            write_changes(host, loaded, &changes).with_context(|| {
                format!("{} is live, but its site file was not updated", r.release)
            })?;
            clear_marker(host, g, site)?;
            return Ok((
                Outcome::Updated {
                    changes,
                    image_changed,
                    release: r.release,
                    warnings: r.warnings,
                },
                plan,
            ));
        }
        Ok(r) => {
            let mut p = r.problems.clone();
            if let Some((rel, more)) = &r.rolled_back {
                p.push(format!("rolled back to {rel}"));
                p.extend(more.iter().cloned());
            }
            if let Some(hint) = r.restore_hint() {
                p.push(format!("restore the database with: {hint}"));
            }
            p
        }
        Err(e) => vec![format!("{e:#}")],
    };
    // The site file must describe what is live: when the new release stayed, it gets the edit.
    let previous_live =
        crate::lifecycle::releases::current(&base)?.as_deref() == Some(live.as_str());
    if !previous_live {
        write_changes(host, loaded, &changes)?;
    }
    write_marker(host, g, site, &signature)?;
    Ok((
        Outcome::Failed {
            changes,
            problems,
            previous_live,
        },
        plan,
    ))
}

/// `text` parsed and validated as the site file at `path`.
fn checked_site(path: &Path, text: &str) -> Result<Site> {
    let s = crate::config::parse_site(text).context("the updated site file does not parse")?;
    let stem = path.file_stem().and_then(|s| s.to_str());
    let issues = crate::config::validate_site(&s, stem);
    if !issues.is_empty() {
        let list: Vec<String> = issues.iter().map(ToString::to_string).collect();
        anyhow::bail!(
            "the updated site file would be invalid:\n  {}",
            list.join("\n  ")
        );
    }
    Ok(s)
}

/// Applies `changes` to the site file as it is now (keeping edits made meanwhile).
fn write_changes(host: &dyn Host, loaded: &LoadedSite, changes: &[Change]) -> Result<()> {
    if changes.is_empty() {
        return Ok(());
    }
    let now = std::fs::read_to_string(&loaded.path)
        .with_context(|| format!("reading {}", loaded.path.display()))?;
    let text = apply(&now, changes)?;
    checked_site(&loaded.path, &text)?;
    crate::host::fsx::write_atomic(
        host,
        &loaded.path,
        text.as_bytes(),
        &crate::host::fsx::FileSpec::default(),
    )
    .with_context(|| format!("writing {}", loaded.path.display()))?;
    Ok(())
}

/// `<base>/config/update-failed` (under the host's sysroot): what the last failed update tried.
pub fn failed_marker(host: &dyn Host, g: &GlobalConfig, site: &Site) -> std::path::PathBuf {
    sys(host, site.base_dir(g).join("config").join("update-failed"))
}

fn read_marker(host: &dyn Host, g: &GlobalConfig, site: &Site) -> Result<Option<String>> {
    let path = failed_marker(host, g, site);
    match std::fs::read_to_string(&path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

fn clear_marker(host: &dyn Host, g: &GlobalConfig, site: &Site) -> Result<()> {
    let path = failed_marker(host, g, site);
    match std::fs::remove_file(&path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            Err(e).with_context(|| format!("removing {}", path.display()))
        }
        _ => Ok(()),
    }
}

fn write_marker(host: &dyn Host, g: &GlobalConfig, site: &Site, signature: &str) -> Result<()> {
    let path = failed_marker(host, g, site);
    crate::host::fsx::write_atomic(
        host,
        &path,
        signature.as_bytes(),
        &crate::host::fsx::FileSpec {
            mode: Some(0o644),
            owner: Some((0, 0)),
        },
    )
    .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[derive(Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct Pending {
    /// Skipped update (`Plan::blocked` key) -> when it was first seen (unix seconds).
    blocked: std::collections::BTreeMap<String, u64>,
    /// `source` package ("plugin <slug>") -> its pin and when that pin was first seen.
    sources: std::collections::BTreeMap<String, SourcePin>,
}

#[derive(Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
struct SourcePin {
    pin: String,
    since: u64,
}

/// `<base>/config/update-pending.json` (under the host's sysroot): since when updates have been
/// held back and `source` packages unchanged.
pub fn pending_path(host: &dyn Host, g: &GlobalConfig, site: &Site) -> std::path::PathBuf {
    sys(
        host,
        site.base_dir(g).join("config").join("update-pending.json"),
    )
}

/// Records since when each skipped update and each `source` pin has been around and returns
/// those past `[update] overdue_days` / `source_review_days`. `write = false` (dry run) only
/// reads. An unreadable record starts over; it never stops an update.
fn track(
    host: &dyn Host,
    g: &GlobalConfig,
    site: &Site,
    plan: &Plan,
    now: u64,
    write: bool,
) -> Result<Vec<String>> {
    const DAY: u64 = 86_400;
    let path = pending_path(host, g, site);
    let old: Pending = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let mut new = Pending::default();
    let mut overdue = Vec::new();
    for (key, to) in &plan.blocked {
        let since = old.blocked.get(key).copied().unwrap_or(now).min(now);
        new.blocked.insert(key.clone(), since);
        let days = (now - since) / DAY;
        let limit = u64::from(site.update.overdue_days);
        if limit > 0 && days >= limit {
            let accept = if key.starts_with("core ") {
                "set [update] core = \"major\"".to_string()
            } else {
                "set hold = true on it to keep the version".to_string()
            };
            overdue.push(format!(
                "{key} -> {to}: held back for {days} days ([update] overdue_days = {limit}); update it by hand, or {accept}"
            ));
        }
    }
    // A failed lookup says nothing about what is still held back: keep those clocks running.
    if !plan.errors.is_empty() {
        for (key, since) in &old.blocked {
            new.blocked.entry(key.clone()).or_insert(*since);
        }
    }
    for (kind, list) in [
        (PackageKind::Plugin, &site.plugins),
        (PackageKind::Theme, &site.themes),
    ] {
        for pkg in list.iter().filter(|p| !p.hold) {
            let Some(source) = &pkg.source else { continue };
            let key = format!("{} {}", kind.table(), pkg.slug);
            let pin = pkg.sha256.clone().unwrap_or_default();
            let since = old
                .sources
                .get(&key)
                .filter(|s| s.pin == pin)
                .map_or(now, |s| s.since.min(now));
            new.sources.insert(key.clone(), SourcePin { pin, since });
            let days = (now - since) / DAY;
            let limit = u64::from(site.update.source_review_days);
            if limit > 0 && days >= limit {
                let from = match source {
                    crate::config::Source::Path { .. } => "path",
                    crate::config::Source::Git { .. } => "git",
                    crate::config::Source::Url { .. } => "url",
                };
                overdue.push(format!(
                    "{key} ({from} source): unchanged for {days} days ([update] source_review_days = {limit}) and iwp cannot look for its updates; update it and run `iwp pin`, or set hold = true on it once reviewed"
                ));
            }
        }
    }
    if write && new != old {
        if new == Pending::default() {
            match std::fs::remove_file(&path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    return Err(e).with_context(|| format!("removing {}", path.display()));
                }
                _ => {}
            }
        } else {
            crate::host::fsx::write_atomic(
                host,
                &path,
                &serde_json::to_vec_pretty(&new)?,
                &crate::host::fsx::FileSpec {
                    mode: Some(0o644),
                    owner: Some((0, 0)),
                },
            )
            .with_context(|| format!("writing {}", path.display()))?;
        }
    }
    Ok(overdue)
}

fn signature(changes: &[Change], image_changed: bool) -> String {
    let mut lines: Vec<String> = changes.iter().map(ToString::to_string).collect();
    if image_changed {
        lines.push("image rebuilt".into());
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_site;
    use crate::fetch::cache::Cache;
    use crate::fetch::wporg::{CORE_VERSION_CHECK_URL, plugin_info_url, theme_info_url};
    use crate::testutil::{FakeFetcher, RecordingHost, tmp};
    use std::cell::RefCell;

    const R1: &str = "20261001-100000-aaaaaaa";
    const R2: &str = "20261002-100000-bbbbbbb";
    const TEXT: &str = r#"# acme
name = "a"
domains = ["a.example"]
id = 1

[core]
wordpress = "7.1.2"   # pinned
php = "8.3"

[[plugin]]
slug = "p"
version = "1.0"  # keep me

[[plugin]]
slug = "held"
version = "1.0"
hold = true

[[plugin]]
slug = "needsphp"
version = "1.0"

[[plugin]]
slug = "gone"
version = "1.0"

[[theme]]
slug = "t"
version = "3.5"
"#;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn fetcher() -> FakeFetcher {
        FakeFetcher::new()
            .with(
                &format!("{CORE_VERSION_CHECK_URL}?version=7.1.2"),
                r#"{"offers":[{"version":"7.2"},{"version":"7.2"},{"version":"7.1.4"},{"version":"7.0.9"}]}"#,
            )
            .with(&plugin_info_url("p"), r#"{"version":"1.1","requires_php":"7.4"}"#)
            .with(&plugin_info_url("held"), r#"{"version":"9.0"}"#)
            .with(&plugin_info_url("needsphp"), r#"{"version":"1.5","requires_php":"8.4"}"#)
            .with(&theme_info_url("t"), r#"{"version":"3.5"}"#)
    }

    fn ch(kind: &str, slug: &str, from: &str, to: &str) -> Change {
        Change {
            kind: kind.into(),
            slug: slug.into(),
            from: from.into(),
            to: to.into(),
        }
    }

    #[test]
    fn major_means_a_new_first_number_or_an_unparsable_version() {
        assert!(!is_major("4.2", "4.9.1"));
        assert!(!is_major("4", "4.0.1"));
        assert!(is_major("4.9", "5.0"));
        assert!(is_major("1.0", "1.0-beta2"));
        assert!(is_major("v1", "1.1"));
        assert!(is_major("1..2", "1.3"));
    }

    #[test]
    fn core_policy() {
        let offers = s(&["7.0.9", "7.1.10", "7.1.4", "7.2"]);
        let pick = |cur: &str, p| pick_core(cur, &offers, p);
        assert_eq!(pick("7.1.2", CorePolicy::Minor).as_deref(), Some("7.1.10"));
        assert_eq!(pick("7.1.2", CorePolicy::Major).as_deref(), Some("7.2"));
        assert_eq!(pick("7.1.2", CorePolicy::None), None);
        assert_eq!(pick("7.1.10", CorePolicy::Minor), None);
        assert_eq!(pick("7.2", CorePolicy::Major), None);
        // "7.1" is the first release of the 7.1 branch.
        assert_eq!(pick("7.1", CorePolicy::Minor).as_deref(), Some("7.1.10"));
        assert_eq!(pick("6.0.1", CorePolicy::Minor), None);
    }

    #[test]
    fn plan_takes_newer_versions_and_explains_the_rest() {
        let site = parse_site(TEXT).unwrap();
        let (f, d) = (fetcher(), tmp());
        let c = Cache::new(d.path());
        let p = plan(
            &WpOrg {
                fetcher: &f,
                cache: &c,
            },
            &site,
        );
        assert_eq!(
            p.changes,
            vec![
                ch("core", "wordpress", "7.1.2", "7.1.4"),
                ch("plugin", "p", "1.0", "1.1")
            ]
        );
        assert_eq!(p.skipped.len(), 2, "{:?}", p.skipped);
        assert!(p.skipped[0].contains("core wordpress 7.1.2 -> 7.2: a new branch"));
        assert!(p.skipped[1].contains("needsphp") && p.skipped[1].contains("8.4"));
        assert_eq!(
            p.blocked,
            vec![
                ("core wordpress".to_string(), "7.2".to_string()),
                ("plugin needsphp".to_string(), "1.5".to_string())
            ]
        );
        assert_eq!(p.errors.len(), 1, "{:?}", p.errors);
        assert!(p.errors[0].contains("gone"));
        assert!(
            !f.calls().iter().any(|u| u.contains("held")),
            "held packages are not looked up"
        );
    }

    const DAY: u64 = 86_400;

    fn blocked_plan(items: &[(&str, &str)]) -> Plan {
        Plan {
            blocked: items
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            ..Plan::default()
        }
    }

    #[test]
    fn held_back_updates_become_overdue_after_the_configured_days() {
        let (h, g, l) = deployed();
        let plan = blocked_plan(&[("plugin p", "2.0"), ("core wordpress", "7.2")]);
        let t0 = 1_000 * DAY;
        assert!(track(&h, &g, &l.site, &plan, t0, true).unwrap().is_empty());
        assert!(pending_path(&h, &g, &l.site).is_file());
        let day29 = track(&h, &g, &l.site, &plan, t0 + 29 * DAY, true).unwrap();
        assert!(day29.is_empty(), "{day29:?}");
        let day30 = track(&h, &g, &l.site, &plan, t0 + 30 * DAY, true).unwrap();
        assert_eq!(
            day30,
            vec![
                "plugin p -> 2.0: held back for 30 days ([update] overdue_days = 30); update it by hand, or set hold = true on it to keep the version",
                "core wordpress -> 7.2: held back for 30 days ([update] overdue_days = 30); update it by hand, or set [update] core = \"major\"",
            ]
        );
        // A newer major does not restart the clock; an update that is no longer held back does.
        let newer = blocked_plan(&[("plugin p", "3.0")]);
        let o = track(&h, &g, &l.site, &newer, t0 + 31 * DAY, true).unwrap();
        assert_eq!(o.len(), 1, "{o:?}");
        assert!(o[0].starts_with("plugin p -> 3.0: held back for 31 days"));
        assert!(
            track(&h, &g, &l.site, &Plan::default(), t0 + 32 * DAY, true)
                .unwrap()
                .is_empty()
        );
        assert!(
            !pending_path(&h, &g, &l.site).exists(),
            "nothing pending: no file"
        );
        assert!(
            track(&h, &g, &l.site, &newer, t0 + 33 * DAY, true)
                .unwrap()
                .is_empty()
        );
        // 0 switches the deadline off.
        let mut off = l.site.clone();
        off.update.overdue_days = 0;
        assert!(
            track(&h, &g, &off, &newer, t0 + 400 * DAY, true)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_failed_lookup_or_a_dry_run_does_not_reset_the_clock() {
        let (h, g, l) = deployed();
        let plan = blocked_plan(&[("plugin p", "2.0")]);
        let t0 = 1_000 * DAY;
        // A dry run reads but never writes.
        track(&h, &g, &l.site, &plan, t0, false).unwrap();
        assert!(!pending_path(&h, &g, &l.site).exists());
        track(&h, &g, &l.site, &plan, t0, true).unwrap();
        let lookup_failed = Plan {
            errors: vec!["plugin p: timeout".into()],
            ..Plan::default()
        };
        track(&h, &g, &l.site, &lookup_failed, t0 + 10 * DAY, true).unwrap();
        let o = track(&h, &g, &l.site, &plan, t0 + 30 * DAY, false).unwrap();
        assert_eq!(o.len(), 1, "{o:?}");
        // An unreadable record starts over instead of stopping the update.
        std::fs::write(pending_path(&h, &g, &l.site), "{not json").unwrap();
        assert!(
            track(&h, &g, &l.site, &plan, t0 + 60 * DAY, true)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn source_packages_are_due_for_review_until_repinned_or_held() {
        let (h, g, l) = deployed();
        let mut site = l.site.clone();
        let src = |slug: &str, sha: &str, hold: bool| crate::config::Package {
            slug: slug.into(),
            version: None,
            source: Some(crate::config::Source::Url {
                url: format!("https://example.org/{slug}.zip"),
            }),
            sha256: Some(sha.into()),
            writable: vec![],
            cache: vec![],
            mu: false,
            hold,
        };
        site.plugins.push(src("premium", "aaa", false));
        site.plugins.push(src("inhouse", "bbb", true));
        let (none, t0) = (Plan::default(), 1_000 * DAY);
        assert!(track(&h, &g, &site, &none, t0, true).unwrap().is_empty());
        assert!(
            track(&h, &g, &site, &none, t0 + 89 * DAY, true)
                .unwrap()
                .is_empty()
        );
        let o = track(&h, &g, &site, &none, t0 + 90 * DAY, true).unwrap();
        assert_eq!(
            o,
            vec![
                "plugin premium (url source): unchanged for 90 days ([update] source_review_days = 90) and iwp cannot look for its updates; update it and run `iwp pin`, or set hold = true on it once reviewed"
            ]
        );
        // A new pin restarts the clock.
        site.plugins
            .iter_mut()
            .find(|p| p.slug == "premium")
            .unwrap()
            .sha256 = Some("ccc".into());
        assert!(
            track(&h, &g, &site, &none, t0 + 91 * DAY, true)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            track(&h, &g, &site, &none, t0 + 181 * DAY, true)
                .unwrap()
                .len(),
            1
        );
        site.update.source_review_days = 0;
        assert!(
            track(&h, &g, &site, &none, t0 + 999 * DAY, true)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn apply_keeps_comments_and_layout() {
        let out = apply(
            TEXT,
            &[
                ch("core", "wordpress", "7.1.2", "7.1.4"),
                ch("plugin", "p", "1.0", "1.1"),
                ch("theme", "t", "3.5", "3.6"),
            ],
        )
        .unwrap();
        let want = TEXT
            .replace(
                "wordpress = \"7.1.2\"   # pinned",
                "wordpress = \"7.1.4\"   # pinned",
            )
            .replace(
                "version = \"1.0\"  # keep me",
                "version = \"1.1\"  # keep me",
            )
            .replace("version = \"3.5\"", "version = \"3.6\"");
        assert_eq!(out, want);
        assert!(apply(TEXT, &[ch("plugin", "nope", "1", "2")]).is_err());
    }

    #[test]
    fn deployable_ignores_operator_settings() {
        let a = parse_site(TEXT).unwrap();
        let mut b = a.clone();
        b.wpcli.mounts = vec!["/srv/x".into()];
        b.update.auto = false;
        b.verify.admins = Some(vec!["alice".into()]);
        b.plugins[0].hold = true;
        assert!(same_deployable(&a, &b));
        b.plugins[0].version = Some("1.1".into());
        assert!(!same_deployable(&a, &b));
    }

    /// A host with site "a" deployed as R1 from `TEXT`.
    fn deployed() -> (RecordingHost, GlobalConfig, LoadedSite) {
        let h = RecordingHost::new(true);
        let g = GlobalConfig {
            base_root: "/srv/www".into(),
            ..GlobalConfig::default()
        };
        let site = parse_site(TEXT).unwrap();
        let base = sys(&h, site.base_dir(&g));
        let rel = base.join("releases").join(R1);
        std::fs::create_dir_all(&rel).unwrap();
        std::fs::write(
            rel.join(".iwp-release.json"),
            serde_json::to_vec(&crate::build::tests::sample_manifest(&site, R1)).unwrap(),
        )
        .unwrap();
        crate::lifecycle::releases::point(&base, "current", R1).unwrap();
        let snap = crate::lifecycle::releases::snapshot_path(&base, R1);
        std::fs::create_dir_all(snap.parent().unwrap()).unwrap();
        std::fs::write(&snap, serde_json::to_vec(&site).unwrap()).unwrap();
        let path = sys(&h, "/etc/iwp/sites/a.toml");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, TEXT).unwrap();
        (h, g, LoadedSite { path, site })
    }

    fn live_image() -> String {
        crate::build::tests::sample_manifest(&parse_site(TEXT).unwrap(), R1).image_digest
    }

    /// Runs `update_site` with a scripted deploy; returns the outcome and the sites deployed.
    fn run(
        h: &RecordingHost,
        g: &GlobalConfig,
        l: &LoadedSite,
        image: Option<String>,
        deploy: &dyn Fn(&Site) -> Result<DeployReport>,
        dry_run: bool,
    ) -> (Outcome, Vec<Site>) {
        run_as(h, g, l, image, deploy, dry_run, false)
    }

    fn run_as(
        h: &RecordingHost,
        g: &GlobalConfig,
        l: &LoadedSite,
        image: Option<String>,
        deploy: &dyn Fn(&Site) -> Result<DeployReport>,
        dry_run: bool,
        retry_failed: bool,
    ) -> (Outcome, Vec<Site>) {
        let (f, d) = (fetcher(), tmp());
        let c = Cache::new(d.path());
        let seen = RefCell::new(Vec::new());
        let fx = Effects {
            image_id: &|_| Ok(image.clone()),
            deploy: &|s| {
                seen.borrow_mut().push(s.clone());
                deploy(s)
            },
        };
        let w = WpOrg {
            fetcher: &f,
            cache: &c,
        };
        let (o, _) = update_site(h, g, l, &w, &fx, dry_run, retry_failed).unwrap();
        (o, seen.into_inner())
    }

    fn report(release: &str, problems: &[&str]) -> DeployReport {
        DeployReport {
            site: "a".into(),
            release: release.into(),
            dry_run_diff: None,
            problems: s(problems),
            rolled_back: None,
            dump: None,
            gc_removed: vec![],
            warnings: vec![],
        }
    }

    #[test]
    fn update_bumps_the_file_and_deploys_it() {
        let (h, g, l) = deployed();
        let (o, deployed) = run(
            &h,
            &g,
            &l,
            Some(live_image()),
            &|_| Ok(report(R2, &[])),
            false,
        );
        assert!(
            matches!(&o, Outcome::Updated { release, changes, image_changed: false, .. } if release == R2 && changes.len() == 2),
            "{o:?}"
        );
        assert_eq!(deployed.len(), 1);
        assert_eq!(deployed[0].core.wordpress, "7.1.4");
        assert_eq!(deployed[0].plugins[0].version.as_deref(), Some("1.1"));
        let text = std::fs::read_to_string(&l.path).unwrap();
        assert!(text.contains("wordpress = \"7.1.4\"   # pinned"), "{text}");
    }

    #[test]
    fn the_site_file_is_written_only_after_the_deploy_succeeded() {
        // A run killed (SIGTERM, timeout) or failing mid-deploy must leave the file describing
        // what is live.
        let (h, g, l) = deployed();
        let path = l.path.clone();
        let (o, deployed) = run(
            &h,
            &g,
            &l,
            Some(live_image()),
            &|s| {
                assert_eq!(std::fs::read_to_string(&path).unwrap(), TEXT);
                assert_eq!(s.core.wordpress, "7.1.4");
                Ok(report(R2, &[]))
            },
            false,
        );
        assert!(matches!(o, Outcome::Updated { .. }), "{o:?}");
        assert_eq!(deployed.len(), 1);
        let text = std::fs::read_to_string(&l.path).unwrap();
        assert!(text.contains("wordpress = \"7.1.4\"   # pinned"), "{text}");
        assert!(text.contains("version = \"1.1\"  # keep me"), "{text}");
    }

    #[test]
    fn deploy_failure_leaves_the_site_file_unchanged() {
        let (h, g, l) = deployed();
        let path = l.path.clone();
        let (o, _) = run(
            &h,
            &g,
            &l,
            Some(live_image()),
            &|_| {
                assert_eq!(std::fs::read_to_string(&path).unwrap(), TEXT);
                anyhow::bail!("killed")
            },
            false,
        );
        assert!(
            matches!(
                &o,
                Outcome::Failed {
                    previous_live: true,
                    ..
                }
            ),
            "{o:?}"
        );
        assert_eq!(std::fs::read_to_string(&l.path).unwrap(), TEXT);
    }

    #[test]
    fn an_edit_made_during_the_deploy_is_kept() {
        let (h, g, l) = deployed();
        let path = l.path.clone();
        let (o, _) = run(
            &h,
            &g,
            &l,
            Some(live_image()),
            &|_| {
                let t = std::fs::read_to_string(&path).unwrap();
                std::fs::write(&path, format!("# operator note\n{t}")).unwrap();
                Ok(report(R2, &[]))
            },
            false,
        );
        assert!(matches!(o, Outcome::Updated { .. }), "{o:?}");
        let text = std::fs::read_to_string(&l.path).unwrap();
        assert!(text.starts_with("# operator note\n# acme"), "{text}");
        assert!(text.contains("wordpress = \"7.1.4\""), "{text}");
    }

    #[test]
    fn a_busy_site_is_left_alone() {
        // Someone else is deploying: neither the file edit nor a later write-back may happen.
        let (h, g, l) = deployed();
        let _held = crate::host::lock::SiteLock::acquire(&h, "a").unwrap();
        let (f, d) = (fetcher(), tmp());
        let c = Cache::new(d.path());
        let fx = Effects {
            image_id: &|_| Ok(Some(live_image())),
            deploy: &|_| unreachable!(),
        };
        let w = WpOrg {
            fetcher: &f,
            cache: &c,
        };
        let e = update_site(&h, &g, &l, &w, &fx, false, true).unwrap_err();
        assert!(format!("{e:#}").contains("in progress"), "{e:#}");
        assert_eq!(std::fs::read_to_string(&l.path).unwrap(), TEXT);
    }

    #[test]
    fn an_update_that_failed_is_not_retried_unattended() {
        let (h, g, l) = deployed();
        let fail = |_: &Site| Ok(report(R2, &["smoke: 500"]));
        let (o, n) = run(&h, &g, &l, Some(live_image()), &fail, false);
        assert!(matches!(o, Outcome::Failed { .. }) && n.len() == 1);
        // The next unattended run sees the same update and does not deploy it again.
        let (o, n) = run(&h, &g, &l, Some(live_image()), &|_| unreachable!(), false);
        assert!(
            matches!(&o, Outcome::Skipped { why: m, .. } if m.contains("failed before") && m.contains("plugin p 1.0 -> 1.1")),
            "{o:?}"
        );
        assert!(n.is_empty());
        // An operator's explicit run retries, and success clears the memory.
        let (o, _) = run_as(
            &h,
            &g,
            &l,
            Some(live_image()),
            &|_| Ok(report(R2, &[])),
            false,
            true,
        );
        assert!(matches!(o, Outcome::Updated { .. }), "{o:?}");
        assert!(!failed_marker(&h, &g, &l.site).exists());
    }

    #[test]
    fn package_policy_limits_unattended_majors() {
        use crate::config::PackagePolicy;
        let mut site = parse_site(TEXT).unwrap();
        site.update.core = CorePolicy::None;
        let f = fetcher()
            .with(&plugin_info_url("p"), r#"{"version":"2.0"}"#)
            .with(&plugin_info_url("needsphp"), r#"{"version":"1.4.2"}"#)
            .with(&plugin_info_url("gone"), r#"{"version":"1.0-beta2"}"#)
            .with(&theme_info_url("t"), r#"{"version":"3.6"}"#);
        let d = tmp();
        let c = Cache::new(d.path());
        let w = WpOrg {
            fetcher: &f,
            cache: &c,
        };
        // Default "minor": same first number only; unparsable versions count as major.
        assert_eq!(site.update.plugins, PackagePolicy::Minor);
        let p = plan(&w, &site);
        assert_eq!(
            p.changes,
            vec![
                ch("plugin", "needsphp", "1.0", "1.4.2"),
                ch("theme", "t", "3.5", "3.6")
            ]
        );
        assert!(
            p.skipped
                .iter()
                .any(|m| m.contains("plugin p 1.0 -> 2.0") && m.contains("major")),
            "{:?}",
            p.skipped
        );
        assert!(
            p.skipped
                .iter()
                .any(|m| m.contains("plugin gone 1.0 -> 1.0-beta2") && m.contains("major")),
            "{:?}",
            p.skipped
        );
        // "major": everything newer.
        site.update.plugins = PackagePolicy::Major;
        let p = plan(&w, &site);
        assert_eq!(p.changes.len(), 4, "{:?}", p.changes);
        // "none": packages are not even looked up.
        site.update.plugins = PackagePolicy::None;
        let f2 = fetcher();
        let w2 = WpOrg {
            fetcher: &f2,
            cache: &c,
        };
        let p = plan(&w2, &site);
        assert!(p.changes.is_empty() && p.errors.is_empty(), "{p:?}");
        assert!(
            f2.calls().iter().all(|u| !u.contains("/info/")),
            "{:?}",
            f2.calls()
        );
    }

    #[test]
    fn package_policy_parses_and_rejects_unknown_values() {
        use crate::config::PackagePolicy;
        let s = parse_site(&format!("{TEXT}\n[update]\nplugins = \"major\"\n")).unwrap();
        assert_eq!(s.update.plugins, PackagePolicy::Major);
        let s = parse_site(&format!("{TEXT}\n[update]\nplugins = \"none\"\n")).unwrap();
        assert_eq!(s.update.plugins, PackagePolicy::None);
        assert!(parse_site(&format!("{TEXT}\n[update]\nplugins = \"all\"\n")).is_err());
    }

    #[test]
    fn plugin_needing_a_newer_wordpress_is_skipped() {
        let mut site = parse_site(TEXT).unwrap();
        site.update.core = CorePolicy::None;
        let f = fetcher().with(
            &plugin_info_url("p"),
            r#"{"version":"1.1","requires":"7.2"}"#,
        );
        let d = tmp();
        let c = Cache::new(d.path());
        let p = plan(
            &WpOrg {
                fetcher: &f,
                cache: &c,
            },
            &site,
        );
        assert!(p.changes.is_empty(), "{:?}", p.changes);
        assert!(
            p.skipped
                .iter()
                .any(|m| m.contains("plugin p") && m.contains("WordPress 7.2")),
            "{:?}",
            p.skipped
        );
    }

    #[test]
    fn dry_run_changes_nothing() {
        let (h, g, l) = deployed();
        let (o, deployed) = run(&h, &g, &l, Some(live_image()), &|_| unreachable!(), true);
        assert!(
            matches!(&o, Outcome::DryRun { changes, .. } if changes.len() == 2),
            "{o:?}"
        );
        assert!(deployed.is_empty());
        assert_eq!(std::fs::read_to_string(&l.path).unwrap(), TEXT);
    }

    #[test]
    fn failed_deploy_restores_the_site_file() {
        let (h, g, l) = deployed();
        // Rolled back (or never activated): R1 is still current.
        let (o, _) = run(
            &h,
            &g,
            &l,
            Some(live_image()),
            &|_| Ok(report(R2, &["smoke: 500"])),
            false,
        );
        assert!(
            matches!(&o, Outcome::Failed { previous_live: true, problems, .. } if problems[0].contains("500")),
            "{o:?}"
        );
        assert_eq!(std::fs::read_to_string(&l.path).unwrap(), TEXT);
        let (o, _) = run_as(
            &h,
            &g,
            &l,
            Some(live_image()),
            &|_| anyhow::bail!("build boom"),
            false,
            true,
        );
        assert!(
            matches!(&o, Outcome::Failed { previous_live: true, problems, .. } if problems[0].contains("build boom")),
            "{o:?}"
        );
        assert_eq!(std::fs::read_to_string(&l.path).unwrap(), TEXT);
    }

    #[test]
    fn failed_deploy_that_stays_live_keeps_the_new_file() {
        let (h, g, l) = deployed();
        let base = sys(&h, l.site.base_dir(&g));
        let (o, _) = run(
            &h,
            &g,
            &l,
            Some(live_image()),
            &|_| {
                // The new release went live and the automatic rollback did not work.
                std::fs::create_dir_all(base.join("releases").join(R2)).unwrap();
                crate::lifecycle::releases::point(&base, "current", R2).unwrap();
                Ok(report(R2, &["smoke: 500", "automatic rollback failed"]))
            },
            false,
        );
        assert!(
            matches!(
                &o,
                Outcome::Failed {
                    previous_live: false,
                    ..
                }
            ),
            "{o:?}"
        );
        assert!(std::fs::read_to_string(&l.path).unwrap().contains("7.1.4"));
    }

    #[test]
    fn undeployed_edits_are_never_activated() {
        let (h, g, mut l) = deployed();
        l.site.plugins[0].version = Some("0.9".into());
        let (o, deployed) = run(&h, &g, &l, Some(live_image()), &|_| unreachable!(), false);
        assert!(
            matches!(&o, Outcome::Skipped { why: m, benign: false } if m.contains("not deployed")),
            "{o:?}"
        );
        assert!(deployed.is_empty());
        assert_eq!(std::fs::read_to_string(&l.path).unwrap(), TEXT);
    }

    #[test]
    fn unparsable_snapshot_is_skipped_with_its_path() {
        let (h, g, l) = deployed();
        let snap = crate::lifecycle::releases::snapshot_path(&sys(&h, l.site.base_dir(&g)), R1);
        std::fs::write(&snap, b"{not json").unwrap();
        let (o, n) = run(&h, &g, &l, Some(live_image()), &|_| unreachable!(), false);
        assert!(
            matches!(&o, Outcome::Skipped { why: m, .. } if m.contains(&snap.display().to_string())),
            "{o:?}"
        );
        assert!(n.is_empty());
    }

    #[test]
    fn site_without_a_release_is_skipped() {
        let (h, g, l) = deployed();
        std::fs::remove_file(sys(&h, l.site.base_dir(&g)).join("current")).unwrap();
        let (o, _) = run(&h, &g, &l, None, &|_| unreachable!(), false);
        assert!(
            matches!(&o, Outcome::Skipped { why: m, benign: true } if m.contains("iwp deploy")),
            "{o:?}"
        );
    }

    #[test]
    fn new_image_alone_redeploys_the_site_as_it_is() {
        let (h, g, mut l) = deployed();
        // Nothing newer on wordpress.org for this site.
        let text = TEXT.replace("7.1.2", "7.1.4").replace(
            "version = \"1.0\"  # keep me",
            "version = \"1.1\"  # keep me",
        );
        l.site = parse_site(&text).unwrap();
        std::fs::write(&l.path, &text).unwrap();
        let base = sys(&h, l.site.base_dir(&g));
        std::fs::write(
            crate::lifecycle::releases::snapshot_path(&base, R1),
            serde_json::to_vec(&l.site).unwrap(),
        )
        .unwrap();
        let f = FakeFetcher::new()
            .with(
                &format!("{CORE_VERSION_CHECK_URL}?version=7.1.4"),
                r#"{"offers":[{"version":"7.1.4"}]}"#,
            )
            .with(&plugin_info_url("p"), r#"{"version":"1.1"}"#)
            .with(&plugin_info_url("needsphp"), r#"{"version":"1.0"}"#)
            .with(&plugin_info_url("gone"), r#"{"version":"1.0"}"#)
            .with(&theme_info_url("t"), r#"{"version":"3.5"}"#);
        let d = tmp();
        let c = Cache::new(d.path());
        let w = WpOrg {
            fetcher: &f,
            cache: &c,
        };
        let n = RefCell::new(0);
        let go = |image: Option<String>| {
            let fx = Effects {
                image_id: &|_| Ok(image.clone()),
                deploy: &|_| {
                    *n.borrow_mut() += 1;
                    Ok(report(R2, &[]))
                },
            };
            update_site(&h, &g, &l, &w, &fx, false, false).unwrap().0
        };
        assert!(matches!(go(Some(live_image())), Outcome::UpToDate));
        assert!(
            matches!(go(None), Outcome::UpToDate),
            "a missing image is not a change"
        );
        assert_eq!(*n.borrow(), 0);
        let o = go(Some("sha256:new".into()));
        assert!(
            matches!(&o, Outcome::Updated { image_changed: true, changes, .. } if changes.is_empty()),
            "{o:?}"
        );
        assert_eq!(*n.borrow(), 1);
        assert_eq!(std::fs::read_to_string(&l.path).unwrap(), text);
    }

    #[test]
    fn an_unreadable_failure_marker_is_an_error_not_a_fresh_start() {
        // The marker is a host path (under the sysroot) like every other effect; failing to read
        // it must not silently re-deploy an update that failed before.
        let (h, g, l) = deployed();
        let marker = sys(&h, l.site.base_dir(&g).join("config/update-failed"));
        std::fs::create_dir_all(&marker).unwrap();
        let (f, d) = (fetcher(), tmp());
        let c = Cache::new(d.path());
        let fx = Effects {
            image_id: &|_| Ok(Some(live_image())),
            deploy: &|_| unreachable!(),
        };
        let w = WpOrg {
            fetcher: &f,
            cache: &c,
        };
        let e = update_site(&h, &g, &l, &w, &fx, false, false).unwrap_err();
        assert!(format!("{e:#}").contains("update-failed"), "{e:#}");
    }
}
