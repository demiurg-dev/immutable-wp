//! Site lifecycle commands: new, setup, deploy, rollback, gc, update.

use super::*;

/// The dump holding the database as it was under `target`: deploy takes `db-<release>` just
/// before activating that release, so it is the dump of the release that replaced `target`.
fn with_db_dump(
    backups: &std::path::Path,
    target: &str,
    current: Option<&str>,
    previous: Option<&str>,
) -> Result<PathBuf> {
    if previous != Some(target) {
        return Err(UsageError(format!(
            "--with-db only rolls back to the previous release ({}); restore another state explicitly with iwp db restore",
            previous.unwrap_or("none")
        ))
        .into());
    }
    let current = current.ok_or_else(|| anyhow::anyhow!("site has no current release"))?;
    // db-<current> is the database as it was just before `current` replaced `previous`; that
    // only holds when `current` came from a deploy, i.e. is newer than the target.
    if target >= current {
        return Err(UsageError(
            "--with-db only undoes the last deploy (target must be older than the current release); restore another state explicitly with iwp db restore".into(),
        )
        .into());
    }
    Ok(backups.join(format!("db-{current}.sql.gz")))
}

/// Lock, find the podman network and provision the host for a validated site.
fn run_setup(
    host: &dyn Host,
    global: &GlobalConfig,
    site: &Site,
    salts_from: Option<&std::path::Path>,
) -> Result<()> {
    let _lock = crate::host::lock::SiteLock::acquire(host, &site.name)?;
    let net = crate::host::db::podman_network(host, &global.podman_network)?;
    let opts = crate::lifecycle::setup::SetupOpts {
        salts_from,
        ..Default::default()
    };
    crate::lifecycle::setup::setup(host, global, site, &opts, &net)
}

pub(super) fn setup_cmd(
    global: &GlobalConfig,
    name: &str,
    salts_from: Option<&std::path::Path>,
) -> Result<ExitCode> {
    let host = SystemHost::new();
    let name = site_arg(name)?;
    let sites = load_valid_sites(global, &[name.to_string()])?;
    let site = loaded_site(&sites, name);
    require_root(&host, "setup")?;
    let salts_from = salts_from.map(|p| absolute(p.to_path_buf())).transpose()?;
    run_setup(&host, global, site, salts_from.as_deref())?;
    println!("set up {name}; next: iwp deploy {name}");
    Ok(ExitCode::SUCCESS)
}

pub(super) fn new_cmd(
    global: &GlobalConfig,
    name: &str,
    domains: &[String],
    base: Option<&std::path::Path>,
    wordpress: Option<String>,
    php: &str,
    salts_from: Option<&std::path::Path>,
) -> Result<ExitCode> {
    let host = SystemHost::new();
    let name = site_arg(name)?;
    let final_path = global.sites_dir.join(format!("{name}.toml"));
    if final_path.exists() {
        return Err(
            UsageError(format!("site file {} already exists", final_path.display())).into(),
        );
    }
    let wordpress = match wordpress {
        Some(w) => w,
        None => {
            let fetcher = crate::fetch::net::HttpFetcher::new();
            let cache = crate::fetch::cache::Cache::new(&global.cache_dir);
            crate::fetch::wporg::WpOrg {
                fetcher: &fetcher,
                cache: &cache,
            }
            .core_latest()?
        }
    };
    let issues = validate_core_versions(&wordpress, php);
    if !issues.is_empty() {
        let msg: Vec<String> = issues.iter().map(|i| i.to_string()).collect();
        return Err(UsageError(msg.join("; ")).into());
    }
    let base = base.map(|b| absolute(b.to_path_buf())).transpose()?;
    let salts_from = salts_from.map(|p| absolute(p.to_path_buf())).transpose()?;
    let existing = crate::lifecycle::setup::existing_sites(global)?;
    let text = crate::lifecycle::setup::new_site_text(
        name,
        domains,
        base.as_deref(),
        crate::lifecycle::setup::next_id(&host, global, &existing)?,
        &wordpress,
        php,
    );
    // A preview for a clear early error (also for non-root); repeated under the lock below.
    crate::lifecycle::setup::validate_new(global, existing, name, &text, &final_path)?;
    require_root(&host, "new")?;
    // Worker check, then id assignment + installation under the host-wide sites lock.
    let loaded = crate::lifecycle::setup::create_site_file(
        &host,
        global,
        &crate::lifecycle::setup::NewSite {
            name,
            domains,
            base: base.as_deref(),
            wordpress: &wordpress,
            php,
            id: None,
        },
    )?;
    println!("created {}", final_path.display());
    if let Err(e) = run_setup(&host, global, &loaded.site, salts_from.as_deref()) {
        return Err(e.context(format!(
            "setup failed; {} was kept: fix the problem and run `iwp setup {name}`",
            final_path.display()
        )));
    }
    println!("set up {name}; next: iwp deploy {name}");
    Ok(ExitCode::SUCCESS)
}

pub(super) fn deploy_cmd(global: &GlobalConfig, name: &str, dry_run: bool) -> Result<ExitCode> {
    let host = SystemHost::new();
    let name = site_arg(name)?;
    let sites = load_valid_sites(global, &[name.to_string()])?;
    let site = loaded_site(&sites, name);
    require_root(&host, "deploy")?;
    let fetcher = crate::fetch::net::HttpFetcher::new();
    let cache = crate::fetch::cache::Cache::new(&global.cache_dir);
    let images = PodmanImages {
        wporg: crate::fetch::wporg::WpOrg {
            fetcher: &fetcher,
            cache: &cache,
        },
        refresh_base: false,
    };
    let ops = crate::lifecycle::deploy::SystemOps {
        host: &host,
        g: global,
        fetcher: &fetcher,
        images: &images,
    };
    let report = crate::lifecycle::deploy::deploy(&host, global, site, &ops, dry_run)?;
    print_warnings(&report.warnings);
    if let Some(diff) = &report.dry_run_diff {
        if diff.is_empty() {
            println!("no changes");
        }
        for l in diff {
            println!("{l}");
        }
        return Ok(ExitCode::SUCCESS);
    }
    if report.problems.is_empty() {
        println!("deployed {}", report.release);
        return Ok(ExitCode::SUCCESS);
    }
    for p in &report.problems {
        println!("{p}");
    }
    if let Some((rel, problems)) = &report.rolled_back {
        println!("rolled back to {rel}");
        for p in problems {
            println!("{p}");
        }
    }
    if let Some(hint) = report.restore_hint() {
        println!("restore the database with: {hint}");
    }
    Ok(ExitCode::from(1))
}

pub(super) fn rollback_cmd(
    global: &GlobalConfig,
    name: &str,
    release: Option<&str>,
    with_db: bool,
    yes: bool,
) -> Result<ExitCode> {
    let host = SystemHost::new();
    let name = site_arg(name)?;
    if let Some(r) = release
        && !crate::lifecycle::releases::is_release_name(r)
    {
        return Err(UsageError(format!(
            "{r:?} is not a release name (expected YYYYMMDD-HHMMSS-<7 hex>)"
        ))
        .into());
    }
    if with_db && !yes {
        return Err(UsageError(format!(
            "refusing to restore the database without --yes (this overwrites the database of {name})"
        ))
        .into());
    }
    let sites = load_valid_sites(global, &[name.to_string()])?;
    let site = loaded_site(&sites, name);
    require_root(&host, "rollback")?;
    let fetcher = crate::fetch::net::HttpFetcher::new();
    let cache = crate::fetch::cache::Cache::new(&global.cache_dir);
    let images = PodmanImages {
        wporg: crate::fetch::wporg::WpOrg {
            fetcher: &fetcher,
            cache: &cache,
        },
        refresh_base: false,
    };
    let ops = crate::lifecycle::deploy::SystemOps {
        host: &host,
        g: global,
        fetcher: &fetcher,
        images: &images,
    };
    let before = |target: &str| -> Result<Option<PathBuf>> {
        if !with_db {
            return Ok(None);
        }
        let backups = backups_dir(global, site)?;
        let base = site.base_dir(global);
        let dump = with_db_dump(
            &backups,
            target,
            crate::lifecycle::releases::current(&base)?.as_deref(),
            crate::lifecycle::releases::previous(&base)?.as_deref(),
        )?;
        if !dump.is_file() {
            anyhow::bail!(
                "no database snapshot {} (taken when the current release was deployed); roll back without --with-db",
                dump.display()
            );
        }
        let ident = crate::host::db::DbIdent::from_site(site)?;
        crate::host::db::validate_dump_source(&dump)?;
        let safety = backups.join(format!("db-pre-rollback-{}.sql.gz", timestamp()));
        crate::host::db::dump(&host, global, &ident, &safety)?;
        println!("safety dump: {}", safety.display());
        crate::host::db::restore(&host, global, &ident, &dump)?;
        println!("restored from: {}", dump.display());
        Ok(Some(dump))
    };
    let report = crate::lifecycle::deploy::rollback(&host, global, site, &ops, release, &before)?;
    print_warnings(&report.warnings);
    println!("rolled back to {}", report.release);
    for p in &report.problems {
        println!("{p}");
    }
    Ok(if report.problems.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

pub(super) fn gc_cmd(global: &GlobalConfig, name: &str) -> Result<ExitCode> {
    let host = SystemHost::new();
    let name = site_arg(name)?;
    let sites = load_valid_sites(global, &[name.to_string()])?;
    let site = loaded_site(&sites, name);
    require_root(&host, "gc")?;
    let _lock = crate::host::lock::SiteLock::acquire(&host, name)?;
    let base = crate::host::sys(&host, site.base_dir(global));
    let removed = crate::lifecycle::deploy::gc(&base, global)?;
    if removed.is_empty() {
        println!("nothing to remove");
    }
    for r in removed {
        println!("removed {r}");
    }
    Ok(ExitCode::SUCCESS)
}

/// Every site file in the sites directory with its own verdict (for `iwp update --all`): a file
/// that does not parse or validate is an `Err` naming its issues, and does not affect the
/// others. Cross-site issues ("sites: …") count against each file they name. Global config
/// issues are a UsageError as everywhere else.
/// True when `issue` contains `file` as a whole token: bounded by the start, whitespace, `,` or
/// `:` on both sides (so `a.toml` is not blamed for an issue naming `ba.toml`).
fn names_file(issue: &str, file: &str) -> bool {
    let is_sep = |c: char| c.is_whitespace() || c == ',' || c == ':';
    issue.match_indices(file).any(|(i, m)| {
        issue[..i].chars().next_back().is_none_or(is_sep)
            && issue[i + m.len()..].chars().next().is_none_or(is_sep)
    })
}

fn load_sites_each(
    global: &GlobalConfig,
) -> Result<Vec<(String, std::result::Result<LoadedSite, String>)>> {
    let global_issues: Vec<String> = validate_global(global)
        .into_iter()
        .map(|i| format!("iwp.toml: {i}"))
        .collect();
    if !global_issues.is_empty() {
        return Err(UsageError(global_issues.join("\n")).into());
    }
    let dir = &global.sites_dir;
    let mut paths = Vec::new();
    for e in
        std::fs::read_dir(dir).map_err(|e| UsageError(format!("reading {}: {e}", dir.display())))?
    {
        let p = e?.path();
        if p.extension().is_some_and(|x| x == "toml") {
            paths.push(p);
        }
    }
    paths.sort();
    let file = |p: &std::path::Path| {
        p.file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_default()
    };
    let mut out: Vec<(String, std::result::Result<LoadedSite, String>)> = paths
        .iter()
        .map(|p| {
            (
                file(p),
                crate::config::load_site(p).map_err(|e| format!("{e:#}")),
            )
        })
        .collect();
    let parsed: Vec<LoadedSite> = out
        .iter()
        .filter_map(|(_, r)| r.as_ref().ok().cloned())
        .collect();
    let issues: Vec<String> = validate_all(&parsed, global)
        .into_iter()
        .map(|i| i.to_string())
        .collect();
    for (f, r) in &mut out {
        if r.is_err() {
            continue;
        }
        let own: Vec<&str> = issues
            .iter()
            .filter(|t| {
                t.starts_with(&format!("{f}:")) || (t.starts_with("sites:") && names_file(t, f))
            })
            .map(String::as_str)
            .collect();
        if !own.is_empty() {
            *r = Err(own.join("\n"));
        }
    }
    Ok(out)
}

pub(super) fn update_cmd(
    global: &GlobalConfig,
    name: Option<&str>,
    all: bool,
    dry_run: bool,
    refresh_base: bool,
) -> Result<ExitCode> {
    use crate::lifecycle::update::{Effects, Outcome, update_site};
    let only: Vec<String> = match (name, all) {
        (Some(n), false) => vec![site_arg(n)?.to_string()],
        (None, true) => vec![],
        _ => return Err(UsageError("give either <site> or --all".into()).into()),
    };
    let host = SystemHost::new();
    let mut failed = false;
    // --all: one broken site file is reported as that site's failure; the others still update.
    let (sites, broken) = if name.is_some() {
        (load_valid_sites(global, &only)?, Vec::new())
    } else {
        let mut ok = Vec::new();
        let mut broken = Vec::new();
        for (file, r) in load_sites_each(global)? {
            match r {
                Ok(l) => ok.push(l),
                Err(e) => broken.push((file, e)),
            }
        }
        (ok, broken)
    };
    require_root(&host, "update")?;
    for (file, e) in &broken {
        println!("{file}: invalid site file, not updated:\n{e}");
        failed = true;
    }
    // A named site is updated even when it opted out of the unattended run.
    let selected: Vec<&LoadedSite> = sites
        .iter()
        .filter(|l| match name {
            Some(n) => l.site.name == n,
            None => {
                if !l.site.update.auto {
                    println!("{}: skipped ([update] auto = false)", l.site.name);
                }
                l.site.update.auto
            }
        })
        .collect();
    let fetcher = crate::fetch::net::HttpFetcher::new();
    let cache = crate::fetch::cache::Cache::new(&global.cache_dir);
    let wporg = || crate::fetch::wporg::WpOrg {
        fetcher: &fetcher,
        cache: &cache,
    };
    let images = PodmanImages {
        wporg: wporg(),
        refresh_base: false,
    };
    if refresh_base && !dry_run {
        let fresh = PodmanImages {
            wporg: wporg(),
            refresh_base: true,
        };
        let pairs: BTreeSet<(&str, &str)> = selected
            .iter()
            .map(|l| (l.site.core.wordpress.as_str(), l.site.core.php.as_str()))
            .collect();
        for (wp, php) in pairs {
            eprintln!("refreshing {}", fpm_tag(wp, php));
            if let Err(e) = fresh.build(wp, php) {
                eprintln!("error: {e:#}");
                failed = true;
            }
        }
    }
    let ops = crate::lifecycle::deploy::SystemOps {
        host: &host,
        g: global,
        fetcher: &fetcher,
        images: &images,
    };
    let fx = Effects {
        image_id: &|s| {
            let tag = s.fpm_image();
            Ok(if images.exists(&tag)? {
                Some(images.image_id(&tag)?)
            } else {
                None
            })
        },
        // update_site holds the site lock around the whole update.
        deploy: &|s| crate::lifecycle::deploy::deploy_locked(&host, global, s, &ops, false),
    };
    for l in selected {
        let n = &l.site.name;
        let (outcome, plan) =
            match update_site(&host, global, l, &wporg(), &fx, dry_run, name.is_some()) {
                Ok(r) => r,
                Err(e) => {
                    println!("{n}: error: {e:#}");
                    failed = true;
                    continue;
                }
            };
        for s in &plan.skipped {
            println!("{n}: skipped {s}");
        }
        for e in &plan.errors {
            println!("{n}: lookup failed: {e}");
            failed = true;
        }
        for o in &plan.overdue {
            println!("{n}: overdue: {o}");
            failed = true;
        }
        let list = |changes: &[crate::lifecycle::update::Change], image_changed: bool| {
            for c in changes {
                println!("{n}: {c}");
            }
            if image_changed {
                println!("{n}: image rebuilt");
            }
        };
        match outcome {
            Outcome::UpToDate => println!("{n}: up to date"),
            Outcome::Skipped { why, benign } => {
                println!("{n}: not updated: {why}");
                failed |= !benign;
            }
            Outcome::DryRun {
                changes,
                image_changed,
            } => list(&changes, image_changed),
            Outcome::Updated {
                changes,
                image_changed,
                release,
                warnings,
            } => {
                list(&changes, image_changed);
                for w in &warnings {
                    println!("{n}: warning: {w}");
                }
                println!("{n}: deployed {release}");
            }
            Outcome::Failed {
                changes,
                problems,
                previous_live: restored,
            } => {
                list(&changes, false);
                for p in &problems {
                    println!("{n}: {p}");
                }
                println!(
                    "{n}: update FAILED; {}",
                    if restored {
                        "the previous release is live; the site file was not changed"
                    } else {
                        "the new release is still live; the site file describes it"
                    }
                );
                failed = true;
            }
        }
    }
    Ok(if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_all_loads_each_site_file_on_its_own() {
        let d = crate::testutil::tmp();
        let site = |name: &str, id: u32| {
            format!(
                "name = \"{name}\"\ndomains = [\"{name}.example\"]\nid = {id}\n[core]\nwordpress = \"7.1.2\"\nphp = \"8.3\"\n"
            )
        };
        std::fs::write(d.path().join("a.toml"), site("a", 1)).unwrap();
        std::fs::write(d.path().join("b.toml"), "name = ").unwrap(); // does not parse
        std::fs::write(d.path().join("c.toml"), site("wrong", 3)).unwrap(); // name != stem
        std::fs::write(d.path().join("e.toml"), site("e", 5)).unwrap();
        let g = GlobalConfig {
            sites_dir: d.path().to_path_buf(),
            ..GlobalConfig::default()
        };
        let all = load_sites_each(&g).unwrap();
        let verdict: Vec<(&str, bool)> = all.iter().map(|(f, r)| (f.as_str(), r.is_ok())).collect();
        assert_eq!(
            verdict,
            vec![
                ("a.toml", true),
                ("b.toml", false),
                ("c.toml", false),
                ("e.toml", true)
            ]
        );
        assert!(
            all[2].1.as_ref().unwrap_err().contains("c.toml"),
            "{:?}",
            all[2].1
        );
        // A cross-site clash (same id) counts against both files it names, not the bystander.
        std::fs::write(d.path().join("e.toml"), site("e", 1)).unwrap();
        let all = load_sites_each(&g).unwrap();
        let verdict: Vec<(&str, bool)> = all.iter().map(|(f, r)| (f.as_str(), r.is_ok())).collect();
        assert_eq!(
            verdict,
            vec![
                ("a.toml", false),
                ("b.toml", false),
                ("c.toml", false),
                ("e.toml", false)
            ]
        );
        std::fs::write(d.path().join("f.toml"), site("f", 6)).unwrap();
        let all = load_sites_each(&g).unwrap();
        assert!(all.iter().any(|(f, r)| f == "f.toml" && r.is_ok()));
    }

    #[test]
    fn with_db_dump_path_rules() {
        let b = std::path::Path::new("/b");
        let p = with_db_dump(b, "R1", Some("R2"), Some("R1")).unwrap();
        assert_eq!(p, b.join("db-R2.sql.gz"));
        let e = with_db_dump(b, "R0", Some("R2"), Some("R1")).unwrap_err();
        assert!(e.downcast_ref::<UsageError>().is_some());
        assert!(
            e.to_string()
                .contains("only rolls back to the previous release (R1)")
        );
        assert!(with_db_dump(b, "R1", None, Some("R1")).is_err());
    }

    #[test]
    fn with_db_only_undoes_the_last_deploy() {
        // After `iwp rollback` from R2 to R1, `previous` is R2: newer than current. Restoring
        // db-R1 would bring back the database as it was before R1, not R2's.
        let b = std::path::Path::new("/b");
        const R1: &str = "20261001-100000-aaaaaaa";
        const R2: &str = "20261002-100000-bbbbbbb";
        let e = with_db_dump(b, R2, Some(R1), Some(R2)).unwrap_err();
        assert!(e.downcast_ref::<UsageError>().is_some());
        assert_eq!(
            e.to_string(),
            "--with-db only undoes the last deploy (target must be older than the current release); restore another state explicitly with iwp db restore"
        );
        assert_eq!(
            with_db_dump(b, R1, Some(R2), Some(R1)).unwrap(),
            b.join(format!("db-{R2}.sql.gz"))
        );
    }

    #[test]
    fn cross_site_blame_needs_an_exact_file_token() {
        let issue = "sites: ba.toml and c.toml share id 1";
        assert!(!names_file(issue, "a.toml"));
        assert!(names_file(issue, "ba.toml"));
        assert!(names_file(issue, "c.toml"));
        assert!(names_file("sites: id clash: a.toml,b.toml", "a.toml"));
        assert!(names_file("sites: id clash: a.toml,b.toml", "b.toml"));
        assert!(names_file("sites: a.toml: duplicate", "a.toml"));
        assert!(!names_file("sites: xa.toml", "a.toml"));
    }
}
