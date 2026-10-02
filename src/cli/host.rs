//! Host integration commands: nginx, db, selinux.

use super::*;

pub(super) fn nginx_cmd(global: &GlobalConfig, action: NginxAction) -> Result<ExitCode> {
    let host = SystemHost::new();
    match action {
        NginxAction::Apply { site } => {
            let name = site_arg(&site)?;
            let sites = load_valid_sites(global, &[name.to_string()])?;
            let site = loaded_site(&sites, name);
            require_root(&host, "nginx apply")?;
            crate::host::nginx::check_worker_group(&host, global)?;
            // The include only follows symlinks owned by their target's owner, and needs the
            // current policy module to check that; see `deploy::own_release_links`.
            crate::host::selinux::install_module(&host)?;
            let mut warnings = Vec::new();
            crate::lifecycle::deploy::own_current_links(&host, global, site, &mut warnings)?;
            print_warnings(&warnings);
            let _l = crate::host::lock::NginxLock::acquire(&host)?;
            // The nginx files do not depend on the DB host address.
            let rendered = render_site(global, site, &RenderEnv::default())?;
            if crate::host::nginx::apply(&host, global, site, &rendered)? {
                println!("nginx: updated");
            } else {
                println!("nginx: unchanged");
            }
            Ok(ExitCode::SUCCESS)
        }
        NginxAction::Check { site } => {
            let name = site_arg(&site)?;
            let sites = load_valid_sites(global, &[name.to_string()])?;
            let site = loaded_site(&sites, name);
            let problems = crate::host::nginx::check(&host, site)?;
            if problems.is_empty() {
                println!("nginx: ok");
                Ok(ExitCode::SUCCESS)
            } else {
                for p in &problems {
                    println!("{p}");
                }
                Ok(ExitCode::from(1))
            }
        }
    }
}

/// The restore source must be an existing regular file starting with the gzip magic.
fn check_gzip_source(path: &std::path::Path) -> Result<()> {
    use std::io::Read;
    if !path.exists() {
        return Err(UsageError(format!("restore source {} does not exist", path.display())).into());
    }
    if !path.is_file() {
        return Err(UsageError(format!(
            "restore source {} is not a regular file",
            path.display()
        ))
        .into());
    }
    let mut magic = [0u8; 2];
    let ok = std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .is_ok()
        && magic == [0x1f, 0x8b];
    if !ok {
        return Err(UsageError(format!(
            "restore source {} is not a gzip file",
            path.display()
        ))
        .into());
    }
    Ok(())
}

/// `iwp db dump` once its arguments are checked. Holds the site lock so a dump never runs
/// against a deploy, update or rollback in progress; it is taken here and not in `host::db`,
/// because those commands call `host::db::dump` under their own (non-re-entrant) lock.
fn db_dump(
    host: &dyn Host,
    global: &GlobalConfig,
    site: &Site,
    out: Option<PathBuf>,
) -> Result<PathBuf> {
    let _lock = crate::host::lock::SiteLock::acquire(host, &site.name)?;
    let ident = crate::host::db::DbIdent::from_site(site)?;
    let dest = match out {
        Some(p) => absolute(p)?,
        None => backups_dir(global, site)?.join(format!("db-{}.sql.gz", timestamp())),
    };
    crate::host::db::dump(host, global, &ident, &dest)?;
    Ok(dest)
}

/// `iwp db restore` once its arguments are checked, under the site lock (see `db_dump`).
fn db_restore(
    host: &dyn Host,
    global: &GlobalConfig,
    site: &Site,
    file: &std::path::Path,
) -> Result<()> {
    let _lock = crate::host::lock::SiteLock::acquire(host, &site.name)?;
    let ident = crate::host::db::DbIdent::from_site(site)?;
    crate::host::db::validate_dump_source(file)?;
    let safety = backups_dir(global, site)?.join(format!("db-pre-restore-{}.sql.gz", timestamp()));
    crate::host::db::dump(host, global, &ident, &safety)?;
    println!("safety dump: {}", safety.display());
    crate::host::db::restore(host, global, &ident, file)?;
    println!("restored from: {}", file.display());
    Ok(())
}

pub(super) fn db_cmd(global: &GlobalConfig, action: DbAction) -> Result<ExitCode> {
    let host = SystemHost::new();
    match action {
        DbAction::Dump { site, out } => {
            let name = site_arg(&site)?;
            let sites = load_valid_sites(global, &[name.to_string()])?;
            let site = loaded_site(&sites, name);
            crate::host::db::DbIdent::from_site(site)?;
            require_root(&host, "db dump")?;
            let dest = db_dump(&host, global, site, out)?;
            println!("{}", dest.display());
        }
        DbAction::Restore { site, file, yes } => {
            let name = site_arg(&site)?;
            let sites = load_valid_sites(global, &[name.to_string()])?;
            let site = loaded_site(&sites, name);
            if !yes {
                return Err(UsageError(format!(
                    "refusing to restore without --yes (this overwrites the database of {name})"
                ))
                .into());
            }
            require_root(&host, "db restore")?;
            let file = absolute(file)?;
            check_gzip_source(&file)?;
            db_restore(&host, global, site, &file)?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

pub(super) fn selinux_cmd(action: SelinuxAction) -> Result<ExitCode> {
    let host = SystemHost::new();
    match action {
        SelinuxAction::Install => {
            require_root(&host, "selinux install")?;
            if crate::host::selinux::install_module(&host)? {
                println!("selinux: module installed");
            } else if crate::host::selinux::enabled(&host)? {
                println!("selinux: module up to date");
            } else {
                println!("selinux: disabled on this host");
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn global_or_usage(global: &GlobalConfig) -> Result<()> {
    let issues: Vec<String> = validate_global(global)
        .into_iter()
        .map(|i| format!("iwp.toml: {i}"))
        .collect();
    if issues.is_empty() {
        Ok(())
    } else {
        Err(UsageError(issues.join("\n")).into())
    }
}

pub(super) fn egress_cmd(global: &GlobalConfig, action: EgressAction) -> Result<ExitCode> {
    use crate::host::egress::{Applied, apply, ruleset};
    let host = SystemHost::new();
    global_or_usage(global)?;
    match action {
        EgressAction::Show => {
            let net = crate::host::db::podman_network(&host, &global.podman_network)?;
            print!("{}", ruleset(&net, &global.egress)?);
            if !global.egress.restrict {
                eprintln!(
                    "note: [egress] restrict is false; `iwp egress apply` would load nothing"
                );
            }
        }
        EgressAction::Apply => {
            require_root(&host, "egress apply")?;
            match apply(&host, global)? {
                Applied::Loaded => println!(
                    "egress: filter loaded for network {} (iwp-egress.service, enabled at boot)",
                    global.podman_network
                ),
                Applied::Removed => println!("egress: filter removed ([egress] restrict = false)"),
                Applied::Off => println!("egress: not restricted ([egress] restrict = false)"),
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

pub(super) fn alert_cmd(global: &GlobalConfig, unit: &str) -> Result<ExitCode> {
    let host = SystemHost::new();
    if !crate::host::alert::valid_unit(unit) {
        return Err(UsageError(format!("not an iwp unit: {unit:?}")).into());
    }
    global_or_usage(global)?;
    if crate::host::alert::send(&host, global, unit)? {
        println!("alert: mailed {unit}");
    } else {
        println!("alert: no alert_email in iwp.toml; nothing sent for {unit}");
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site_a() -> Site {
        crate::config::parse_site(
            "name = \"a\"\ndomains = [\"a.example\"]\nid = 1\n[core]\nwordpress = \"7.1.2\"\nphp = \"8.3\"\n",
        )
        .unwrap()
    }

    #[test]
    fn db_restore_and_dump_refuse_while_the_site_is_busy() {
        // A deploy (or update, rollback) holds the site lock: neither runs any command.
        let h = crate::testutil::RecordingHost::new(true);
        let g = GlobalConfig::default();
        let site = site_a();
        let _held = crate::host::lock::SiteLock::acquire(&h, "a").unwrap();
        let src = h.sysroot().join("x.sql.gz");
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, b"INSERT 1;\n").unwrap();
        std::fs::write(&src, gz.finish().unwrap()).unwrap();
        let e = db_restore(&h, &g, &site, &src).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "another iwp operation on a is in progress"
        );
        let e = db_dump(&h, &g, &site, Some(h.sysroot().join("d.sql.gz"))).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "another iwp operation on a is in progress"
        );
        assert!(h.calls().is_empty(), "{:?}", h.calls());
    }

    #[test]
    fn gzip_source_validation() {
        let d = tempfile::tempdir().unwrap();
        let missing = d.path().join("nope.gz");
        let e = check_gzip_source(&missing).unwrap_err().to_string();
        assert!(e.contains("does not exist"), "{e}");
        let e = check_gzip_source(d.path()).unwrap_err().to_string();
        assert!(e.contains("not a regular file"), "{e}");
        let bad = d.path().join("bad.sql.gz");
        std::fs::write(&bad, "SELECT 1;").unwrap();
        let e = check_gzip_source(&bad).unwrap_err().to_string();
        assert!(e.contains("is not a gzip file"), "{e}");
        let short = d.path().join("short.gz");
        std::fs::write(&short, [0x1f]).unwrap();
        assert!(check_gzip_source(&short).is_err());
        let ok = d.path().join("ok.sql.gz");
        std::fs::write(&ok, [0x1f, 0x8b, 8, 0]).unwrap();
        assert!(check_gzip_source(&ok).is_ok());
    }
}
