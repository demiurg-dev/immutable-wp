//! `iwp wp`, `iwp shell` and `iwp cron`.

use super::*;

/// `args` Some: `iwp wp`; None: `iwp shell`.
pub(super) fn wp_cmd(
    global: &GlobalConfig,
    name: &str,
    args: Option<&[String]>,
) -> Result<ExitCode> {
    use crate::lifecycle::wpcli::{Entry, podman_cmd, stdio_is_tty};
    let host = SystemHost::new();
    let name = site_arg(name)?;
    let sites = load_valid_sites(global, &[name.to_string()])?;
    let site = loaded_site(&sites, name);
    if let Some(msg) = args.and_then(crate::lifecycle::wpcli::blocked) {
        return Err(UsageError(msg).into());
    }
    require_root(&host, if args.is_some() { "wp" } else { "shell" })?;
    // Match the running container, not site-file edits that are not deployed yet.
    let mut warnings = Vec::new();
    let site = &crate::lifecycle::deploy::deployed_site(&host, global, site, &mut warnings)?;
    print_warnings(&warnings);
    let gateway = crate::host::db::podman_network(&host, &global.podman_network)?.gateway;
    let entry = match args {
        Some(a) => Entry::Wp(a),
        None => Entry::Shell,
    };
    let code = host.run_interactive(&podman_cmd(
        global,
        site,
        gateway,
        entry,
        stdio_is_tty(),
        None,
    ))?;
    Ok(ExitCode::from(code.clamp(0, 255) as u8))
}

/// Upper bound on one cron wp-cli run (podman's own limit; the host kill is the backstop).
pub(super) const CRON_WP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(240);

fn cron_capture_cmd(
    global: &GlobalConfig,
    site: &Site,
    gateway: std::net::Ipv4Addr,
    args: &[String],
) -> crate::host::Cmd {
    use crate::lifecycle::wpcli::{Entry, podman_cmd};
    podman_cmd(
        global,
        site,
        gateway,
        Entry::Capture(args),
        false,
        Some(CRON_WP_TIMEOUT),
    )
    .timeout(CRON_WP_TIMEOUT + std::time::Duration::from_secs(30))
}

pub(super) fn cron_cmd(global: &GlobalConfig, name: &str) -> Result<ExitCode> {
    let host = SystemHost::new();
    let name = site_arg(name)?;
    let sites = load_valid_sites(global, &[name.to_string()])?;
    let site = loaded_site(&sites, name);
    require_root(&host, "cron")?;
    let mut warnings = Vec::new();
    let site = &crate::lifecycle::deploy::deployed_site(&host, global, site, &mut warnings)?;
    print_warnings(&warnings);
    if site.config.multisite.is_none() && site.php.cron == crate::config::CronMode::Fpm {
        // One request over the FPM socket: no container start, and it runs on the warm pool.
        // A network still goes through wp-cli below, which knows every subsite's URL.
        let sock = crate::host::sys(&host, format!("/run/iwp/{}/php.sock", site.name));
        let timeout = std::time::Duration::from_secs(u64::from(site.php.max_execution_time) + 30);
        return Ok(
            match crate::lifecycle::fcgi::cron(&sock, &site.domains[0], timeout) {
                None => ExitCode::SUCCESS,
                Some(problem) => {
                    eprintln!("{problem}");
                    ExitCode::from(1)
                }
            },
        );
    }
    let gateway = crate::host::db::podman_network(&host, &global.podman_network)?.gateway;
    let capture = |args: &[String]| host.run(&cron_capture_cmd(global, site, gateway, args));
    let urls: Vec<Option<String>> = if site.config.multisite.is_some() {
        let out = capture(&crate::lifecycle::wpcli::SITE_LIST.map(String::from))?;
        if out.status != 0 {
            eprint!("{}", String::from_utf8_lossy(&out.stderr));
            return Ok(ExitCode::from(1));
        }
        let urls: Vec<Option<String>> = crate::lifecycle::wpcli::site_urls(&out.stdout)
            .into_iter()
            .map(Some)
            .collect();
        if urls.is_empty() {
            eprintln!("warning: {name}: wp site list returned no URLs; no cron events were run");
        }
        urls
    } else {
        vec![None]
    };
    let mut failed = false;
    for url in urls {
        let mut args: Vec<String> = ["cron", "event", "run", "--due-now"]
            .map(String::from)
            .into();
        if let Some(u) = url {
            args.push(format!("--url={u}"));
        }
        let out = match capture(&args) {
            Ok(o) => o,
            Err(e) => {
                // A hung subsite must not starve the others.
                eprintln!("{e:#}");
                failed = true;
                continue;
            }
        };
        print!("{}", String::from_utf8_lossy(&out.stdout));
        eprint!("{}", String::from_utf8_lossy(&out.stderr));
        failed |= out.status != 0;
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
    fn cron_capture_has_podman_and_host_timeouts() {
        let g = GlobalConfig::default();
        let site = crate::config::parse_site("name = \"kr\"\ndomains = [\"kr.example\"]\nid = 1\n[core]\nwordpress = \"7.1.2\"\nphp = \"8.3\"\n").unwrap();
        let c = cron_capture_cmd(
            &g,
            &site,
            "10.88.0.1".parse().unwrap(),
            &["site".to_string(), "list".to_string()],
        );
        assert!(
            c.args.contains(&"--timeout=240".to_string()),
            "{:?}",
            c.args
        );
        assert_eq!(c.timeout, Some(std::time::Duration::from_secs(270)));
        assert_eq!(CRON_WP_TIMEOUT, std::time::Duration::from_secs(240));
    }
}
