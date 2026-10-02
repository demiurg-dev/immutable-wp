//! `iwp wp` / `iwp shell` / cron: wp-cli in the site's cli image with the site's container
//! identity.

use std::net::Ipv4Addr;
use std::time::Duration;

use crate::config::{GlobalConfig, Site, shared_rel};
use crate::host::Cmd;
use crate::host::identity::Identity;

const CODE_VERBS: &[(&str, &[&str])] = &[
    ("plugin", &["install", "update", "delete", "uninstall"]),
    ("theme", &["install", "update", "delete"]),
    // `core install` only writes the database and stays allowed.
    ("core", &["update", "download"]),
];

pub fn blocked(args: &[String]) -> Option<String> {
    let pos: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|a| !a.starts_with('-'))
        .collect();
    let hit = match pos.as_slice() {
        [cmd, verb, ..]
            if CODE_VERBS
                .iter()
                .any(|(c, vs)| c == cmd && vs.contains(verb)) =>
        {
            true
        }
        ["language", _, verb, ..] => matches!(*verb, "install" | "update" | "uninstall"),
        _ => false,
    };
    hit.then(|| {
        format!(
            "use the site file and `iwp deploy`: wp {} would change code",
            args.join(" ")
        )
    })
}

pub fn volumes(g: &GlobalConfig, site: &Site) -> Vec<String> {
    let base = site.base_dir(g).display().to_string();
    let mut v = Vec::new();
    for d in ["plugins", "themes", "mu-plugins", "languages"] {
        v.push(format!(
            "{base}/current/wp-content/{d}:/var/www/html/wp-content/{d}:ro"
        ));
    }
    for d in site.dropins.keys() {
        v.push(format!(
            "{base}/current/wp-content/{d}:/var/www/html/wp-content/{d}:ro"
        ));
    }
    v.push(format!(
        "{base}/shared/uploads:/var/www/html/wp-content/uploads:rw,noexec,nosuid,nodev"
    ));
    for w in site.writable_paths() {
        v.push(format!(
            "{base}/shared/{}:/var/www/html/{w}:rw,noexec,nosuid,nodev",
            shared_rel(w)
        ));
    }
    v.push(format!(
        "{base}/config/wp-config.site.php:/etc/iwp/wp-config.site.php:ro"
    ));
    v.push(format!(
        "{base}/config/zz-site.ini:/usr/local/etc/php/conf.d/zz-site.ini:ro"
    ));
    v.push(format!(
        "{base}/config/zz-site.conf:/usr/local/etc/php-fpm.d/zz-site.conf:ro"
    ));
    v
}

/// Arguments that list a network's sites, one URL per line.
pub const SITE_LIST: [&str; 3] = ["site", "list", "--field=url"];

/// The URLs in the output of `wp site list --field=url`.
pub fn site_urls(stdout: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(stdout)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

pub enum Entry<'a> {
    Wp(&'a [String]),
    Shell,
    Capture(&'a [String]),
}

pub fn podman_cmd(
    g: &GlobalConfig,
    site: &Site,
    gateway: Ipv4Addr,
    entry: Entry,
    tty: bool,
    timeout: Option<Duration>,
) -> Cmd {
    let id = Identity::for_site(site.id, g.id_offset);
    let n = &site.name;
    let mut c = Cmd::new("podman").args(["run", "--rm", "--pull=never"]);
    if let Some(t) = timeout {
        // Podman's own limit: conmon kills the container itself, so the host-side watchdog
        // (which only kills the podman client) stays a backstop.
        c = c.arg(format!("--timeout={}", t.as_secs()));
    }
    if !matches!(entry, Entry::Capture(_)) {
        c = c.arg("-i");
        if tty {
            c = c.arg("-t");
        }
    }
    c = c.args([
        "--read-only".to_string(),
        "--tmpfs".into(),
        format!(
            "/tmp:rw,size={},mode=1777,noexec,nosuid,nodev",
            site.tmp_size()
        ),
        "--cap-drop=all".into(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--uidmap".into(),
        format!("0:{}:65536", id.base_id),
        "--gidmap".into(),
        format!("0:{}:65536", id.base_id),
        "--security-opt".into(),
        format!("label=level:{}", id.selinux_level()),
        "--network".into(),
        g.podman_network.clone(),
        "--add-host".into(),
        format!("iwp-db-host:{gateway}"),
        "--secret".into(),
        format!("iwp-{n}-db,type=mount,target=iwp-db,uid=33,gid=33,mode=0400"),
        "--secret".into(),
        format!("iwp-{n}-salts,type=mount,target=iwp-salts,uid=33,gid=33,mode=0400"),
        "-e".into(),
        "HOME=/tmp".into(),
        "-e".into(),
        "WP_CLI_CACHE_DIR=/tmp/wp-cli-cache".into(),
        "-w".into(),
        "/var/www/html".into(),
    ]);
    for v in volumes(g, site) {
        c = c.args(["-v".to_string(), v]);
    }
    for m in &site.wpcli.mounts {
        let m = m.display();
        c = c.args(["-v".to_string(), format!("{m}:{m}:ro")]);
    }
    c = c.arg(site.cli_image());
    match entry {
        Entry::Shell => c.arg("bash"),
        Entry::Wp(a) | Entry::Capture(a) => c
            .args(["wp", "--path=/var/www/html"])
            .args(a.iter().cloned()),
    }
}

pub fn stdio_is_tty() -> bool {
    // SAFETY: isatty has no preconditions.
    unsafe { libc::isatty(0) == 1 && libc::isatty(1) == 1 }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_site;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }
    fn site() -> Site {
        parse_site("name = \"kr\"\ndomains = [\"kr.example\"]\nid = 1\n[core]\nwordpress = \"7.1.2\"\nphp = \"8.3\"\n[wpcli]\nmounts = [\"/srv/iwp/migration\"]\n[[plugin]]\nslug = \"wordfence\"\nversion = \"8.1.0\"\nwritable = [\"wp-content/wflogs\"]\n").unwrap()
    }

    #[test]
    fn interception() {
        for a in [
            &["plugin", "install", "x"][..],
            &["--skip-plugins", "plugin", "update", "--all"],
            &["theme", "delete", "t"],
            &["core", "update"],
            &["core", "download"],
            &["language", "core", "install", "hr"],
            &["language", "plugin", "update", "--all"],
            &["plugin", "uninstall", "x"],
        ] {
            let m = blocked(&s(a)).unwrap_or_else(|| panic!("{a:?} not blocked"));
            assert!(m.contains("iwp deploy"), "{m}");
        }
        for a in [
            &["plugin", "list"][..],
            &["plugin", "is-active", "x"],
            &["plugin", "activate", "x"],
            &["option", "get", "home"],
            &["eval-file", "/srv/iwp/migration/a.php", "--skip-plugins"],
            &["core", "update-db"],
            &["core", "version"],
            // Install only writes the database (a new site's first deploy needs it).
            &["core", "install", "--url=https://a.example", "--title=T"],
            &["core", "multisite-install", "--url=https://a.example"],
            &["language", "core", "list"],
            &["search-replace", "plugin install", "x"],
        ] {
            assert!(blocked(&s(a)).is_none(), "{a:?} blocked");
        }
    }

    #[test]
    fn volumes_match_quadlet() {
        let g = GlobalConfig::default();
        let site = site();
        let quadlet = crate::render::render_site(&g, &site, &crate::render::RenderEnv::default())
            .unwrap()["containers/iwp-kr.container"]
            .clone();
        let q: Vec<String> = quadlet
            .lines()
            .filter_map(|l| l.strip_prefix("Volume="))
            .map(String::from)
            .filter(|v| !v.starts_with("/run/iwp/"))
            .collect();
        assert_eq!(volumes(&g, &site), q);
    }

    #[test]
    fn podman_command_shape() {
        let g = GlobalConfig::default();
        let args = s(&["eval-file", "/srv/iwp/migration/x y.php", "--skip-plugins"]);
        let c = podman_cmd(
            &g,
            &site(),
            "10.88.0.1".parse().unwrap(),
            Entry::Wp(&args),
            true,
            None,
        );
        let a = c.args.join(" ");
        assert_eq!(c.program, "podman");
        assert!(a.starts_with("run --rm --pull=never -i -t "), "{a}");
        let id = crate::host::identity::Identity::for_site(1, g.id_offset);
        let uid = format!("--uidmap 0:{}:65536", id.base_id);
        let gid = format!("--gidmap 0:{}:65536", id.base_id);
        for want in [
            "--read-only",
            "--tmpfs /tmp:rw,size=1G,mode=1777,noexec,nosuid,nodev",
            "--cap-drop=all",
            "--security-opt no-new-privileges",
            uid.as_str(),
            gid.as_str(),
            "--security-opt label=level:s0:c1,c513",
            "--network podman",
            "--add-host iwp-db-host:10.88.0.1",
            "--secret iwp-kr-db,type=mount,target=iwp-db,uid=33,gid=33,mode=0400",
            "--secret iwp-kr-salts,type=mount,target=iwp-salts,uid=33,gid=33,mode=0400",
            "-v /srv/iwp/migration:/srv/iwp/migration:ro",
            "-e HOME=/tmp",
            "localhost/iwp-cli:7.1.2-php8.3 wp --path=/var/www/html eval-file",
        ] {
            assert!(a.contains(want), "missing {want:?} in {a}");
        }
        // The argument with a space stays one argv element.
        assert!(c.args.contains(&"/srv/iwp/migration/x y.php".to_string()));
        assert!(!a.contains("--timeout"), "{a}");
        let c = podman_cmd(
            &g,
            &site(),
            "10.88.0.1".parse().unwrap(),
            Entry::Capture(&args),
            true,
            None,
        );
        assert!(!c.args.contains(&"-i".to_string()) && !c.args.contains(&"-t".to_string()));
        let c = podman_cmd(
            &g,
            &site(),
            "10.88.0.1".parse().unwrap(),
            Entry::Shell,
            false,
            None,
        );
        assert!(c.args.ends_with(&[
            "localhost/iwp-cli:7.1.2-php8.3".to_string(),
            "bash".to_string()
        ]));
        assert!(!c.args.contains(&"-t".to_string()));
    }

    #[test]
    fn podman_run_timeout_precedes_the_image() {
        let g = GlobalConfig::default();
        let args = s(&["option", "get", "home"]);
        let c = podman_cmd(
            &g,
            &site(),
            "10.88.0.1".parse().unwrap(),
            Entry::Capture(&args),
            false,
            Some(std::time::Duration::from_secs(1800)),
        );
        let t = c.args.iter().position(|a| a == "--timeout=1800").unwrap();
        let img = c
            .args
            .iter()
            .position(|a| a == "localhost/iwp-cli:7.1.2-php8.3")
            .unwrap();
        assert!(t < img, "{:?}", c.args);
    }
}
