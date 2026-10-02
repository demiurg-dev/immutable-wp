//! Host provisioning for a site.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::config::{GlobalConfig, LoadedSite, Site, parse_site, validate_all, validate_global};
use crate::host::db::{DbIdent, PodmanNet};
use crate::host::identity::Identity;
use crate::host::secrets::{self, DbSecret};
use crate::host::{Cmd, Host, run_ok, sys};
use crate::render::{RenderEnv, render_site};

fn usage(msg: impl Into<String>) -> anyhow::Error {
    crate::error::UsageError(msg.into()).into()
}

/// An /etc/subuid or /etc/subgid entry overlapping the ID range of site id `id`.
struct SubidConflict {
    /// `<file>:<line>: <name>:<start>:<count>`
    entry: String,
    lo: u64,
    hi: u64,
}

fn subid_conflict(host: &dyn Host, g: &GlobalConfig, id: u32) -> Result<Option<SubidConflict>> {
    let ident = Identity::for_site(id, g.id_offset);
    let (lo, hi) = (u64::from(ident.base_id), u64::from(ident.base_id) + 65_536);
    for f in ["/etc/subuid", "/etc/subgid"] {
        let text = match std::fs::read_to_string(sys(host, f)) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e).with_context(|| format!("reading {f}")),
        };
        for (n, line) in text.lines().enumerate() {
            let p: Vec<&str> = line.trim().split(':').collect();
            let [name, start, count] = p[..] else {
                continue;
            };
            let (Ok(s), Ok(c)) = (start.parse::<u64>(), count.parse::<u64>()) else {
                continue;
            };
            let Some(end) = s.checked_add(c) else {
                continue;
            };
            if c > 0 && s < hi && lo < end {
                return Ok(Some(SubidConflict {
                    entry: format!("{f}:{}: {name}:{s}:{c}", n + 1),
                    lo,
                    hi,
                }));
            }
        }
    }
    Ok(None)
}

pub fn check_subids(host: &dyn Host, g: &GlobalConfig, site: &Site) -> Result<()> {
    if let Some(c) = subid_conflict(host, g, site.id)? {
        bail!(
            "{} overlaps site {}'s ID range {}..{}; change id_offset in iwp.toml or the site id",
            c.entry,
            site.name,
            c.lo,
            c.hi
        );
    }
    Ok(())
}

/// Where `setup` takes the site's secrets from.
#[derive(Default)]
pub struct SetupOpts<'a> {
    /// Import the 8 keys/salts from this wp-config.php.
    pub salts_from: Option<&'a Path>,
    /// Use these keys/salts (takes precedence over `salts_from`).
    pub salts: Option<BTreeMap<String, String>>,
    /// Use this DB password (overrides an existing secret's password and is written into it).
    pub db_password: Option<String>,
}

impl std::fmt::Debug for SetupOpts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetupOpts")
            .field("salts_from", &self.salts_from)
            .field("salts", &self.salts.as_ref().map(|_| "<redacted>"))
            .field(
                "db_password",
                &self.db_password.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

pub fn setup(
    host: &dyn Host,
    g: &GlobalConfig,
    site: &Site,
    opts: &SetupOpts,
    net: &PodmanNet,
) -> Result<()> {
    // Before any change: a base nginx cannot enter serves 403/502 although everything else
    // succeeds.
    crate::host::nginx::check_worker_group(host, g)?;
    check_subids(host, g, site)?;
    // Read before any change; never through a symlink (it is read as root).
    let salts_from = match (&opts.salts, opts.salts_from) {
        (None, Some(p)) => Some(secrets::import_salts(
            &crate::host::fsx::read_regular_file(p)?,
        )?),
        _ => None,
    };
    let ident = DbIdent::from_site(site)?;
    let (db_secret, salts_secret) = secrets::secret_names(&site.name);
    let stored = stored_db_secret(host, &site.name)?;
    check_db_user_free(host, g, &ident.user, stored.as_ref(), net)?;
    eprintln!("[{}] directories", site.name);
    crate::host::layout::prepare_site_dirs(host, g, site)?;

    eprintln!("[{}] database", site.name);
    // A stored secret counts only when it is this user's: one left behind for another user
    // (a failed import of the old site's account, then `--new-db-user`) is not this account's
    // password and must not become it.
    let stored = stored.filter(|s| s.user == ident.user);
    let first_setup = stored.is_none();
    let password = match (&opts.db_password, stored) {
        (Some(p), _) => p.clone(),
        (None, Some(s)) => s.password,
        (None, None) => secrets::generate_password()?,
    };
    let s = DbSecret {
        name: ident.name.clone(),
        user: ident.user.clone(),
        password,
        host: "iwp-db-host".into(),
        prefix: site.db_prefix().to_string(),
    };
    // Validate before any side effect.
    let rendered_secret = s.render()?;
    // On a first setup the secret goes first: once it is stored, a re-run knows the account
    // is this site's. Creating the account first would leave, if storing then fails, an
    // account that the re-run refuses as "exists and no iwp site owns it". Re-runs
    // keep the usual order (database, then secrets).
    if first_setup {
        secrets::store_secret(host, &db_secret, rendered_secret.as_bytes())?;
    }
    crate::host::db::ensure_database(host, g, &ident, &s.password, net)?;

    eprintln!("[{}] secrets", site.name);
    if !first_setup {
        secrets::store_secret(host, &db_secret, rendered_secret.as_bytes())?;
    }
    // Precedence: explicit salts, then salts_from, then keep existing, then generate.
    if let Some(values) = &opts.salts {
        let salts = secrets::render_salts(values)?;
        secrets::store_secret(host, &salts_secret, salts.as_bytes())?;
    } else if let Some(values) = &salts_from {
        let salts = secrets::render_salts(values)?;
        secrets::store_secret(host, &salts_secret, salts.as_bytes())?;
    } else if !secrets::secret_exists(host, &salts_secret)? {
        secrets::store_secret(host, &salts_secret, secrets::generate_salts()?.as_bytes())?;
    }

    eprintln!("[{}] selinux", site.name);
    crate::host::selinux::install_module(host)?;
    crate::host::selinux::label_site(host, g, site)?;

    eprintln!("[{}] config and tmpfiles", site.name);
    let env = RenderEnv {
        db_host_ip: net.gateway,
        ..RenderEnv::default()
    };
    let rendered = render_site(g, site, &env)?;
    crate::host::install::install_rendered(host, g, site, &rendered, &|k| {
        k.starts_with("config/") || k.starts_with("tmpfiles/")
    })?;
    run_ok(host, &Cmd::new("systemctl").arg("daemon-reload"))?;
    run_ok(
        host,
        &Cmd::new("systemd-tmpfiles").args([
            "--create".to_string(),
            crate::host::install::SHARED_TMPFILES_PATH.to_string(),
            format!("/etc/tmpfiles.d/iwp-{}.conf", site.name),
        ]),
    )?;
    let run_dir = std::path::PathBuf::from(format!("/run/iwp/{}", site.name));
    crate::host::selinux::relabel(host, &[run_dir.as_path()])?;
    Ok(())
}

/// The site's stored DB secret, parsed; `None` when it does not exist.
pub fn stored_db_secret(host: &dyn Host, site: &str) -> Result<Option<DbSecret>> {
    let (db_secret, _) = secrets::secret_names(site);
    secrets::read_secret(host, &db_secret)?
        .map(|b| DbSecret::parse(&String::from_utf8(b).context("DB secret is not UTF-8")?))
        .transpose()
}

/// Refuses (usage error) when `'<user>'@'<podman subnet>'` already exists in MariaDB and this
/// site does not own it: setup would otherwise change the password of an account another
/// application (or another site) uses. A re-run of the same site, whose stored DB
/// secret names that user, may keep it.
pub fn check_db_user_free(
    host: &dyn Host,
    g: &GlobalConfig,
    user: &str,
    stored: Option<&DbSecret>,
    net: &PodmanNet,
) -> Result<()> {
    if stored.is_some_and(|s| s.user == user) {
        return Ok(());
    }
    if crate::host::db::user_exists(host, g, user, net)? {
        return Err(crate::error::UsageError(format!(
            "the MariaDB account '{user}'@'{}' already exists and no iwp site owns it; iwp would change its password. Use another database user ([database] user in the site file; for iwp import: --new-db-user), or drop the account if it is a leftover",
            net.host_pattern()
        ))
        .into());
    }
    Ok(())
}

/// Highest site id (`validate_site`: 1..=511; the SELinux categories are derived from it).
const MAX_SITE_ID: u32 = 511;

/// The id arithmetic below needs a sane `id_offset`; an invalid iwp.toml is a usage error here,
/// not an overflow later.
fn check_global(g: &GlobalConfig) -> Result<()> {
    let issues: Vec<String> = validate_global(g)
        .into_iter()
        .map(|i| format!("iwp.toml: {i}"))
        .collect();
    if issues.is_empty() {
        Ok(())
    } else {
        Err(usage(issues.join("\n")))
    }
}

/// The next free site id: above every existing one (ids are never reused) and with an ID
/// range that no /etc/subuid or /etc/subgid entry overlaps, so `setup` will accept it.
pub fn next_id(host: &dyn Host, g: &GlobalConfig, sites: &[LoadedSite]) -> Result<u32> {
    check_global(g)?;
    let start = sites.iter().map(|l| l.site.id).max().unwrap_or(0) + 1;
    for id in start..=MAX_SITE_ID {
        if subid_conflict(host, g, id)?.is_none() {
            return Ok(id);
        }
    }
    Err(usage(format!(
        "no free site id in {start}..={MAX_SITE_ID}: every remaining ID range overlaps /etc/subuid or /etc/subgid (or the ids are used up); change id_offset in iwp.toml"
    )))
}

/// `wanted` (an explicit `--id`) if its ID range is free, else the next free id.
pub fn pick_id(
    host: &dyn Host,
    g: &GlobalConfig,
    sites: &[LoadedSite],
    wanted: Option<u32>,
) -> Result<u32> {
    let Some(id) = wanted else {
        return next_id(host, g, sites);
    };
    check_global(g)?;
    if !(1..=MAX_SITE_ID).contains(&id) {
        return Err(usage(format!("--id {id} must be in 1..={MAX_SITE_ID}")));
    }
    if let Some(c) = subid_conflict(host, g, id)? {
        return Err(usage(format!(
            "{} overlaps the ID range {}..{} of --id {id}; choose another id or change id_offset in iwp.toml",
            c.entry, c.lo, c.hi
        )));
    }
    Ok(id)
}

/// The existing site files; a missing `sites_dir` (a fresh host) means there are none yet.
pub fn existing_sites(g: &GlobalConfig) -> Result<Vec<LoadedSite>> {
    if !g.sites_dir.exists() {
        return Ok(Vec::new());
    }
    crate::config::load_sites_dir(&g.sites_dir).map_err(|e| usage(format!("{e:#}")))
}

/// Creates `sites_dir` (0755 root) on a fresh host; an existing one is left as it is.
pub fn ensure_sites_dir(host: &dyn Host, g: &GlobalConfig) -> Result<()> {
    if g.sites_dir.exists() {
        return Ok(());
    }
    crate::host::fsx::ensure_dir(host, &g.sites_dir, 0o755, Some((0, 0)))
}

/// Validates `text` as the new site among all existing ones, as `iwp new` does.
pub fn validate_new(
    g: &GlobalConfig,
    mut all: Vec<LoadedSite>,
    name: &str,
    text: &str,
    path: &Path,
) -> Result<Site> {
    let site = parse_site(text).map_err(|e| usage(format!("generated site file: {e:#}")))?;
    all.push(LoadedSite {
        path: path.to_path_buf(),
        site,
    });
    let issues: Vec<String> = validate_global(g)
        .into_iter()
        .map(|i| format!("iwp.toml: {i}"))
        .chain(
            validate_all(&all, g)
                .into_iter()
                .map(|i| i.to_string())
                .filter(|t| t.starts_with("sites:") || t.starts_with(&format!("{name}.toml:"))),
        )
        .collect();
    if !issues.is_empty() {
        return Err(usage(issues.join("\n")));
    }
    Ok(all.pop().expect("just pushed").site)
}

/// Installs the site file without clobbering an existing one (hard link of a temp file).
pub fn install_site_file(g: &GlobalConfig, name: &str, text: &str, path: &Path) -> Result<()> {
    let tmp = g.sites_dir.join(format!(".{name}.toml.new"));
    fs::write(&tmp, text).with_context(|| format!("writing {}", tmp.display()))?;
    let linked = fs::hard_link(&tmp, path);
    let _ = fs::remove_file(&tmp);
    linked.map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            usage(format!("site file {} already exists", path.display()))
        } else {
            anyhow::anyhow!("installing {}: {e}", path.display())
        }
    })
}

/// What `iwp new` creates.
#[derive(Debug, Clone)]
pub struct NewSite<'a> {
    pub name: &'a str,
    pub domains: &'a [String],
    pub base: Option<&'a Path>,
    pub wordpress: &'a str,
    pub php: &'a str,
    /// An explicit site id; `None` takes the next free one.
    pub id: Option<u32>,
}

/// `iwp new`'s site file: the nginx worker check first (nothing is written when it fails),
/// then, under the host-wide sites lock, the id assignment, validation and installation
/// (never clobbering).
pub fn create_site_file(host: &dyn Host, g: &GlobalConfig, n: &NewSite) -> Result<LoadedSite> {
    crate::host::nginx::check_worker_group(host, g)?;
    let path = g.sites_dir.join(format!("{}.toml", n.name));
    // Id assignment and installation under the host-wide lock (two creations, one id).
    let _sites = crate::host::lock::SitesLock::acquire(host)?;
    let existing = existing_sites(g)?;
    let id = pick_id(host, g, &existing, n.id)?;
    let text = new_site_text(n.name, n.domains, n.base, id, n.wordpress, n.php);
    let site = validate_new(g, existing, n.name, &text, &path)?;
    ensure_sites_dir(host, g)?;
    install_site_file(g, n.name, &text, &path)?;
    Ok(LoadedSite { path, site })
}

pub fn new_site_text(
    name: &str,
    domains: &[String],
    base: Option<&Path>,
    id: u32,
    wordpress: &str,
    php: &str,
) -> String {
    let q = |s: &str| format!("{s:?}");
    let mut t = format!(
        "# Created by `iwp new`. Edit, then `iwp deploy {}`.\nname = {}\n",
        q(name),
        q(name)
    );
    if let Some(b) = base {
        t.push_str(&format!("base = {}\n", q(&b.display().to_string())));
    }
    let ds: Vec<String> = domains.iter().map(|d| q(d)).collect();
    t.push_str(&format!(
        "domains = [{}]\nid = {id}\n\n[core]\nwordpress = {}\nphp = {}\nlanguages = []\n",
        ds.join(", "),
        q(wordpress),
        q(php)
    ));
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_site;
    use crate::host::sys;
    use crate::testutil::RecordingHost;

    fn site() -> Site {
        parse_site("name = \"kr\"\ndomains = [\"kr.example\"]\nid = 1\n[core]\nwordpress = \"7.1.2\"\nphp = \"8.3\"\n[database]\nname = \"legacy_portal\"\nuser = \"iwp_kr\"\ncharset = \"utf8\"\n").unwrap()
    }
    fn net() -> crate::host::db::PodmanNet {
        crate::host::db::PodmanNet {
            subnet: "10.88.0.0".parse().unwrap(),
            prefix: 16,
            gateway: "10.88.0.1".parse().unwrap(),
        }
    }
    fn g() -> GlobalConfig {
        GlobalConfig {
            base_root: std::path::PathBuf::from("/srv/www"),
            id_offset: 1_000_000,
            ..GlobalConfig::default()
        }
    }

    #[test]
    fn subid_overlap_is_refused() {
        let h = RecordingHost::new(true);
        std::fs::create_dir_all(sys(&h, "/etc")).unwrap();
        std::fs::write(
            sys(&h, "/etc/subuid"),
            "alice:100000:65536\nbig:1000000:200000\n",
        )
        .unwrap();
        let e = check_subids(&h, &g(), &site()).unwrap_err();
        assert!(
            format!("{e}").contains("/etc/subuid") && format!("{e}").contains("big"),
            "{e}"
        );
        std::fs::write(sys(&h, "/etc/subuid"), "alice:100000:196608\n").unwrap();
        check_subids(&h, &g(), &site()).unwrap();
    }

    #[test]
    fn setup_order_and_secret_reuse() {
        let existing = "DB_NAME=legacy_portal\nDB_USER=iwp_kr\nDB_PASSWORD=keepme\nDB_HOST=iwp-db-host\nDB_PREFIX=wp_\n";
        let h = RecordingHost::new(true)
            .respond(
                "podman secret inspect --showsecret --format {{.SecretData}} iwp-kr-db",
                0,
                existing,
                "",
            )
            .respond("podman secret exists iwp-kr-salts", 0, "", "");
        setup(&h, &g(), &site(), &SetupOpts::default(), &net()).unwrap();
        let calls: Vec<String> = h.calls().iter().map(|c| c.to_string()).collect();
        let pos = |p: &str| {
            calls
                .iter()
                .position(|c| c.starts_with(p))
                .unwrap_or_else(|| panic!("{p} missing: {calls:#?}"))
        };
        // DB before secrets, secrets before selinux, daemon-reload before tmpfiles create.
        assert!(pos("mariadb") < pos("podman secret create --replace iwp-kr-db -"));
        assert!(pos("podman secret create --replace iwp-kr-db -") < pos("semodule"));
        assert!(pos("systemctl daemon-reload") < pos("systemd-tmpfiles --create"));
        let sql = String::from_utf8(h.calls()[pos("mariadb")].stdin.clone().unwrap()).unwrap();
        assert!(
            sql.contains("'keepme'")
                && sql.contains("`legacy_portal`")
                && sql.contains("'iwp_kr'@'10.88.0.0/255.255.0.0'")
        );
        // Existing salts kept: no salts secret written.
        assert!(
            !calls
                .iter()
                .any(|c| c.starts_with("podman secret create --replace iwp-kr-salts"))
        );
        // Neither the quadlet nor timers installed by setup.
        assert!(!sys(&h, "/etc/containers/systemd/iwp-kr.container").exists());
        assert!(sys(&h, "/etc/tmpfiles.d/iwp-kr.conf").exists());
        assert!(sys(&h, "/srv/www/kr/config/wp-config.site.php").exists());
        let db_secret = h
            .calls()
            .into_iter()
            .find(|c| {
                c.to_string()
                    .starts_with("podman secret create --replace iwp-kr-db")
            })
            .unwrap();
        assert!(
            String::from_utf8(db_secret.stdin.unwrap())
                .unwrap()
                .contains("DB_PASSWORD=keepme")
        );
    }

    #[test]
    fn setup_generates_missing_secrets_and_imports_salts() {
        let h = RecordingHost::new(true)
            .respond(
                "podman secret inspect --showsecret",
                125,
                "",
                "Error: no such secret",
            )
            .respond("podman secret exists iwp-kr-salts", 1, "", "")
            .respond(
                "mariadb --socket=/var/lib/mysql/mysql.sock --batch --skip-column-names",
                0,
                "0\n",
                "",
            );
        let cfg = h.sysroot().join("old-wp-config.php");
        let defs: String = crate::host::secrets::SALT_KEYS
            .iter()
            .map(|k| format!("define('{k}','v-{k}');\n"))
            .collect();
        std::fs::write(&cfg, format!("<?php\n{defs}")).unwrap();
        setup(
            &h,
            &g(),
            &site(),
            &SetupOpts {
                salts_from: Some(&cfg),
                ..SetupOpts::default()
            },
            &net(),
        )
        .unwrap();
        let salts = h
            .calls()
            .into_iter()
            .find(|c| {
                c.to_string()
                    .starts_with("podman secret create --replace iwp-kr-salts")
            })
            .unwrap();
        assert!(
            String::from_utf8(salts.stdin.unwrap())
                .unwrap()
                .contains("'v-NONCE_SALT'")
        );
        let db = h
            .calls()
            .into_iter()
            .find(|c| {
                c.to_string()
                    .starts_with("podman secret create --replace iwp-kr-db")
            })
            .unwrap();
        let pw = DbSecret::parse(&String::from_utf8(db.stdin.unwrap()).unwrap())
            .unwrap()
            .password;
        assert_eq!(pw.len(), 64);
    }

    #[test]
    fn new_site_text_validates_and_next_id() {
        let t = new_site_text("blog", &["blog.example".into()], None, 4, "7.1.2", "8.3");
        let s = parse_site(&t).unwrap();
        assert!(crate::config::validate::validate_site(&s, Some("blog")).is_empty());
        assert_eq!(s.id, 4);
    }

    #[test]
    fn nginx_workers_outside_nginx_group_fail_setup_before_any_change() {
        let h = RecordingHost::new(true)
            .respond("nginx -T", 0, "user nginx www-users;\n", "")
            .respond("getent group www-users", 0, "www-users:x:2000:\n", "");
        let e = format!(
            "{:#}",
            setup(&h, &g(), &site(), &SetupOpts::default(), &net()).unwrap_err()
        );
        assert!(
            e.starts_with("nginx workers run as nginx:www-users and are not in group nginx"),
            "{e}"
        );
        let calls: Vec<String> = h.calls().iter().map(|c| c.to_string()).collect();
        assert_eq!(calls[0], "nginx -T");
        assert!(
            calls
                .iter()
                .all(|c| c == "nginx -T" || c.starts_with("getent ") || c.starts_with("id ")),
            "{calls:?}"
        );
        assert!(h.chowns().is_empty());
        assert!(!sys(&h, "/srv/www/kr").exists());
    }

    #[test]
    fn invalid_existing_secret_fails_before_database() {
        let bad = "DB_NAME=legacy_portal\nDB_USER=iwp_kr\nDB_PASSWORD=\n";
        let h = RecordingHost::new(true).respond(
            "podman secret inspect --showsecret --format {{.SecretData}} iwp-kr-db",
            0,
            bad,
            "",
        );
        assert!(setup(&h, &g(), &site(), &SetupOpts::default(), &net()).is_err());
        assert!(
            !h.calls()
                .iter()
                .any(|c| c.to_string().starts_with("mariadb"))
        );
    }

    #[test]
    fn subgid_only_overlap_and_zero_or_overflow_lines() {
        let h = RecordingHost::new(true);
        std::fs::create_dir_all(sys(&h, "/etc")).unwrap();
        std::fs::write(
            sys(&h, "/etc/subuid"),
            "z:1065600:0\no:18446744073709551615:5\n",
        )
        .unwrap();
        std::fs::write(sys(&h, "/etc/subgid"), "grp:1065600:10\n").unwrap();
        let e = check_subids(&h, &g(), &site()).unwrap_err();
        assert!(
            format!("{e}").contains("/etc/subgid") && format!("{e}").contains("grp"),
            "{e}"
        );
    }

    #[test]
    fn new_site_text_comment_is_quoted() {
        let t = new_site_text("a\nb", &["x.example".into()], None, 4, "7.1.2", "8.3");
        assert!(
            t.lines().next().unwrap().starts_with('#') && !t.contains("\nb "),
            "{t}"
        );
        assert_eq!(t.lines().filter(|l| l.starts_with("b")).count(), 0, "{t}");
    }

    fn created(h: &RecordingHost, name: &str) -> Option<String> {
        h.calls()
            .into_iter()
            .find(|c| {
                c.to_string()
                    .starts_with(&format!("podman secret create --replace {name} "))
            })
            .map(|c| String::from_utf8(c.stdin.unwrap()).unwrap())
    }

    #[test]
    fn db_password_overrides_existing_secret() {
        let existing = "DB_NAME=legacy_portal\nDB_USER=iwp_kr\nDB_PASSWORD=keepme\n";
        let h = RecordingHost::new(true)
            .respond(
                "podman secret inspect --showsecret --format {{.SecretData}} iwp-kr-db",
                0,
                existing,
                "",
            )
            .respond("podman secret exists iwp-kr-salts", 0, "", "");
        let pw = "o'ld\\pa$s#wörd";
        let opts = SetupOpts {
            db_password: Some(pw.into()),
            ..SetupOpts::default()
        };
        setup(&h, &g(), &site(), &opts, &net()).unwrap();
        let sql = h
            .calls()
            .into_iter()
            .find(|c| c.program == "mariadb")
            .map(|c| String::from_utf8(c.stdin.unwrap()).unwrap())
            .unwrap();
        assert!(
            sql.contains(&crate::host::db::sql_str(pw)) && !sql.contains("keepme"),
            "{sql}"
        );
        let db = DbSecret::parse(&created(&h, "iwp-kr-db").unwrap()).unwrap();
        assert_eq!(db.password, pw);
        assert!(!format!("{opts:?}").contains("wörd"));
    }

    #[test]
    fn salts_override_salts_from_and_existing() {
        let h = RecordingHost::new(true)
            .respond(
                "podman secret inspect --showsecret",
                125,
                "",
                "no such secret",
            )
            .respond("podman secret exists iwp-kr-salts", 0, "", "")
            .respond(
                "mariadb --socket=/var/lib/mysql/mysql.sock --batch --skip-column-names",
                0,
                "0\n",
                "",
            );
        let salts: std::collections::BTreeMap<String, String> = secrets::SALT_KEYS
            .iter()
            .map(|k| (k.to_string(), format!("x'\\{k}")))
            .collect();
        let cfg = h.sysroot().join("other.php");
        std::fs::write(&cfg, "<?php // no salts here, must not be read").unwrap();
        let opts = SetupOpts {
            salts: Some(salts.clone()),
            salts_from: Some(&cfg),
            db_password: None,
        };
        setup(&h, &g(), &site(), &opts, &net()).unwrap();
        assert_eq!(
            created(&h, "iwp-kr-salts").unwrap(),
            secrets::render_salts(&salts).unwrap()
        );
        assert!(!format!("{opts:?}").contains("x'"));
    }
}

#[cfg(test)]
mod f1_tests {
    use super::*;
    use crate::testutil::RecordingHost;

    #[test]
    fn salts_from_symlink_is_refused_before_any_change() {
        let h = RecordingHost::new(true)
            .respond(
                "podman secret inspect --showsecret",
                125,
                "",
                "no such secret",
            )
            .respond(
                "mariadb --socket=/var/lib/mysql/mysql.sock --batch --skip-column-names",
                0,
                "0\n",
                "",
            );
        let real = h.sysroot().join("real.php");
        let defs: String = crate::host::secrets::SALT_KEYS
            .iter()
            .map(|k| format!("define('{k}','v-{k}');\n"))
            .collect();
        std::fs::write(&real, format!("<?php\n{defs}")).unwrap();
        let link = h.sysroot().join("link.php");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let site = crate::config::parse_site("name = \"kr\"\ndomains = [\"kr.example\"]\nid = 1\n[core]\nwordpress = \"7.1.2\"\nphp = \"8.3\"\n").unwrap();
        let g = GlobalConfig {
            base_root: std::path::PathBuf::from("/srv/www"),
            id_offset: 1_000_000,
            ..GlobalConfig::default()
        };
        let net = crate::host::db::PodmanNet {
            subnet: "10.88.0.0".parse().unwrap(),
            prefix: 16,
            gateway: "10.88.0.1".parse().unwrap(),
        };
        let opts = SetupOpts {
            salts_from: Some(&link),
            ..SetupOpts::default()
        };
        let err = setup(&h, &g, &site, &opts, &net).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            err.downcast_ref::<crate::error::UsageError>().is_some(),
            "{msg}"
        );
        assert!(
            msg.contains(&link.display().to_string()) && msg.contains("symlink"),
            "{msg}"
        );
        assert!(
            !h.calls()
                .iter()
                .any(|c| c.program == "mariadb" && c.args.len() == 2)
        );
        assert!(!sys(&h, "/srv/www/kr").exists());
        // A regular file works.
        let h2 = RecordingHost::new(true)
            .respond(
                "podman secret inspect --showsecret",
                125,
                "",
                "no such secret",
            )
            .respond(
                "mariadb --socket=/var/lib/mysql/mysql.sock --batch --skip-column-names",
                0,
                "0\n",
                "",
            );
        let opts = SetupOpts {
            salts_from: Some(&real),
            ..SetupOpts::default()
        };
        setup(&h2, &g, &site, &opts, &net).unwrap();
    }
}

#[cfg(test)]
mod f2_tests {
    use super::*;
    use crate::host::sys;
    use crate::testutil::RecordingHost;

    const USER_COUNT: &str =
        "mariadb --socket=/var/lib/mysql/mysql.sock --batch --skip-column-names";

    fn site() -> Site {
        crate::config::parse_site("name = \"kr\"\ndomains = [\"kr.example\"]\nid = 1\n[core]\nwordpress = \"7.1.2\"\nphp = \"8.3\"\n[database]\nuser = \"legacy\"\n").unwrap()
    }
    fn g() -> GlobalConfig {
        GlobalConfig {
            base_root: std::path::PathBuf::from("/srv/www"),
            id_offset: 1_000_000,
            ..GlobalConfig::default()
        }
    }
    fn net() -> PodmanNet {
        PodmanNet {
            subnet: "10.88.0.0".parse().unwrap(),
            prefix: 16,
            gateway: "10.88.0.1".parse().unwrap(),
        }
    }

    #[test]
    fn stored_password_of_another_user_is_not_reused() {
        // A failed import left a secret for the old site's user and password; a second import
        // for another user must give that account a fresh password, not the old site's.
        let stale = "DB_NAME=legacy_portal\nDB_USER=olduser\nDB_PASSWORD=oldsecret\nDB_HOST=iwp-db-host\nDB_PREFIX=wp_\n";
        let h = RecordingHost::new(true)
            .respond(
                "podman secret inspect --showsecret --format {{.SecretData}} iwp-kr-db",
                0,
                stale,
                "",
            )
            .respond(USER_COUNT, 0, "0\n", "");
        setup(&h, &g(), &site(), &SetupOpts::default(), &net()).unwrap();
        let sql: Vec<String> = h
            .calls()
            .iter()
            .filter(|c| c.program == "mariadb")
            .filter_map(|c| c.stdin.clone())
            .map(|b| String::from_utf8(b).unwrap())
            .collect();
        assert!(
            sql.iter()
                .any(|q| q.contains("CREATE USER IF NOT EXISTS 'legacy'@")),
            "{sql:?}"
        );
        assert!(
            !sql.iter().any(|q| q.contains("oldsecret")),
            "old password reused"
        );
    }

    #[test]
    fn id_choice_reports_a_bad_id_offset_instead_of_panicking() {
        let t = crate::testutil::tmp();
        let g = GlobalConfig {
            id_offset: 4_294_900_000,
            sites_dir: t.path().to_path_buf(),
            ..g()
        };
        let h = RecordingHost::new(true);
        for r in [next_id(&h, &g, &[]), pick_id(&h, &g, &[], Some(3))] {
            let e = r.unwrap_err();
            assert!(
                e.downcast_ref::<crate::error::UsageError>().is_some(),
                "{e:#}"
            );
            assert!(format!("{e:#}").contains("id_offset"), "{e:#}");
        }
    }

    #[test]
    fn secret_is_stored_before_the_account_is_created() {
        // If storing the secret fails, no account exists yet, so a re-run is not refused by
        // the "account exists and no iwp site owns it" check.
        let h = RecordingHost::new(true)
            .respond(
                "podman secret inspect --showsecret",
                125,
                "",
                "Error: no such secret",
            )
            .respond(USER_COUNT, 0, "0\n", "")
            .respond("podman secret create", 125, "", "Error: disk full");
        let e = setup(&h, &g(), &site(), &SetupOpts::default(), &net()).unwrap_err();
        assert!(format!("{e:#}").contains("storing podman secret"), "{e:#}");
        let calls: Vec<String> = h.calls().iter().map(|c| c.to_string()).collect();
        let pos = |p: &str| calls.iter().position(|c| c.starts_with(p));
        assert!(pos("podman secret create").is_some(), "{calls:#?}");
        assert!(
            !calls.iter().any(|c| c.ends_with("--batch")),
            "no account may be created before the secret is stored: {calls:#?}"
        );
    }

    #[test]
    fn existing_account_not_owned_by_this_site_is_refused() {
        let h = RecordingHost::new(true)
            .respond(
                "podman secret inspect --showsecret",
                125,
                "",
                "no such secret",
            )
            .respond(USER_COUNT, 0, "1\n", "");
        let err = setup(&h, &g(), &site(), &SetupOpts::default(), &net()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            err.downcast_ref::<crate::error::UsageError>().is_some(),
            "{msg}"
        );
        assert!(
            msg.contains("'legacy'@'10.88.0.0/255.255.0.0' already exists"),
            "{msg}"
        );
        assert!(
            !h.calls()
                .iter()
                .any(|c| c.to_string() == "mariadb --socket=/var/lib/mysql/mysql.sock --batch")
        );
        assert!(!sys(&h, "/srv/www/kr").exists());
    }

    #[test]
    fn rerun_of_the_same_site_may_keep_its_account() {
        let secret = "DB_NAME=wp_kr\nDB_USER=legacy\nDB_PASSWORD=keepme\nDB_HOST=iwp-db-host\nDB_PREFIX=wp_\n";
        let h = RecordingHost::new(true)
            .respond(
                "podman secret inspect --showsecret --format {{.SecretData}} iwp-kr-db",
                0,
                secret,
                "",
            )
            .respond("podman secret exists iwp-kr-salts", 0, "", "")
            .respond(USER_COUNT, 0, "1\n", "");
        setup(&h, &g(), &site(), &SetupOpts::default(), &net()).unwrap();
        // A secret for another user name does not count as owning the account.
        let other = secret.replace("DB_USER=legacy", "DB_USER=someone");
        let h = RecordingHost::new(true)
            .respond(
                "podman secret inspect --showsecret --format {{.SecretData}} iwp-kr-db",
                0,
                &other,
                "",
            )
            .respond(USER_COUNT, 0, "1\n", "");
        assert!(setup(&h, &g(), &site(), &SetupOpts::default(), &net()).is_err());
    }

    #[test]
    fn failing_account_query_is_an_error_without_stderr() {
        let h = RecordingHost::new(true)
            .respond(
                "podman secret inspect --showsecret",
                125,
                "",
                "no such secret",
            )
            .respond(USER_COUNT, 1, "", "ERROR secret-ish");
        let msg = format!(
            "{:#}",
            setup(&h, &g(), &site(), &SetupOpts::default(), &net()).unwrap_err()
        );
        assert!(
            !msg.contains("secret-ish") && msg.contains("exit 1"),
            "{msg}"
        );
    }
}

#[cfg(test)]
mod new_site_tests {
    use super::*;
    use crate::testutil::RecordingHost;

    fn g(sites: &Path) -> GlobalConfig {
        GlobalConfig {
            sites_dir: sites.to_path_buf(),
            base_root: std::path::PathBuf::from("/srv/www"),
            id_offset: 1_000_000,
            ..GlobalConfig::default()
        }
    }

    fn new_site<'a>(name: &'a str, domains: &'a [String]) -> NewSite<'a> {
        NewSite {
            name,
            domains,
            base: None,
            wordpress: "7.1.2",
            php: "8.3",
            id: None,
        }
    }

    /// F8 (T8): the worker check runs before the site file is written.
    #[test]
    fn worker_group_failure_writes_no_site_file() {
        let t = crate::testutil::tmp();
        let h = RecordingHost::new(true)
            .respond("nginx -T", 0, "user nginx www-users;\n", "")
            .respond("getent group www-users", 0, "www-users:x:2000:\n", "");
        let d = ["blog.example".to_string()];
        let e = format!(
            "{:#}",
            create_site_file(&h, &g(t.path()), &new_site("blog", &d)).unwrap_err()
        );
        assert!(e.starts_with("nginx workers run as nginx:www-users"), "{e}");
        assert_eq!(std::fs::read_dir(t.path()).unwrap().count(), 0);
    }

    #[test]
    fn creates_the_site_file_with_the_next_id() {
        let t = crate::testutil::tmp();
        let h = RecordingHost::new(true);
        let d = ["blog.example".to_string()];
        let l = create_site_file(&h, &g(t.path()), &new_site("blog", &d)).unwrap();
        assert_eq!(l.site.id, 1);
        assert_eq!(l.path, t.path().join("blog.toml"));
        assert!(t.path().join("blog.toml").is_file());
        let d2 = ["two.example".to_string()];
        assert_eq!(
            create_site_file(&h, &g(t.path()), &new_site("two", &d2))
                .unwrap()
                .site
                .id,
            2
        );
        // Validation still applies (duplicate domain) and nothing is written then.
        let e = create_site_file(&h, &g(t.path()), &new_site("three", &d)).unwrap_err();
        assert!(
            e.downcast_ref::<crate::error::UsageError>().is_some(),
            "{e:#}"
        );
        assert!(!t.path().join("three.toml").exists());
    }

    #[test]
    fn missing_sites_dir_is_created_for_the_first_site() {
        let t = crate::testutil::tmp();
        let sites = t.path().join("iwp/sites");
        let h = RecordingHost::new(true);
        let d = ["blog.example".to_string()];
        let l = create_site_file(&h, &g(&sites), &new_site("blog", &d)).unwrap();
        assert_eq!(l.site.id, 1);
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&sites).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o755);
        assert!(
            h.chowns().contains(&(sites.clone(), 0, 0)),
            "{:?}",
            h.chowns()
        );
    }

    /// Covers the ID range of site `id` in /etc/subuid of `h`.
    fn occupy(h: &RecordingHost, g: &GlobalConfig, ids: std::ops::RangeInclusive<u32>) {
        let lo = Identity::for_site(*ids.start(), g.id_offset).base_id;
        let n = u64::from(ids.end() - ids.start() + 1) * 65_536;
        std::fs::create_dir_all(sys(h, "/etc")).unwrap();
        std::fs::write(sys(h, "/etc/subuid"), format!("cloud:{lo}:{n}\n")).unwrap();
    }

    #[test]
    fn next_id_skips_ranges_that_overlap_subids() {
        let t = crate::testutil::tmp();
        let (h, g) = (RecordingHost::new(true), g(t.path()));
        assert_eq!(next_id(&h, &g, &[]).unwrap(), 1);
        occupy(&h, &g, 1..=2);
        assert_eq!(next_id(&h, &g, &[]).unwrap(), 3);
        let d = ["blog.example".to_string()];
        assert_eq!(
            create_site_file(&h, &g, &new_site("blog", &d))
                .unwrap()
                .site
                .id,
            3
        );
        occupy(&h, &g, 1..=511);
        let e = next_id(&h, &g, &[]).unwrap_err();
        assert!(
            e.downcast_ref::<crate::error::UsageError>().is_some(),
            "{e:#}"
        );
        assert!(
            format!("{e:#}").contains("/etc/subuid") && format!("{e:#}").contains("id_offset"),
            "{e:#}"
        );
    }

    #[test]
    fn explicit_id_is_used_and_checked_before_anything_is_written() {
        let t = crate::testutil::tmp();
        let (h, g) = (RecordingHost::new(true), g(t.path()));
        occupy(&h, &g, 1..=2);
        let d = ["blog.example".to_string()];
        let mut n = new_site("blog", &d);
        n.id = Some(2);
        let e = create_site_file(&h, &g, &n).unwrap_err();
        assert!(
            e.downcast_ref::<crate::error::UsageError>().is_some(),
            "{e:#}"
        );
        assert!(format!("{e:#}").contains("/etc/subuid:1: cloud:"), "{e:#}");
        assert!(!t.path().join("blog.toml").exists());
        n.id = Some(40);
        assert_eq!(create_site_file(&h, &g, &n).unwrap().site.id, 40);
    }

    /// F9 (M5): id assignment and installation happen under the host-wide sites lock.
    #[test]
    fn id_assignment_waits_for_the_sites_lock() {
        let t = crate::testutil::tmp();
        let h = RecordingHost::new(true);
        let held = crate::host::lock::SitesLock::acquire(&h).unwrap();
        let root = h.sysroot().to_path_buf();
        let gc = g(t.path());
        let (tx, rx) = std::sync::mpsc::channel();
        let th = std::thread::spawn(move || {
            let h2 = RecordingHost::with_root(&root);
            let d = ["blog.example".to_string()];
            let r = create_site_file(&h2, &gc, &new_site("blog", &d)).map(|l| l.site.id);
            tx.send(()).unwrap();
            r.unwrap()
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(300))
                .is_err()
        );
        assert!(!t.path().join("blog.toml").exists());
        // Meanwhile another creation took id 1.
        std::fs::write(
            t.path().join("other.toml"),
            new_site_text("other", &["other.example".into()], None, 1, "7.1.2", "8.3"),
        )
        .unwrap();
        drop(held);
        rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
        assert_eq!(th.join().unwrap(), 2);
    }
}
