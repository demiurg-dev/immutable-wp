use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

use super::*;
use crate::config::Source;
use crate::fetch::cache::Cache;
use crate::fetch::net::Fetcher;
use crate::fetch::wporg::plugin_checksums_url;
use crate::hash::{sha256_file, sha256_hex, tree_hash};
use crate::host::secrets::{DbSecret, SALT_KEYS};
use crate::testutil::{FakeFetcher, RecordingHost, tmp};

/// PHP single-quote semantics: `\'` is `'`, `\\` is `\`, everything else is literal.
const PW: &str = "p'w\\d$x#žü€";
const PW_PHP: &str = "p\\'w\\\\d$x#žü€";

fn salt(k: &str) -> String {
    format!("s'\\${k}#ŝ")
}
fn salt_php(k: &str) -> String {
    format!("s\\'\\\\${k}#ŝ")
}

fn w(root: &Path, rel: &str, body: &str) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, body).unwrap();
}

const CLEAN: [(&str, &str); 2] = [
    (
        "clean.php",
        "<?php\n/*\nPlugin Name: Clean\nVersion: 1.0\n*/\n",
    ),
    ("readme.txt", "clean readme"),
];
const MODDED: [(&str, &str); 2] = [
    (
        "modded.php",
        "<?php\n/*\nPlugin Name: Modded\nVersion: 2.0\n*/\n",
    ),
    ("inc.php", "<?php // original"),
];

fn sums_json(files: &[(&str, &str)]) -> String {
    let f: Vec<String> = files
        .iter()
        .map(|(n, c)| format!(r#""{n}":{{"sha256":"{}"}}"#, sha256_hex(c.as_bytes())))
        .collect();
    format!(r#"{{"files":{{{}}}}}"#, f.join(","))
}

fn wp_config(extra: &str) -> String {
    let salts: String = SALT_KEYS
        .iter()
        .map(|k| format!("define( '{k}', '{}' );\n", salt_php(k)))
        .collect();
    format!(
        "<?php\ndefine( 'DB_NAME', 'olddb' );\ndefine( 'DB_USER', 'wpuser' );\n\
         define( 'DB_PASSWORD', '{PW_PHP}' );\ndefine( 'DB_HOST', 'localhost' );\n\
         define( 'DB_CHARSET', 'utf8mb4' );\ndefine( 'DB_COLLATE', '' );\n\
         $table_prefix = 'wpx_';\n{salts}\
         define( 'WP_DEBUG', false );\n\
         define( 'SITE_LABEL', 'Ž \"q\" \\\\ x' );\n\
         define( 'WP_HOME', 'https://' . $_SERVER['HTTP_HOST'] );\n\
         define( 'MY_API_KEY', 'k' );\n{extra}\
         require_once ABSPATH . 'wp-settings.php';\n"
    )
}

/// A classic webroot: core version, wp-config.php, a wordpress.org-clean plugin, a modified
/// one, a custom one (with an executable file), a single-file plugin, one with a symlink, a
/// mu-plugin, a custom theme, a drop-in, an unknown dir, a language and uploads (nested file
/// and a symlink to /etc).
fn webroot() -> tempfile::TempDir {
    let d = tmp();
    let r = d.path();
    w(
        r,
        "wp-includes/version.php",
        "<?php\n$wp_version = '7.1.2';\n",
    );
    w(r, "wp-config.php", &wp_config(""));
    for (n, c) in CLEAN {
        w(r, &format!("wp-content/plugins/clean/{n}"), c);
    }
    w(r, "wp-content/plugins/modded/modded.php", MODDED[0].1);
    w(r, "wp-content/plugins/modded/inc.php", "<?php // changed");
    w(
        r,
        "wp-content/plugins/custom/custom.php",
        "<?php\n/*\nPlugin Name: Custom\nVersion: 0.1\n*/\n",
    );
    w(r, "wp-content/plugins/custom/bin/tool.sh", "#!/bin/sh\n");
    fs::set_permissions(
        r.join("wp-content/plugins/custom/bin/tool.sh"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    w(r, "wp-content/plugins/custom/private.php", "<?php // 0640");
    fs::set_permissions(
        r.join("wp-content/plugins/custom/private.php"),
        fs::Permissions::from_mode(0o640),
    )
    .unwrap();
    w(
        r,
        "wp-content/plugins/single.php",
        "<?php\n/*\nPlugin Name: Single\n*/\n",
    );
    w(
        r,
        "wp-content/plugins/linked/linked.php",
        "<?php\n/*\nPlugin Name: Linked\nVersion: 1\n*/\n",
    );
    symlink("/etc/passwd", r.join("wp-content/plugins/linked/pw.txt")).unwrap();
    w(r, "wp-content/mu-plugins/tweaks.php", "<?php // tweaks");
    w(
        r,
        "wp-content/themes/mytheme/style.css",
        "/*\nTheme Name: Mine\nVersion: 1.0\n*/\n",
    );
    w(r, "wp-content/themes/mytheme/index.php", "<?php");
    w(r, "wp-content/object-cache.php", "<?php // cache");
    w(r, "wp-content/wflogs/config.php", "<?php");
    w(r, "wp-content/languages/hr.mo", "mo");
    w(r, "wp-content/uploads/2024/01/a.jpg", "jpg");
    symlink("/etc", r.join("wp-content/uploads/etc-link")).unwrap();
    d
}

fn fetcher() -> FakeFetcher {
    FakeFetcher::new()
        .with(&plugin_checksums_url("clean", "1.0"), sums_json(&CLEAN))
        .with(&plugin_checksums_url("modded", "2.0"), sums_json(&MODDED))
}

/// The read-only query `setup` and `import` run to see whether the DB account already exists.
const USER_COUNT: &str = "mariadb --socket=/var/lib/mysql/mysql.sock --batch --skip-column-names";

fn host() -> RecordingHost {
    RecordingHost::new(true)
        .respond(USER_COUNT, 0, "0\n", "")
        .respond("podman network inspect", 0, "10.88.0.0/16 10.88.0.1\n", "")
        .respond(
            "podman secret inspect --showsecret",
            125,
            "",
            "Error: no such secret",
        )
}

struct Env {
    _t: tempfile::TempDir,
    _cache: tempfile::TempDir,
    g: GlobalConfig,
    cache: Cache,
}

fn env() -> Env {
    let t = tmp();
    let sites = t.path().join("sites");
    fs::create_dir(&sites).unwrap();
    let c = tmp();
    Env {
        g: GlobalConfig {
            sites_dir: sites,
            base_root: PathBuf::from("/srv/www"),
            id_offset: 1_000_000,
            ..GlobalConfig::default()
        },
        cache: Cache::new(c.path()),
        _cache: c,
        _t: t,
    }
}

fn args(from: &Path) -> ImportArgs {
    ImportArgs {
        site: "shop".into(),
        from: from.to_path_buf(),
        domains: vec!["shop.example".into()],
        base: None,
        php: "8.3".into(),
        new_db_user: false,
        id: None,
        src_root: PathBuf::from(DEFAULT_SRC_ROOT),
    }
}

fn go(e: &Env, h: &RecordingHost, f: &dyn Fetcher, a: ImportArgs) -> Result<ImportReport> {
    let ctx = ImportCtx {
        wporg: WpOrg {
            fetcher: f,
            cache: &e.cache,
        },
    };
    run(h, &e.g, &ctx, a)
}

/// (path, kind, mtime, size, content hash or link target) of everything under `root`.
fn snapshot(root: &Path) -> Vec<(String, String, i64, i64, u64, String)> {
    walkdir::WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .map(|e| {
            let e = e.unwrap();
            let m = fs::symlink_metadata(e.path()).unwrap();
            let rel = e.path().strip_prefix(root).unwrap().display().to_string();
            let what = if m.file_type().is_symlink() {
                fs::read_link(e.path()).unwrap().display().to_string()
            } else if m.is_file() {
                sha256_file(e.path()).unwrap()
            } else {
                String::new()
            };
            let kind = format!("{:o}", m.mode());
            (rel, kind, m.mtime(), m.mtime_nsec(), m.size(), what)
        })
        .collect()
}

fn all_salts() -> Vec<String> {
    SALT_KEYS.iter().map(|k| salt(k)).collect()
}

fn assert_no_secrets(hay: &str, what: &str) {
    assert!(!hay.contains(PW), "password in {what}: {hay}");
    for s in all_salts() {
        assert!(!hay.contains(&s), "salt in {what}: {hay}");
    }
}

#[test]
fn import_writes_site_file_copies_secrets_and_uploads() {
    let wr = webroot();
    let from = wr.path();
    let before = snapshot(from);
    let e = env();
    let h = host();
    let rep = go(&e, &h, &fetcher(), args(from)).unwrap();

    // Site file.
    let path = e.g.sites_dir.join("shop.toml");
    let text = fs::read_to_string(&path).unwrap();
    let s = parse_site(&text).unwrap();
    assert!(crate::config::validate_site(&s, Some("shop")).is_empty());
    assert_eq!((s.id, s.core.wordpress.as_str()), (1, "7.1.2"));
    assert_eq!(s.core.languages, vec!["hr"]);
    assert_eq!(s.domains, vec!["shop.example"]);
    assert_eq!(s.database.name.as_deref(), Some("olddb"));
    assert_eq!(s.database.user.as_deref(), Some("wpuser"));
    assert_eq!(s.database.prefix.as_deref(), Some("wpx_"));
    assert_eq!(s.database.charset.as_deref(), Some("utf8mb4"));
    assert_eq!(s.config.constants["WP_DEBUG"], ConstValue::Bool(false));
    assert_eq!(
        s.config.constants["SITE_LABEL"],
        ConstValue::Str("Ž \"q\" \\ x".into())
    );
    assert!(s.config.multisite.is_none());
    assert!(!text.contains("[config]\n"), "{text}");
    let pk = |slug: &str| {
        s.plugins
            .iter()
            .chain(&s.themes)
            .find(|p| p.slug == slug)
            .unwrap_or_else(|| panic!("{slug} missing: {text}"))
    };
    assert_eq!(pk("clean").version.as_deref(), Some("1.0"));
    assert!(pk("clean").source.is_none());
    let src = "/srv/iwp/src/shop";
    for (slug, rel) in [
        ("modded", "plugins/modded"),
        ("custom", "plugins/custom"),
        ("single", "plugins/single"),
        ("tweaks", "mu-plugins/tweaks.php"),
        ("mytheme", "themes/mytheme"),
    ] {
        let p = pk(slug);
        let real = PathBuf::from(format!("{src}/{rel}"));
        assert_eq!(
            p.source,
            Some(Source::Path { path: real.clone() }),
            "{slug}"
        );
        let copy = sys(&h, &real);
        let pin = if slug == "tweaks" {
            sha256_file(&copy).unwrap()
        } else {
            tree_hash(&copy).unwrap()
        };
        assert_eq!(p.sha256.as_deref(), Some(pin.as_str()), "{slug}");
    }
    assert!(pk("tweaks").mu);
    assert!(s.plugins.iter().all(|p| p.slug != "linked"));
    assert!(sys(&h, format!("{src}/plugins/single/single.php")).is_file());
    let tool = sys(&h, format!("{src}/plugins/custom/bin/tool.sh"));
    assert_eq!(
        fs::metadata(&tool).unwrap().permissions().mode() & 0o777,
        0o755
    );
    let inc = sys(&h, format!("{src}/plugins/modded/inc.php"));
    assert_eq!(
        fs::metadata(&inc).unwrap().permissions().mode() & 0o777,
        0o644
    );
    assert_eq!(fs::read_to_string(inc).unwrap(), "<?php // changed");

    // Setup: same user at the podman subnet, old password; never the old host.
    let sql = h
        .calls()
        .into_iter()
        .find(|c| c.program == "mariadb" && c.to_string() != USER_COUNT)
        .map(|c| String::from_utf8(c.stdin.unwrap()).unwrap())
        .unwrap();
    assert!(sql.contains("'wpuser'@'10.88.0.0/255.255.0.0'"), "{sql}");
    assert!(sql.contains(&crate::host::db::sql_str(PW)), "{sql}");
    assert!(!sql.contains("'localhost'"), "{sql}");
    let secret = |name: &str| {
        h.calls()
            .into_iter()
            .find(|c| c.to_string() == format!("podman secret create --replace {name} -"))
            .map(|c| String::from_utf8(c.stdin.unwrap()).unwrap())
            .unwrap()
    };
    let db = DbSecret::parse(&secret("iwp-shop-db")).unwrap();
    assert_eq!((db.user.as_str(), db.password.as_str()), ("wpuser", PW));
    assert_eq!(db.prefix, "wpx_");
    let salts: BTreeMap<String, String> =
        SALT_KEYS.iter().map(|k| (k.to_string(), salt(k))).collect();
    assert_eq!(
        secret("iwp-shop-salts"),
        crate::host::secrets::render_salts(&salts).unwrap()
    );

    // Uploads.
    let cmds: Vec<String> = h.calls().iter().map(ToString::to_string).collect();
    let www = Identity::for_site(1, 1_000_000).www_uid;
    let rsync = h
        .calls()
        .into_iter()
        .find(|c| c.program == "setpriv" && c.args.iter().any(|a| a == "rsync"))
        .unwrap();
    assert_eq!(
        rsync.to_string(),
        format!(
            "setpriv --reuid={www} --regid={www} --clear-groups -- rsync -rtH --no-links --chmod=D2755,F0644 {}/wp-content/uploads/ /srv/www/shop/shared/uploads/",
            from.display()
        )
    );
    assert_eq!(rsync.timeout, Some(RSYNC_TIMEOUT));
    // Root only probes rsync (`rsync --version`); the copy itself never runs as root.
    assert!(
        !cmds
            .iter()
            .any(|c| c.starts_with("rsync") && c != "rsync --version")
    );
    let up = sys(&h, "/srv/www/shop/shared/uploads");
    let chown = format!("chown_tree {} {www} {www}", up.display());
    let pos = |p: &str| cmds.iter().position(|c| c.starts_with(p)).unwrap();
    assert!(pos(&rsync_prefix()) < pos(&chown));
    assert!(pos(&chown) < pos("restorecon -RF /srv/www/shop/shared/uploads"));
    assert!(
        !cmds
            .iter()
            .any(|c| c.contains("systemctl start") || c.contains("podman run"))
    );

    // Report.
    assert_eq!(rep.dropins, vec!["object-cache.php"]);
    assert_eq!(rep.other_content_dirs, vec!["wflogs"]);
    assert!(rep.not_carried.iter().any(|n| n == "WP_HOME"));
    assert!(rep.not_carried.iter().any(|n| n.starts_with("MY_API_KEY")));
    let line = |slug: &str| rep.packages.iter().find(|p| p.slug == slug).unwrap();
    assert_eq!(line("clean").verdict, "wporg");
    assert_eq!(line("modded").verdict, "source");
    assert_eq!(line("modded").reason.as_deref(), Some("modified inc.php"));
    assert_eq!(
        line("custom").reason.as_deref(),
        Some("not on wordpress.org at 0.1")
    );
    assert_eq!(line("linked").verdict, "skipped");
    assert!(line("linked").reason.as_ref().unwrap().contains("symlink"));
    assert!(line("modded").sha256.is_some());
    assert!(
        rep.warnings
            .iter()
            .any(|w| w.contains("plugins/single.php"))
    );
    let rpath = sys(&h, "/srv/www/shop/config/import-report.json");
    let json = fs::read_to_string(&rpath).unwrap();
    assert_eq!(
        fs::metadata(&rpath).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(json.contains("\"object-cache.php\"") && json.contains("\"wflogs\""));
    assert!(rep.summary().contains("[dropins]"));
    assert_eq!(
        rep.uploads_not_copied,
        vec!["not copied: symlink wp-content/uploads/etc-link"]
    );
    assert!(
        rep.warnings
            .iter()
            .any(|w| w.contains("linked") && w.contains("skipped"))
    );
    assert!(
        rep.warnings
            .iter()
            .any(|w| w.contains("not world-readable") && w.contains("custom/private.php")),
        "{:?}",
        rep.warnings
    );
    assert!(rep.error.is_none() && rep.recovery.is_empty());

    // Secrets never leak; the old webroot is untouched.
    assert_no_secrets(&text, "site file");
    assert_no_secrets(&json, "report");
    assert_no_secrets(&rep.summary(), "summary");
    for c in h.calls() {
        assert_no_secrets(&format!("{c} {c:?}"), "argv");
    }
    assert_eq!(snapshot(from), before);
}

#[test]
fn new_db_user_gets_generated_password() {
    let wr = webroot();
    let e = env();
    let h = host();
    let mut a = args(wr.path());
    a.new_db_user = true;
    let rep = go(&e, &h, &fetcher(), a).unwrap();
    assert_eq!(rep.db_user, "iwp_shop");
    let s = parse_site(&fs::read_to_string(e.g.sites_dir.join("shop.toml")).unwrap()).unwrap();
    assert_eq!(s.database.user.as_deref(), Some("iwp_shop"));
    let sql = h
        .calls()
        .into_iter()
        .find(|c| c.program == "mariadb" && c.to_string() != USER_COUNT)
        .map(|c| String::from_utf8(c.stdin.unwrap()).unwrap())
        .unwrap();
    assert!(sql.contains("'iwp_shop'@'10.88.0.0/255.255.0.0'"), "{sql}");
    assert!(!sql.contains("wpuser") && !sql.contains(PW), "{sql}");
    let db = h
        .calls()
        .into_iter()
        .find(|c| c.to_string() == "podman secret create --replace iwp-shop-db -")
        .map(|c| DbSecret::parse(&String::from_utf8(c.stdin.unwrap()).unwrap()).unwrap())
        .unwrap();
    assert_eq!(db.password.len(), 64);
    assert_ne!(db.password, PW);
}

struct Down;
impl Fetcher for Down {
    fn get(&self, _: &str) -> Result<Vec<u8>> {
        anyhow::bail!("connection refused")
    }
}

/// Nginx workers outside nginx_group fail the import before detection, lookups or writes.
#[test]
fn nginx_workers_outside_nginx_group_fail_before_anything() {
    let wr = webroot();
    let e = env();
    let before = snapshot(wr.path());
    let h = host()
        .respond("nginx -T", 0, "user nginx www-users;\n", "")
        .respond("getent group www-users", 0, "www-users:x:2000:\n", "");
    let f = fetcher();
    let err = format!("{:#}", go(&e, &h, &f, args(wr.path())).unwrap_err());
    assert!(
        err.starts_with("nginx workers run as nginx:www-users and are not in group nginx"),
        "{err}"
    );
    assert!(f.calls().is_empty(), "{:?}", f.calls());
    assert!(!e.g.sites_dir.join("shop.toml").exists());
    assert_eq!(fs::read_dir(&e.g.sites_dir).unwrap().count(), 0);
    assert!(!sys(&h, "/srv/iwp").exists());
    assert!(!sys(&h, "/srv/www").exists());
    assert!(h.chowns().is_empty());
    let calls: Vec<String> = h.calls().iter().map(|c| c.to_string()).collect();
    assert!(
        calls
            .iter()
            .all(|c| c == "nginx -T" || c.starts_with("getent ") || c.starts_with("id ")),
        "{calls:?}"
    );
    assert_eq!(snapshot(wr.path()), before);
}

/// True when `h` ran nothing but the read-only `check_worker_group` lookups.
fn only_worker_lookups(h: &RecordingHost) -> bool {
    h.calls().iter().all(|c| {
        let c = c.to_string();
        c == "nginx -T" || c.starts_with("getent group ") || c.starts_with("id -")
    })
}

#[test]
fn lookup_failure_writes_nothing() {
    let wr = webroot();
    let e = env();
    let h = host();
    let err = format!("{:#}", go(&e, &h, &Down, args(wr.path())).unwrap_err());
    assert!(
        err.contains("connection refused") && err.contains("nothing was written"),
        "{err}"
    );
    assert_no_secrets(&err, "error");
    assert!(only_worker_lookups(&h), "{:?}", h.calls());
    assert!(!e.g.sites_dir.join("shop.toml").exists());
    assert_eq!(fs::read_dir(&e.g.sites_dir).unwrap().count(), 0);
    assert!(!sys(&h, "/srv/iwp").exists());
}

#[test]
fn setup_failure_error_has_no_secrets_and_keeps_site_file() {
    let wr = webroot();
    let e = env();
    let h = host().respond("mariadb", 1, "", &format!("ERROR near '{PW}'"));
    let err = go(&e, &h, &fetcher(), args(wr.path())).unwrap_err();
    let msg = format!("{err:#}");
    assert_no_secrets(&msg, "error");
    assert!(msg.contains("setup failed"), "{msg}");
    assert!(e.g.sites_dir.join("shop.toml").exists());
    // The report is still written and handed back, with the error and recovery commands.
    let rep = &err.downcast_ref::<ImportError>().unwrap().report;
    assert!(rep.error.as_deref().unwrap().contains("setup failed"));
    let rec = rep.recovery.join("\n");
    assert!(
        rec.contains(&format!(
            "iwp setup shop --salts-from {}/wp-config.php",
            wr.path().display()
        )),
        "{rec}"
    );
    assert!(
        rec.contains("setpriv --reuid=")
            && rec.contains("chown -R -h")
            && rec.contains("restorecon -RF /srv/www/shop/shared/uploads"),
        "{rec}"
    );
    assert!(rec.contains("does not reuse the old"), "{rec}");
    assert!(
        rec.contains("--salts-from must name a regular, root-readable file"),
        "{rec}"
    );
    let json = fs::read_to_string(sys(&h, "/srv/www/shop/config/import-report.json")).unwrap();
    assert!(json.contains("setup failed"));
    assert_no_secrets(&json, "report");
    assert!(
        !h.calls()
            .iter()
            .any(|c| c.args.iter().any(|a| a == "rsync"))
    );
}

fn www() -> u32 {
    Identity::for_site(1, 1_000_000).www_uid
}

fn rsync_prefix() -> String {
    format!(
        "setpriv --reuid={w} --regid={w} --clear-groups -- rsync",
        w = www()
    )
}

/// The fixture's uploads hold `n` regular files (plus the /etc symlink); `copied` of them are
/// pre-placed in the destination, standing in for what a partial rsync (exit 23) copied.
fn partial_uploads(n: usize, copied: usize) -> (tempfile::TempDir, Env, RecordingHost) {
    let wr = webroot();
    fs::remove_file(wr.path().join("wp-content/uploads/2024/01/a.jpg")).unwrap();
    for i in 0..n {
        w(wr.path(), &format!("wp-content/uploads/f{i}.jpg"), "x");
    }
    let e = env();
    let h = host().respond(&rsync_prefix(), 23, "", "permission denied (13)");
    for i in 0..copied {
        w(
            &sys(&h, "/srv/www/shop/shared/uploads"),
            &format!("f{i}.jpg"),
            "x",
        );
    }
    (wr, e, h)
}

#[test]
fn partial_uploads_at_or_above_90_percent_warn_and_continue() {
    let (wr, e, h) = partial_uploads(10, 9);
    let rep = go(&e, &h, &fetcher(), args(wr.path())).unwrap();
    assert!(
        rep.warnings
            .iter()
            .any(|w| w.contains("not readable by the site user")
                && w.contains("1 of 10 files were not copied")),
        "{:?}",
        rep.warnings
    );
    assert!(h.calls().iter().any(|c| c.program == "chown_tree"));
    assert!(h.calls().iter().any(|c| {
        c.to_string()
            .starts_with("restorecon -RF /srv/www/shop/shared/uploads")
    }));
}

#[test]
fn partial_uploads_below_90_percent_fail_with_report() {
    let (wr, e, h) = partial_uploads(10, 8);
    let err = go(&e, &h, &fetcher(), args(wr.path())).unwrap_err();
    let rep = &err.downcast_ref::<ImportError>().unwrap().report;
    let msg = rep.error.as_deref().unwrap();
    assert!(msg.contains("only 8 of 10"), "{msg}");
    assert!(rep.recovery.iter().any(|r| r.starts_with("setpriv")));
    assert!(sys(&h, "/srv/www/shop/config/import-report.json").exists());
    assert!(!h.calls().iter().any(|c| c.program == "chown_tree"));
}

#[test]
fn other_rsync_failures_are_errors() {
    let wr = webroot();
    let e = env();
    let h = host().respond(&rsync_prefix(), 12, "", "protocol error");
    let err = go(&e, &h, &fetcher(), args(wr.path())).unwrap_err();
    let rep = &err.downcast_ref::<ImportError>().unwrap().report;
    assert!(rep.error.as_deref().unwrap().contains("rsync exit 12"));
    assert!(!rep.recovery.iter().any(|r| r.starts_with("iwp setup")));
    assert!(rep.recovery.iter().any(|r| r.starts_with("setpriv")));
    assert!(sys(&h, "/srv/www/shop/config/import-report.json").exists());
}

#[test]
fn uploads_readability_precheck_runs_before_any_write() {
    // Recorded with the planned site's www uid, before the copies and setup.
    let wr = webroot();
    let from = fs::canonicalize(wr.path()).unwrap();
    let up = from.join("wp-content/uploads");
    let e = env();
    let h = host();
    go(&e, &h, &fetcher(), args(wr.path())).unwrap();
    let cmds: Vec<String> = h.calls().iter().map(ToString::to_string).collect();
    let check = format!(
        "setpriv --reuid={w} --regid={w} --clear-groups -- test -r {u} -a -x {u}",
        w = www(),
        u = up.display()
    );
    let pos = |p: &str| cmds.iter().position(|c| c.starts_with(p)).unwrap();
    assert!(pos(&check) < pos("mariadb"), "{cmds:#?}");

    // A failing check is a usage error with setfacl guidance, and nothing is written.
    let wr = webroot();
    let from = fs::canonicalize(wr.path()).unwrap();
    fs::set_permissions(&from, fs::Permissions::from_mode(0o750)).unwrap();
    let up = from.join("wp-content/uploads");
    let e = env();
    let h = host().respond(
        &format!(
            "setpriv --reuid={w} --regid={w} --clear-groups -- test",
            w = www()
        ),
        1,
        "",
        "",
    );
    let err = go(&e, &h, &fetcher(), args(wr.path())).unwrap_err();
    let msg = format!("{err:#}");
    assert!(err.downcast_ref::<UsageError>().is_some(), "{msg}");
    let w = www();
    assert!(
        msg.contains(&format!(
            "the new site user (uid {w}) cannot read {}",
            up.display()
        )),
        "{msg}"
    );
    assert!(
        msg.contains(&format!("setfacl -m u:{w}:x {}", from.display())),
        "{msg}"
    );
    assert!(
        msg.contains(&format!("setfacl -R -m u:{w}:rX {}", up.display())),
        "{msg}"
    );
    // /tmp is world-executable: no command for it.
    assert!(!msg.contains(&format!("setfacl -m u:{w}:x /tmp;")), "{msg}");
    assert!(msg.contains("re-run iwp import"), "{msg}");
    assert!(!e.g.sites_dir.join("shop.toml").exists());
    assert!(!sys(&h, "/srv/iwp").exists());
    assert!(
        !h.calls()
            .iter()
            .any(|c| c.program == "mariadb" || c.program == "chown_tree")
    );
    assert!(
        !h.calls()
            .iter()
            .any(|c| c.to_string().starts_with("podman secret create"))
    );
    fs::set_permissions(&from, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn non_root_is_refused_before_any_lookup() {
    let wr = webroot();
    let e = env();
    let nr = RecordingHost::new(false);
    let f = fetcher();
    let err = go(&e, &nr, &f, args(wr.path())).unwrap_err();
    assert!(err.downcast_ref::<UsageError>().is_some());
    assert!(f.calls().is_empty(), "{:?}", f.calls());
    assert!(nr.calls().is_empty());
}

#[test]
fn site_file_rechecked_under_the_lock() {
    let e = env();
    let h = host();
    let sf = e.g.sites_dir.join("shop.toml");
    let lock = lock_site(&h, "shop", &sf).unwrap();
    drop(lock);
    fs::write(&sf, "name = \"other\"\n").unwrap();
    let err = lock_site(&h, "shop", &sf).unwrap_err();
    assert!(err.downcast_ref::<UsageError>().is_some(), "{err:#}");
    assert!(format!("{err:#}").contains("already exists"));
    assert_eq!(fs::read_to_string(&sf).unwrap(), "name = \"other\"\n");
}

#[test]
fn unstorable_password_fails_before_any_write() {
    let wr = webroot();
    w(
        wr.path(),
        "wp-config.php",
        &wp_config("").replace(PW_PHP, "line1\nline2"),
    );
    let e = env();
    let h = host();
    let err = format!("{:#}", go(&e, &h, &fetcher(), args(wr.path())).unwrap_err());
    assert!(
        err.contains("DB_PASSWORD") && !err.contains("line1"),
        "{err}"
    );
    assert!(!e.g.sites_dir.join("shop.toml").exists());
    assert!(!sys(&h, "/srv/iwp").exists());
    assert!(
        !h.calls()
            .iter()
            .any(|c| c.program == "mariadb" || c.program == "podman" && c.args[0] == "secret")
    );
}

fn copy(
    h: &RecordingHost,
    top: &Path,
    from: &Path,
    p: &LocalPackage,
    dest: &Path,
) -> Result<String> {
    copy_package(h, top, from, from, p, dest, &mut CopyLog::default())
}

fn pkg(kind: detect::Kind, slug: &str, dir: PathBuf, single: bool) -> LocalPackage {
    LocalPackage {
        kind,
        slug: slug.into(),
        version: None,
        dir,
        single_file: single,
    }
}

#[test]
fn copy_never_follows_a_swapped_symlink() {
    let wr = webroot();
    let from = wr.path();
    let h = RecordingHost::new(true);
    let top = h.sysroot().join("src");
    let elsewhere = tmp();
    w(
        elsewhere.path(),
        "x/stolen.php",
        "<?php // not part of the site",
    );
    let refused = |p: &LocalPackage, dest: &str| {
        let r = copy(&h, &top, from, p, &top.join(dest));
        let e = format!("{:#}", r.unwrap_err());
        assert!(e.contains("symlink"), "{e}");
        assert!(!top.join(dest).join("stolen.php").exists());
    };
    // A directory symlink planted under a source subdir.
    symlink(
        elsewhere.path().join("x"),
        from.join("wp-content/plugins/custom/bin/lib"),
    )
    .unwrap();
    refused(
        &pkg(
            detect::Kind::Plugin,
            "custom",
            from.join("wp-content/plugins/custom"),
            false,
        ),
        "custom",
    );
    // The package directory itself swapped for a symlink after the scan.
    fs::remove_dir_all(from.join("wp-content/plugins/modded")).unwrap();
    symlink(
        elsewhere.path().join("x"),
        from.join("wp-content/plugins/modded"),
    )
    .unwrap();
    refused(
        &pkg(
            detect::Kind::Plugin,
            "modded",
            from.join("wp-content/plugins/modded"),
            false,
        ),
        "modded",
    );
    // An intermediate component swapped.
    fs::rename(
        from.join("wp-content/themes"),
        from.join("wp-content/themes.real"),
    )
    .unwrap();
    symlink(
        from.join("wp-content/themes.real"),
        from.join("wp-content/themes"),
    )
    .unwrap();
    refused(
        &pkg(
            detect::Kind::Theme,
            "mytheme",
            from.join("wp-content/themes/mytheme"),
            false,
        ),
        "mytheme",
    );
    // A single-file mu-plugin swapped for a symlink.
    fs::remove_file(from.join("wp-content/mu-plugins/tweaks.php")).unwrap();
    symlink(
        elsewhere.path().join("x/stolen.php"),
        from.join("wp-content/mu-plugins/tweaks.php"),
    )
    .unwrap();
    refused(
        &pkg(
            detect::Kind::MuPlugin,
            "tweaks",
            from.join("wp-content/mu-plugins/tweaks.php"),
            true,
        ),
        "tweaks.php",
    );
}

#[test]
fn usage_errors_before_anything() {
    let wr = webroot();
    let e = env();
    let h = host();
    let is_usage = |r: Result<ImportReport>| {
        let err = r.unwrap_err();
        let msg = format!("{err:#}");
        assert!(err.downcast_ref::<UsageError>().is_some(), "{msg}");
        msg
    };
    // No domain and not multisite.
    let mut a = args(wr.path());
    a.domains.clear();
    assert!(is_usage(go(&e, &h, &fetcher(), a)).contains("--domain"));
    // Bad site name, not a WordPress root, existing site file.
    let mut a = args(wr.path());
    a.site = "Bad".into();
    is_usage(go(&e, &h, &fetcher(), a));
    let mut a = args(wr.path());
    a.from = wr.path().join("wp-content");
    assert!(is_usage(go(&e, &h, &fetcher(), a)).contains("not a WordPress root"));
    // Base inside the old webroot.
    let h2 = RecordingHost::with_root(wr.path());
    let mut a2 = args(wr.path());
    a2.base = Some(PathBuf::from("/iwp"));
    assert!(is_usage(go(&e, &h2, &fetcher(), a2)).contains("overlaps the old webroot"));
    // Not root.
    let nr = RecordingHost::new(false);
    assert!(is_usage(go(&e, &nr, &fetcher(), args(wr.path()))).contains("must be run as root"));
    fs::write(e.g.sites_dir.join("shop.toml"), "x").unwrap();
    assert!(is_usage(go(&e, &h, &fetcher(), args(wr.path()))).contains("already exists"));
    // Usage errors found after the root check (domain, overlap) follow only the read-only
    // nginx worker lookups; nothing else ran.
    assert!(only_worker_lookups(&h) && only_worker_lookups(&h2) && nr.calls().is_empty());
}

#[test]
fn multisite_domain_is_the_default() {
    let wr = webroot();
    w(
        wr.path(),
        "wp-config.php",
        &wp_config(
            "define('MULTISITE', true);\ndefine('SUBDOMAIN_INSTALL', true);\n\
             define('DOMAIN_CURRENT_SITE', 'net.example');\n",
        ),
    );
    let e = env();
    let h = host();
    let mut a = args(wr.path());
    a.domains.clear();
    go(&e, &h, &fetcher(), a).unwrap();
    let s = parse_site(&fs::read_to_string(e.g.sites_dir.join("shop.toml")).unwrap()).unwrap();
    assert_eq!(s.domains, vec!["net.example"]);
    let ms = s.config.multisite.unwrap();
    assert!(ms.subdomain && ms.domain == "net.example");
    assert_eq!((ms.path.as_str(), ms.site_id, ms.blog_id), ("/", 1, 1));

    // Non-default PATH/SITE_ID/BLOG_ID are carried.
    let wr = webroot();
    w(
        wr.path(),
        "wp-config.php",
        &wp_config(
            "define('MULTISITE', true);\ndefine('SUBDOMAIN_INSTALL', true);\n\
             define('DOMAIN_CURRENT_SITE', 'net.example');\ndefine('PATH_CURRENT_SITE', '/net/');\n\
             define('SITE_ID_CURRENT_SITE', 2);\ndefine('BLOG_ID_CURRENT_SITE', 4);\n",
        ),
    );
    let e = env();
    let mut a = args(wr.path());
    a.domains.clear();
    go(&e, &host(), &fetcher(), a).unwrap();
    let text = fs::read_to_string(e.g.sites_dir.join("shop.toml")).unwrap();
    let ms = parse_site(&text).unwrap().config.multisite.unwrap();
    assert_eq!(
        (ms.path.as_str(), ms.site_id, ms.blog_id),
        ("/net/", 2, 4),
        "{text}"
    );
}

#[test]
fn wp_config_one_level_up_is_accepted() {
    let t = tmp();
    let root = t.path().join("public");
    fs::create_dir(&root).unwrap();
    let wr = webroot();
    // Move the webroot under t/public and wp-config.php to t/.
    for e in fs::read_dir(wr.path()).unwrap() {
        let e = e.unwrap();
        fs::rename(e.path(), root.join(e.file_name())).unwrap();
    }
    fs::rename(root.join("wp-config.php"), t.path().join("wp-config.php")).unwrap();
    let e = env();
    let h = host();
    go(&e, &h, &fetcher(), args(&root)).unwrap();
    assert!(e.g.sites_dir.join("shop.toml").exists());
}

// The www uid gets a temporary search ACL on <base> for the uploads copy only.
fn acl_grant() -> String {
    format!("setfacl -m u:{}:x /srv/www/shop", www())
}

fn acl_revoke() -> String {
    format!("setfacl -x u:{} /srv/www/shop", www())
}

const ACL_MASK: &str = "setfacl -x m:: /srv/www/shop";

fn cmd_strings(h: &RecordingHost) -> Vec<String> {
    h.calls().iter().map(|c| c.to_string()).collect()
}

fn count(cmds: &[String], p: &str) -> usize {
    cmds.iter().filter(|c| c.starts_with(p)).count()
}

/// Positions of the grant, the rsync, the revoke and the mask removal in the recorded commands.
fn acl_order(h: &RecordingHost) -> [usize; 4] {
    let cmds = cmd_strings(h);
    let pos = |p: &str| {
        cmds.iter()
            .position(|c| c.starts_with(p))
            .unwrap_or_else(|| panic!("no {p:?} in {cmds:#?}"))
    };
    for p in [acl_grant(), acl_revoke(), ACL_MASK.to_string()] {
        assert_eq!(count(&cmds, &p), 1, "{p}: {cmds:#?}");
    }
    [
        pos(&acl_grant()),
        pos(&rsync_prefix()),
        pos(&acl_revoke()),
        pos(ACL_MASK),
    ]
}

fn assert_recovery_acl_order(rec: &[String]) {
    let at = |p: &str| {
        rec.iter()
            .position(|c| c.starts_with(p))
            .unwrap_or_else(|| panic!("no {p:?} in {rec:#?}"))
    };
    let o = [
        at(&acl_grant()),
        at("setpriv"),
        at(&acl_revoke()),
        at(ACL_MASK),
    ];
    assert!(o.windows(2).all(|w| w[0] < w[1]), "{rec:#?}");
}

#[test]
fn uploads_acl_is_granted_before_rsync_then_revoked_and_mask_removed() {
    let wr = webroot();
    let e = env();
    let h = host();
    let rep = go(&e, &h, &fetcher(), args(wr.path())).unwrap();
    let o = acl_order(&h);
    assert!(o.windows(2).all(|w| w[0] < w[1]), "{o:?}");
    assert!(!rep.warnings.iter().any(|w| w.contains("setfacl")));
}

#[test]
fn uploads_acl_is_revoked_when_rsync_fails() {
    let wr = webroot();
    let e = env();
    let h = host().respond(&rsync_prefix(), 12, "", "protocol error");
    let err = go(&e, &h, &fetcher(), args(wr.path())).unwrap_err();
    let o = acl_order(&h);
    assert!(o.windows(2).all(|w| w[0] < w[1]), "{o:?}");
    assert_recovery_acl_order(&err.downcast_ref::<ImportError>().unwrap().report.recovery);
}

#[test]
fn uploads_acl_revoke_failure_is_a_warning_and_skips_the_mask() {
    let wr = webroot();
    let e = env();
    let h = host().respond("setfacl -x u:", 1, "", "Operation not permitted");
    let rep = go(&e, &h, &fetcher(), args(wr.path())).unwrap();
    assert!(
        rep.warnings.iter().any(|w| w.contains(&acl_revoke())),
        "{:?}",
        rep.warnings
    );
    assert_eq!(count(&cmd_strings(&h), ACL_MASK), 0);
}

#[test]
fn uploads_acl_mask_removal_failure_is_only_a_warning() {
    let wr = webroot();
    let e = env();
    let h = host().respond(ACL_MASK, 1, "", "Operation not supported");
    let rep = go(&e, &h, &fetcher(), args(wr.path())).unwrap();
    assert!(
        rep.warnings.iter().any(|w| w.contains(ACL_MASK)),
        "{:?}",
        rep.warnings
    );
}

#[test]
fn uploads_acl_grant_failure_runs_no_rsync_and_no_revoke() {
    let wr = webroot();
    let e = env();
    let h = host().respond("setfacl -m u:", 1, "", "Operation not supported");
    let err = go(&e, &h, &fetcher(), args(wr.path())).unwrap_err();
    let cmds = cmd_strings(&h);
    assert_eq!(count(&cmds, &acl_grant()), 1, "{cmds:#?}");
    assert_eq!(count(&cmds, &rsync_prefix()), 0, "{cmds:#?}");
    assert_eq!(count(&cmds, "setfacl -x"), 0, "{cmds:#?}");
    let rep = &err.downcast_ref::<ImportError>().unwrap().report;
    assert!(
        rep.error
            .as_deref()
            .unwrap()
            .starts_with("copying uploads failed"),
        "{:?}",
        rep.error
    );
    assert_recovery_acl_order(&rep.recovery);
}

#[test]
fn missing_setfacl_or_rsync_is_a_usage_error_before_any_write() {
    for (tool, pkg) in [("setfacl", "acl"), ("rsync", "rsync")] {
        let wr = webroot();
        let e = env();
        let h = host().fail_spawn(&format!("{tool} --version"));
        let err = go(&e, &h, &fetcher(), args(wr.path())).unwrap_err();
        let msg = format!("{err:#}");
        assert!(err.downcast_ref::<UsageError>().is_some(), "{msg}");
        assert!(
            msg.contains(tool) && msg.contains(&format!("({pkg})")),
            "{msg}"
        );
        assert!(!e.g.sites_dir.join("shop.toml").exists());
        assert!(!sys(&h, "/srv/iwp").exists());
        assert!(!h.calls().iter().any(|c| c.program == "mariadb"));
    }
}

// ---- F1: wp-config.php is never read through a symlink ----

#[test]
fn symlinked_wp_config_is_refused_before_anything() {
    // In the webroot.
    let wr = webroot();
    let elsewhere = tmp();
    w(elsewhere.path(), "real-config.php", &wp_config(""));
    fs::remove_file(wr.path().join("wp-config.php")).unwrap();
    symlink(
        elsewhere.path().join("real-config.php"),
        wr.path().join("wp-config.php"),
    )
    .unwrap();
    let e = env();
    let h = host();
    let err = go(&e, &h, &fetcher(), args(wr.path())).unwrap_err();
    let msg = format!("{err:#}");
    assert!(err.downcast_ref::<UsageError>().is_some(), "{msg}");
    let real = fs::canonicalize(wr.path()).unwrap().join("wp-config.php");
    assert!(
        msg.contains(&real.display().to_string()) && msg.contains("symlink"),
        "{msg}"
    );
    assert!(!e.g.sites_dir.join("shop.toml").exists());
    assert!(!sys(&h, "/srv/iwp").exists());

    // One level up.
    let t = tmp();
    let root = t.path().join("public");
    fs::create_dir(&root).unwrap();
    let wr = webroot();
    for en in fs::read_dir(wr.path()).unwrap() {
        let en = en.unwrap();
        fs::rename(en.path(), root.join(en.file_name())).unwrap();
    }
    fs::remove_file(root.join("wp-config.php")).unwrap();
    symlink(
        elsewhere.path().join("real-config.php"),
        t.path().join("wp-config.php"),
    )
    .unwrap();
    let e = env();
    let h = host();
    let err = go(&e, &h, &fetcher(), args(&root)).unwrap_err();
    let msg = format!("{err:#}");
    assert!(err.downcast_ref::<UsageError>().is_some(), "{msg}");
    let up = fs::canonicalize(t.path()).unwrap().join("wp-config.php");
    assert!(
        msg.contains(&up.display().to_string()) && msg.contains("symlink"),
        "{msg}"
    );
    assert!(!e.g.sites_dir.join("shop.toml").exists());
}

#[test]
fn wp_config_owner_differing_from_the_webroot_warns() {
    assert_eq!(
        wp_config_owner_warning(Path::new("/w/wp-config.php"), 5, 5),
        None
    );
    let w = wp_config_owner_warning(Path::new("/w/wp-config.php"), 0, 1001).unwrap();
    assert!(
        w.contains("/w/wp-config.php") && w.contains("uid 0") && w.contains("uid 1001"),
        "{w}"
    );
}

// ---- F2: cross-site DB isolation ----

fn with_db_user(wr: &tempfile::TempDir, user: &str) {
    w(
        wr.path(),
        "wp-config.php",
        &wp_config("").replace(
            "define( 'DB_USER', 'wpuser' );",
            &format!("define( 'DB_USER', '{user}' );"),
        ),
    );
}

fn assert_nothing_written(e: &Env, h: &RecordingHost) {
    assert!(!e.g.sites_dir.join("shop.toml").exists());
    assert!(!sys(h, "/srv/iwp").exists());
    assert!(!sys(h, "/srv/www").exists());
    assert!(!h.calls().iter().any(|c| c.to_string()
        == "mariadb --socket=/var/lib/mysql/mysql.sock --batch"
        || c.to_string().starts_with("podman secret create")));
}

#[test]
fn system_db_users_are_refused_without_new_db_user() {
    for user in ["root", "mysql", "debian-sys-maint", "mariadb.sys"] {
        let wr = webroot();
        with_db_user(&wr, user);
        let e = env();
        let h = host();
        let err = go(&e, &h, &fetcher(), args(wr.path())).unwrap_err();
        let msg = format!("{err:#}");
        assert!(err.downcast_ref::<UsageError>().is_some(), "{user}: {msg}");
        assert!(msg.contains("--new-db-user") && msg.contains(user), "{msg}");
        assert_nothing_written(&e, &h);
    }
    // --new-db-user avoids it.
    let wr = webroot();
    with_db_user(&wr, "root");
    let e = env();
    let mut a = args(wr.path());
    a.new_db_user = true;
    go(&e, &host(), &fetcher(), a).unwrap();
}

#[test]
fn db_user_of_another_site_file_is_refused() {
    let wr = webroot();
    let e = env();
    fs::write(
        e.g.sites_dir.join("other.toml"),
        "name = \"other\"\ndomains = [\"other.example\"]\nid = 7\n[core]\nwordpress = \"7.1.2\"\nphp = \"8.3\"\n[database]\nuser = \"wpuser\"\n",
    )
    .unwrap();
    let h = host();
    let err = go(&e, &h, &fetcher(), args(wr.path())).unwrap_err();
    let msg = format!("{err:#}");
    assert!(err.downcast_ref::<UsageError>().is_some(), "{msg}");
    assert!(
        msg.contains("--new-db-user") && msg.contains("other.toml"),
        "{msg}"
    );
    assert_nothing_written(&e, &h);
}

#[test]
fn existing_db_account_at_the_subnet_is_refused_before_any_write() {
    let wr = webroot();
    let e = env();
    let h = RecordingHost::new(true)
        .respond(USER_COUNT, 0, "1\n", "")
        .respond("podman network inspect", 0, "10.88.0.0/16 10.88.0.1\n", "")
        .respond(
            "podman secret inspect --showsecret",
            125,
            "",
            "no such secret",
        );
    let err = go(&e, &h, &fetcher(), args(wr.path())).unwrap_err();
    let msg = format!("{err:#}");
    assert!(err.downcast_ref::<UsageError>().is_some(), "{msg}");
    assert!(
        msg.contains("'wpuser'@'10.88.0.0/255.255.0.0' already exists")
            && msg.contains("--new-db-user"),
        "{msg}"
    );
    let q = h
        .calls()
        .into_iter()
        .find(|c| c.to_string() == USER_COUNT)
        .unwrap();
    assert_eq!(
        String::from_utf8(q.stdin.clone().unwrap()).unwrap(),
        "SELECT COUNT(*) FROM mysql.user WHERE User = 'wpuser' AND Host = '10.88.0.0/255.255.0.0';\n"
    );
    assert_eq!(q.timeout, Some(Duration::from_secs(60)));
    assert_nothing_written(&e, &h);
}

// ---- F3: PHP-like files in the old uploads are listed ----

#[test]
fn uploads_php_lists_htaccess_stubs_and_code() {
    let wr = webroot();
    let r = wr.path();
    w(
        r,
        "wp-content/uploads/wpcf7_uploads/.htaccess",
        "Require all denied\n",
    );
    w(
        r,
        "wp-content/uploads/index.php",
        "<?php\n// Silence is golden.\n",
    );
    w(
        r,
        "wp-content/uploads/2024/evil.php",
        "<?php system($_GET['c']);",
    );
    let e = env();
    let rep = go(&e, &host(), &fetcher(), args(r)).unwrap();
    assert_eq!(
        rep.uploads_php,
        vec![
            "wp-content/uploads/2024/evil.php (PHP: `iwp verify` reports it as shared_php; delete it before the first deploy)",
            "wp-content/uploads/index.php (silence stub: `iwp verify` only notes it)",
            "wp-content/uploads/wpcf7_uploads/.htaccess (.htaccess/.user.ini: inert under nginx; `iwp verify` only notes it)",
        ]
    );
    assert!(
        rep.warnings
            .iter()
            .any(|w| w.contains("1 PHP file(s) in wp-content/uploads")),
        "{:?}",
        rep.warnings
    );
    assert!(
        rep.summary()
            .contains("wp-content/uploads/2024/evil.php (PHP")
    );
}

// ---- F4: other top-level webroot entries are reported ----

#[test]
fn other_root_files_are_reported_with_a_hint() {
    let wr = webroot();
    let r = wr.path();
    w(r, "robots.txt", "User-agent: *\n");
    w(r, ".well-known/security.txt", "x");
    w(r, "phpinfo.php", "<?php phpinfo();");
    w(r, "wp-login.php", "<?php");
    let e = env();
    let rep = go(&e, &host(), &fetcher(), args(r)).unwrap();
    assert_eq!(
        rep.other_root_files,
        vec![
            ".well-known (directory: not carried; serve what you need from the server block)",
            "phpinfo.php (PHP: not supported; review)",
            "robots.txt (static file: not carried; serve it with a server-level `location = /robots.txt`)",
        ]
    );
    let sum = rep.summary();
    assert!(sum.contains("other webroot entries (not carried)"), "{sum}");
    assert!(
        sum.contains("phpinfo.php (PHP: not supported; review)"),
        "{sum}"
    );
}

// ---- F9: the host-wide sites lock covers id assignment and the site-file installation ----

#[test]
fn import_waits_for_the_sites_lock_before_assigning_the_id() {
    let wr = webroot();
    let e = env();
    let lock_host = host();
    let held = crate::host::lock::SitesLock::acquire(&lock_host).unwrap();
    let root = lock_host.sysroot().to_path_buf();
    let (g, from) = (e.g.clone(), wr.path().to_path_buf());
    let cache_dir = tmp();
    let cache_path = cache_dir.path().to_path_buf();
    let (tx, rx) = std::sync::mpsc::channel();
    let th = std::thread::spawn(move || {
        let h = RecordingHost::with_root(&root)
            .respond(USER_COUNT, 0, "0\n", "")
            .respond("podman network inspect", 0, "10.88.0.0/16 10.88.0.1\n", "")
            .respond(
                "podman secret inspect --showsecret",
                125,
                "",
                "no such secret",
            );
        let f = fetcher();
        let cache = Cache::new(&cache_path);
        let ctx = ImportCtx {
            wporg: WpOrg {
                fetcher: &f,
                cache: &cache,
            },
        };
        let r = run(&h, &g, &ctx, args(&from)).map(|_| ());
        tx.send(()).unwrap();
        r
    });
    assert!(
        rx.recv_timeout(std::time::Duration::from_millis(500))
            .is_err()
    );
    assert!(!e.g.sites_dir.join("shop.toml").exists());
    // Meanwhile another site took id 1.
    fs::write(
        e.g.sites_dir.join("other.toml"),
        crate::lifecycle::setup::new_site_text(
            "other",
            &["other.example".into()],
            None,
            1,
            "7.1.2",
            "8.3",
        ),
    )
    .unwrap();
    drop(held);
    rx.recv_timeout(std::time::Duration::from_secs(20)).unwrap();
    th.join().unwrap().unwrap();
    let s = parse_site(&fs::read_to_string(e.g.sites_dir.join("shop.toml")).unwrap()).unwrap();
    assert_eq!(s.id, 2);
}

// ---- F10: more report lines ----

#[test]
fn report_lists_runtime_files_custom_translations_and_wpconfig_warnings() {
    let wr = webroot();
    let r = wr.path();
    // A wordpress.org-clean plugin with runtime files beside it.
    for i in 0..7 {
        w(
            r,
            &format!("wp-content/plugins/clean/cache/c{i}.json"),
            "{}",
        );
    }
    // Translations: wordpress.org slug (fine), custom slugs and Loco.
    w(r, "wp-content/languages/plugins/clean-hr.mo", "mo");
    w(r, "wp-content/languages/plugins/custom-hr.mo", "mo");
    w(r, "wp-content/languages/themes/mytheme-hr.po", "po");
    w(r, "wp-content/languages/loco/plugins/clean-hr.mo", "mo");
    w(
        r,
        "wp-config.php",
        &wp_config("define('UPLOADS', 'media');\ndefine('WP_REDIS_HOST', 'localhost');\n"),
    );
    let e = env();
    let rep = go(&e, &host(), &fetcher(), args(r)).unwrap();
    let clean = rep.packages.iter().find(|p| p.slug == "clean").unwrap();
    assert_eq!(clean.verdict, "wporg");
    let ws = rep.warnings.join("\n");
    assert!(
        ws.contains("plugin clean: 7 local-only file(s) are not carried (runtime files): cache/c0.json, cache/c1.json, cache/c2.json, cache/c3.json, cache/c4.json (and 2 more)"),
        "{ws}"
    );
    assert_eq!(
        rep.custom_translations,
        vec![
            "wp-content/languages/loco/plugins/clean-hr.mo",
            "wp-content/languages/plugins/custom-hr.mo",
            "wp-content/languages/themes/mytheme-hr.po",
        ]
    );
    assert!(rep.summary().contains("custom translations (not carried)"));
    assert!(ws.contains("UPLOADS is defined"), "{ws}");
    assert!(ws.contains("WP_REDIS_HOST points at this host"), "{ws}");
}

// ---- F11: the revoke commands are printed before the copy starts ----

#[test]
fn interrupt_hint_names_the_revoke_and_mask_commands() {
    let base = Path::new("/srv/www/shop");
    let h = interrupt_hint(
        &super::acl_revoke(www(), base).unwrap(),
        &acl_mask_remove(base).unwrap(),
    );
    assert!(
        h.contains("if this is interrupted")
            && h.contains(&format!("{}; {ACL_MASK}", acl_revoke())),
        "{h}"
    );
}

fn site_id(e: &Env) -> u32 {
    crate::config::load_site(&e.g.sites_dir.join("shop.toml"))
        .unwrap()
        .site
        .id
}

#[test]
fn missing_sites_dir_is_created() {
    let wr = webroot();
    let e = env();
    fs::remove_dir(&e.g.sites_dir).unwrap();
    go(&e, &host(), &fetcher(), args(wr.path())).unwrap();
    assert_eq!(site_id(&e), 1);
}

#[test]
fn id_skips_subid_overlaps_and_can_be_given() {
    let wr = webroot();
    let e = env();
    let h = host();
    // Site 1's ID range is somebody's subuid range.
    let lo = crate::host::identity::Identity::for_site(1, e.g.id_offset).base_id;
    fs::create_dir_all(sys(&h, "/etc")).unwrap();
    fs::write(sys(&h, "/etc/subuid"), format!("cloud:{lo}:65536\n")).unwrap();
    let mut a = args(wr.path());
    a.id = Some(1);
    let err = go(&e, &h, &fetcher(), a).unwrap_err();
    assert!(
        err.downcast_ref::<crate::error::UsageError>().is_some(),
        "{err:#}"
    );
    assert!(format!("{err:#}").contains("/etc/subuid:1"), "{err:#}");
    assert_nothing_written(&e, &h);
    go(&e, &h, &fetcher(), args(wr.path())).unwrap();
    assert_eq!(site_id(&e), 2);
}

#[test]
fn explicit_id_is_written_to_the_site_file() {
    let wr = webroot();
    let e = env();
    let mut a = args(wr.path());
    a.id = Some(9);
    go(&e, &host(), &fetcher(), a).unwrap();
    assert_eq!(site_id(&e), 9);
}

#[test]
fn report_falls_back_to_the_cache_dir_when_the_base_cannot_be_created() {
    let wr = webroot();
    let e = env();
    let h = host();
    // Setup fails before <base>/config exists: the base's parent is a file.
    fs::create_dir_all(sys(&h, "/srv")).unwrap();
    fs::write(sys(&h, "/srv/www"), "").unwrap();
    let err = go(&e, &h, &fetcher(), args(wr.path())).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("setup failed"), "{msg}");
    let fallback = e.g.cache_dir.join("import-report-shop.json");
    assert!(msg.contains(&fallback.display().to_string()), "{msg}");
    let json = fs::read_to_string(sys(&h, &fallback)).unwrap();
    assert!(json.contains("iwp setup shop --salts-from"), "{json}");
    assert_no_secrets(&json, "report");
    let rep = &err.downcast_ref::<ImportError>().unwrap().report;
    assert!(
        rep.error
            .as_deref()
            .unwrap()
            .contains(&fallback.display().to_string())
    );
    assert!(rep.written.contains(&fallback), "{:?}", rep.written);
    assert!(
        !rep.written
            .iter()
            .any(|p| p.ends_with("config/import-report.json"))
    );
}

#[test]
fn report_that_cannot_be_written_anywhere_says_so() {
    let wr = webroot();
    let mut e = env();
    let h = host();
    fs::create_dir_all(sys(&h, "/srv")).unwrap();
    fs::write(sys(&h, "/srv/www"), "").unwrap();
    // The fallback directory cannot be created either: its parent is a file.
    fs::create_dir_all(sys(&h, "/var")).unwrap();
    fs::write(sys(&h, "/var/blocked"), "").unwrap();
    e.g.cache_dir = PathBuf::from("/var/blocked/iwp");
    let err = go(&e, &h, &fetcher(), args(wr.path())).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("setup failed"), "{msg}");
    assert!(msg.contains("only in this output"), "{msg}");
    assert!(!msg.contains("recovery commands are in /"), "{msg}");
    let rep = &err.downcast_ref::<ImportError>().unwrap().report;
    assert!(
        rep.error
            .as_deref()
            .unwrap()
            .contains("only in this output")
    );
    assert!(
        !rep.written
            .iter()
            .any(|p| p.ends_with("import-report.json")),
        "{:?}",
        rep.written
    );
}
