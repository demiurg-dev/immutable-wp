use std::process::Command;

pub fn iwp() -> Command {
    Command::new(env!("CARGO_BIN_EXE_iwp"))
}

#[test]
fn version_prints_crate_version() {
    let out = iwp().arg("--version").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(stdout.trim(), format!("iwp {}", env!("CARGO_PKG_VERSION")));
}
fn sites_env() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::Builder::new()
        .prefix("iwp-test-")
        .tempdir()
        .unwrap();
    let sites = dir.path().join("sites");
    std::fs::create_dir(&sites).unwrap();
    std::fs::copy(
        concat!(env!("CARGO_MANIFEST_DIR"), "/examples/acme.toml"),
        sites.join("acme.toml"),
    )
    .unwrap();
    let global = dir.path().join("iwp.toml");
    std::fs::write(&global, format!("sites_dir = {:?}\n", sites)).unwrap();
    (dir, global)
}

/// Like `sites_env`, but the site's `base` points into the temp dir (which does not hold it yet).
fn sites_env_with_base() -> (tempfile::TempDir, std::path::PathBuf) {
    let (dir, global) = sites_env();
    let site = dir.path().join("sites/acme.toml");
    let text = std::fs::read_to_string(&site).unwrap();
    let base = dir.path().join("base");
    let text: String = text
        .lines()
        .map(|l| {
            if l.trim_start().starts_with("base ") || l.trim_start().starts_with("base=") {
                format!("base = {:?}", base.display().to_string())
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&site, text + "\n").unwrap();
    (dir, global)
}

#[test]
fn wp_intercepts_code_changes_before_root_or_podman() {
    let (_dir, global) = sites_env();
    let o = iwp()
        .arg("--config")
        .arg(&global)
        .args([
            "wp",
            "acme",
            "--skip-plugins",
            "plugin",
            "install",
            "hello-dolly",
        ])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("iwp deploy") && err.contains("plugin install hello-dolly"),
        "{err}"
    );
}

#[test]
fn releases_and_status_read_only_on_unset_site() {
    let (_dir, global) = sites_env_with_base();
    let o = iwp()
        .arg("--config")
        .arg(&global)
        .args(["releases", "acme"])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(String::from_utf8_lossy(&o.stdout).contains("no releases"));
    let o = iwp()
        .arg("--config")
        .arg(&global)
        .args(["status", "acme", "--json"])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v[0]["name"], "acme");
    assert!(v[0]["current"].is_null());
}

#[test]
fn plugin_set_add_rm_roundtrip() {
    let (dir, global) = sites_env();
    let run = |args: &[&str]| {
        iwp()
            .arg("--config")
            .arg(&global)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(
        run(&["plugin", "set", "acme", "gutena-tabs@1.0.12"])
            .status
            .success()
    );
    assert!(
        run(&["plugin", "add", "acme", "redis-cache@2.6.0"])
            .status
            .success()
    );
    assert!(
        run(&["theme", "rm", "acme", "hello-elementor"])
            .status
            .success()
    );
    let text = std::fs::read_to_string(dir.path().join("sites/acme.toml")).unwrap();
    assert!(text.contains("\"1.0.12\"   # WP 6.9+ compatible"));
    assert!(text.contains("redis-cache"));
    assert!(!text.contains("hello-elementor"));
}

#[test]
fn plugin_set_invalid_version_exit_2_file_unchanged() {
    let (dir, global) = sites_env();
    let before = std::fs::read_to_string(dir.path().join("sites/acme.toml")).unwrap();
    let out = iwp()
        .arg("--config")
        .arg(&global)
        .args(["plugin", "set", "acme", "gutena-tabs@1.0;rm"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("sites/acme.toml")).unwrap(),
        before
    );
}

#[test]
fn plugin_add_requires_version() {
    let (_dir, global) = sites_env();
    let out = iwp()
        .arg("--config")
        .arg(&global)
        .args(["plugin", "add", "acme", "redis-cache"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn plugin_add_path_pins_the_directory() {
    let (dir, global) = sites_env();
    let text = std::fs::read_to_string(&global).unwrap();
    let cache = dir.path().join("cache");
    std::fs::write(&global, format!("{text}cache_dir = {cache:?}\n")).unwrap();
    let src = dir.path().join("ours");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("ours.php"), "<?php").unwrap();
    let out = iwp()
        .arg("--config")
        .arg(&global)
        .args(["plugin", "add", "acme", "ours", "--path"])
        .arg(&src)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("pinned plugin[ours] "));
    let text = std::fs::read_to_string(dir.path().join("sites/acme.toml")).unwrap();
    assert!(
        text.contains(&format!("source = {{ path = {:?} }}", src)) && text.contains("sha256 = "),
        "{text}"
    );
    let out = iwp()
        .arg("--config")
        .arg(&global)
        .args(["validate", "acme"])
        .output()
        .unwrap();
    assert!(out.status.success());
}

#[test]
fn plugin_add_source_usage_errors() {
    let (dir, global) = sites_env();
    let before = std::fs::read_to_string(dir.path().join("sites/acme.toml")).unwrap();
    let cases: Vec<Vec<&str>> = vec![
        vec!["plugin", "add", "acme", "p@1.0", "--url", "https://e/p.zip"],
        vec!["plugin", "add", "acme", "p@1.0", "--path", "/srv/p"],
        vec!["plugin", "add", "acme", "p", "--url", "http://e/p.zip"],
        vec!["plugin", "add", "acme", "p", "--path", "/nonexistent/p"],
        vec![
            "plugin",
            "add",
            "acme",
            "p",
            "--url",
            "https://e/p.zip",
            "--path",
            "/srv/p",
        ],
    ];
    for args in cases {
        let out = iwp()
            .arg("--config")
            .arg(&global)
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
    }
    assert_eq!(
        std::fs::read_to_string(dir.path().join("sites/acme.toml")).unwrap(),
        before
    );
}

#[test]
fn validate_ok_and_collision() {
    let (dir, global) = sites_env();
    let out = iwp()
        .arg("--config")
        .arg(&global)
        .arg("validate")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8(out.stdout).unwrap().trim(),
        "ok: 1 site(s)"
    );

    let dup = std::fs::read_to_string(dir.path().join("sites/acme.toml"))
        .unwrap()
        .replace("name    = \"acme\"", "name    = \"other\"");
    std::fs::write(dir.path().join("sites/other.toml"), dup).unwrap();
    let out = iwp()
        .arg("--config")
        .arg(&global)
        .arg("validate")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(err.contains("id 3 used by acme.toml, other.toml"), "{err}");
    assert!(
        err.contains("domain www.example.org used by acme.toml, other.toml"),
        "{err}"
    );
}

#[test]
fn render_writes_all_outputs() {
    let (dir, global) = sites_env();
    let out_dir = dir.path().join("out");
    let out = iwp()
        .arg("--config")
        .arg(&global)
        .args(["render", "acme", "--out"])
        .arg(&out_dir)
        .args(["--db-host-ip", "10.89.0.1"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for rel in iwp::render::output_paths("acme") {
        assert!(out_dir.join(&rel).is_file(), "{rel}");
    }
    let q = std::fs::read_to_string(out_dir.join("containers/iwp-acme.container")).unwrap();
    assert!(q.contains("AddHost=iwp-db-host:10.89.0.1"));
    // refuses a non-empty output dir
    let again = iwp()
        .arg("--config")
        .arg(&global)
        .args(["render", "acme", "--out"])
        .arg(&out_dir)
        .output()
        .unwrap();
    assert_eq!(again.status.code(), Some(2));
}

#[test]
fn render_refuses_invalid_site() {
    let (dir, global) = sites_env();
    let p = dir.path().join("sites/acme.toml");
    let bad = std::fs::read_to_string(&p).unwrap().replace(
        "\"www.example.org\", \"shop",
        "\"www.example.org;\", \"shop",
    );
    std::fs::write(&p, bad).unwrap();
    let out = iwp()
        .arg("--config")
        .arg(&global)
        .args(["render", "acme", "--out"])
        .arg(dir.path().join("o"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(!dir.path().join("o").exists());
}

#[test]
fn committed_schema_is_current() {
    let out = iwp().arg("schema").output().unwrap();
    assert!(out.status.success());
    let committed = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/schema/site.schema.json"
    ))
    .expect("run: cargo run -q -- schema > schema/site.schema.json");
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        committed,
        "schema is stale: cargo run -q -- schema > schema/site.schema.json"
    );
}

#[test]
fn bad_global_config_exits_2_for_validate_and_render() {
    let (dir, global) = sites_env();
    let mut text = std::fs::read_to_string(&global).unwrap();
    text.push_str("podman_network = \"x;y\"\n");
    std::fs::write(&global, text).unwrap();
    let out = dir.path().join("out");
    for args in [
        vec!["validate"],
        vec!["render", "acme", "--out", out.to_str().unwrap()],
    ] {
        let o = iwp()
            .arg("--config")
            .arg(&global)
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(2), "{args:?}");
        let err = String::from_utf8(o.stderr).unwrap();
        assert!(err.contains("iwp.toml: podman_network"), "{err}");
    }
    assert!(!out.exists());
}

#[test]
fn image_build_rejects_bad_versions() {
    for args in [
        ["image", "build", "abc", "8.3"],
        ["image", "build", "7.1.2", "7.4"],
    ] {
        let out = iwp().args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
    }
}

#[test]
fn build_and_pin_unknown_site_exit_2() {
    let (_dir, global) = sites_env();
    for cmd in [["build", "nope"], ["pin", "nope"], ["outdated", "nope"]] {
        let out = iwp()
            .arg("--config")
            .arg(&global)
            .args(cmd)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{cmd:?}");
    }
}

#[test]
fn site_arguments_are_validated() {
    let (_dir, global) = sites_env();
    let cases: Vec<Vec<&str>> = vec![
        vec!["plugin", "set", "../x", "a@1"],
        vec!["plugin", "add", "/etc/x", "a@1"],
        vec!["theme", "rm", "Bad", "t"],
        vec!["validate", "../../etc/passwd"],
        vec!["render", "a/b", "--out", "/tmp/x"],
        vec!["build", ".."],
        vec!["pin", "x;y"],
        vec!["outdated", "-x"],
        vec!["verify", "Bad/x"],
    ];
    for args in cases {
        let out = iwp()
            .arg("--config")
            .arg(&global)
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        let err = String::from_utf8_lossy(&out.stderr);
        // `outdated -x` is rejected by clap itself; every other case must hit our check.
        let expected = if args[0] == "outdated" {
            "error:"
        } else {
            "invalid site name"
        };
        assert!(err.contains(expected), "{args:?}: {err}");
    }
}

#[test]
fn host_changing_commands_require_root() {
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipped: running as root");
        return;
    }
    let (_dir, global) = sites_env();
    for args in [
        vec!["nginx", "apply", "acme"],
        vec!["db", "dump", "acme"],
        vec!["db", "restore", "acme", "/tmp/x.sql.gz", "--yes"],
        vec!["selinux", "install"],
        vec!["verify", "acme"],
        vec!["verify", "acme", "--json"],
    ] {
        let out = iwp()
            .arg("--config")
            .arg(&global)
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("must be run as root"),
            "{args:?}"
        );
    }
}

#[test]
fn db_restore_requires_yes() {
    let (_dir, global) = sites_env();
    let out = iwp()
        .arg("--config")
        .arg(&global)
        .args(["db", "restore", "acme", "/tmp/x.sql.gz"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--yes"));
}

#[test]
fn lifecycle_commands_validate_and_require_root() {
    let (_dir, global) = sites_env();
    let run = |args: &[&str]| {
        iwp()
            .arg("--config")
            .arg(&global)
            .args(args)
            .output()
            .unwrap()
    };
    if unsafe { libc::geteuid() } != 0 {
        for a in [
            &["setup", "acme"][..],
            &["deploy", "acme"],
            &["rollback", "acme"],
            &[
                "new",
                "fresh",
                "--domain",
                "fresh.example",
                "--wordpress",
                "7.1.2",
            ],
        ] {
            let o = run(a);
            assert_eq!(o.status.code(), Some(2), "{a:?}");
            assert!(
                String::from_utf8_lossy(&o.stderr).contains("must be run as root"),
                "{a:?}"
            );
        }
    }
    for a in [&["update"][..], &["update", "acme", "--all"]] {
        let o = run(a);
        assert_eq!(o.status.code(), Some(2), "{a:?}");
        assert!(
            String::from_utf8_lossy(&o.stderr).contains("either <site> or --all"),
            "{a:?}"
        );
    }
    if unsafe { libc::geteuid() } != 0 {
        let o = run(&["update", "--all", "--dry-run"]);
        assert_eq!(o.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&o.stderr).contains("must be run as root"));
    }
    let o = run(&["rollback", "acme", "--with-db"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("--yes"));
    let o = run(&[
        "new",
        "acme",
        "--domain",
        "x.example",
        "--wordpress",
        "7.1.2",
    ]);
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("already exists"));
    let o = run(&["rollback", "acme", "../etc"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("not a release name"));
}

#[test]
fn new_writes_nothing_before_root_check() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let (dir, global) = sites_env();
    let sites = dir.path().join("sites");
    let before: Vec<_> = std::fs::read_dir(&sites)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    let mut perm = std::fs::metadata(&sites).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perm, 0o555);
    std::fs::set_permissions(&sites, perm.clone()).unwrap();
    let o = iwp()
        .arg("--config")
        .arg(&global)
        .args([
            "new",
            "fresh",
            "--domain",
            "fresh.example",
            "--wordpress",
            "7.1.2",
        ])
        .output()
        .unwrap();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perm, 0o755);
    std::fs::set_permissions(&sites, perm).unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("must be run as root"));
    let after: Vec<_> = std::fs::read_dir(&sites)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(before, after);
}

/// A minimal classic webroot that needs no wordpress.org lookup (only a mu-plugin).
fn old_webroot() -> tempfile::TempDir {
    let d = tempfile::Builder::new()
        .prefix("iwp-test-")
        .tempdir()
        .unwrap();
    let w = |rel: &str, body: &str| {
        let p = d.path().join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    };
    w("wp-includes/version.php", "<?php\n$wp_version = '7.1.2';\n");
    let salts: String = [
        "AUTH_KEY",
        "SECURE_AUTH_KEY",
        "LOGGED_IN_KEY",
        "NONCE_KEY",
        "AUTH_SALT",
        "SECURE_AUTH_SALT",
        "LOGGED_IN_SALT",
        "NONCE_SALT",
    ]
    .iter()
    .map(|k| format!("define('{k}', 'v-{k}');\n"))
    .collect();
    w(
        "wp-config.php",
        &format!(
            "<?php\ndefine('DB_NAME','old');\ndefine('DB_USER','olduser');\n\
             define('DB_PASSWORD','hunter2');\ndefine('DB_HOST','localhost');\n\
             $table_prefix = 'wp_';\n{salts}"
        ),
    );
    w("wp-content/mu-plugins/tweaks.php", "<?php");
    d
}

#[test]
fn import_usage_errors_exit_2_before_root() {
    let (dir, global) = sites_env();
    let old = old_webroot();
    let run = |args: &[&str]| {
        iwp()
            .arg("--config")
            .arg(&global)
            .arg("import")
            .args(args)
            .output()
            .unwrap()
    };
    let from = old.path().to_str().unwrap();
    let cases: [(&[&str], &str); 4] = [
        (&["fresh"], "--from"),
        (&["Bad!", "--from", from], "invalid site name"),
        (&["acme", "--from", from], "already exists"),
        (
            &["fresh", "--from", dir.path().to_str().unwrap()],
            "not a WordPress root",
        ),
    ];
    for (a, msg) in cases {
        let o = run(a);
        assert_eq!(o.status.code(), Some(2), "{a:?}");
        let err = String::from_utf8_lossy(&o.stderr);
        assert!(err.contains(msg), "{a:?}: {err}");
    }
    if unsafe { libc::geteuid() } != 0 {
        let o = run(&[
            "fresh",
            "--from",
            from,
            "--domain",
            "fresh.example",
            "--json",
        ]);
        let err = String::from_utf8_lossy(&o.stderr);
        assert_eq!(o.status.code(), Some(2), "{err}");
        assert!(err.contains("must be run as root"), "{err}");
        assert!(!err.contains("hunter2") && o.stdout.is_empty());
        assert!(!dir.path().join("sites/fresh.toml").exists());
    }
}

#[test]
fn import_non_root_exits_2_before_any_lookup() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let (dir, global) = sites_env();
    let cache = dir.path().join("cache");
    let text = std::fs::read_to_string(&global).unwrap();
    std::fs::write(&global, format!("{text}cache_dir = {cache:?}\n")).unwrap();
    let old = old_webroot();
    // A theme makes classify fetch (and cache) the wordpress.org zip, were it reached.
    let t = old.path().join("wp-content/themes/twentytwenty");
    std::fs::create_dir_all(&t).unwrap();
    std::fs::write(
        t.join("style.css"),
        "/*\nTheme Name: TT\nVersion: 2.0\n*/\n",
    )
    .unwrap();
    let o = iwp()
        .arg("--config")
        .arg(&global)
        .args(["import", "fresh", "--from", old.path().to_str().unwrap()])
        .args(["--domain", "fresh.example"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.status.code(), Some(2), "{err}");
    assert!(err.contains("must be run as root"), "{err}");
    assert!(
        !cache.exists(),
        "nothing may be fetched or cached before the root check"
    );
}

#[test]
fn assets_export_writes_every_share_file_and_refuses_non_empty_dir() {
    let dir = tempfile::tempdir().unwrap();
    let out_dir = dir.path().join("assets");
    let o = iwp()
        .args(["assets", "export"])
        .arg(&out_dir)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let stdout = String::from_utf8(o.stdout).unwrap();
    let share = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("share");
    let mut n = 0;
    for e in walkdir::WalkDir::new(&share) {
        let e = e.unwrap();
        if !e.file_type().is_file() {
            continue;
        }
        let rel = e.path().strip_prefix(&share).unwrap();
        let written = out_dir.join(rel);
        assert_eq!(
            std::fs::read(&written).unwrap(),
            std::fs::read(e.path()).unwrap(),
            "{}",
            rel.display()
        );
        assert!(stdout.contains(&written.display().to_string()), "{stdout}");
        n += 1;
    }
    assert!(n >= 17, "{n}");

    // A second export into the now non-empty dir is a usage error.
    let o = iwp()
        .args(["assets", "export"])
        .arg(&out_dir)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("not empty"));
}
