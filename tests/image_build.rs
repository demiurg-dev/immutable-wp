//! Opt-in: IWP_PODMAN_TESTS=1 cargo test --test image_build -- --nocapture  (builds images: slow)
use std::process::Command;

fn podman(args: &[&str]) -> (bool, String) {
    let o = Command::new("podman").args(args).output().unwrap();
    (
        o.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        ),
    )
}

#[test]
fn image_builds_and_behaves() {
    if std::env::var_os("IWP_PODMAN_TESTS").is_none() {
        eprintln!("skipped: set IWP_PODMAN_TESTS=1");
        return;
    }
    let st = Command::new(env!("CARGO_BIN_EXE_iwp"))
        .args(["image", "build", "7.1.2", "8.3"])
        .status()
        .unwrap();
    assert!(st.success(), "iwp image build failed");
    let fpm = "localhost/iwp-fpm:7.1.2-php8.3";

    let (ok, out) = podman(&["run", "--rm", fpm, "id", "-u"]);
    assert!(
        ok && out.trim() == "33",
        "fpm image must run as uid 33: {out}"
    );
    let (ok, out) = podman(&["run", "--rm", fpm, "php-fpm", "-tt"]);
    assert!(ok, "php-fpm config test failed: {out}");
    assert!(out.contains("listen = /run/iwp/php.sock"), "{out}");
    assert!(out.contains("security.limit_extensions = .php"), "{out}");
    let (ok, out) = podman(&["run", "--rm", fpm, "php", "-m"]);
    assert!(ok, "{out}");
    let modules: Vec<&str> = out.lines().map(str::trim).collect();
    for m in [
        "imagick",
        "gd",
        "intl",
        "zip",
        "exif",
        "mysqli",
        "pdo_mysql",
        "Zend OPcache",
    ] {
        assert!(modules.contains(&m), "php -m lacks {m}: {out}");
    }
    assert!(modules.contains(&"ldap"), "ldap missing: {out}");
    let (ok, cfg) = podman(&["run", "--rm", fpm, "cat", "/var/www/html/wp-config.php"]);
    assert!(ok, "{cfg}");
    let site_req = cfg
        .find("require '/etc/iwp/wp-config.site.php';")
        .expect("site require");
    let charset = cfg
        .find("if ( ! defined( 'DB_CHARSET' ) )")
        .expect("charset fallback");
    assert!(
        charset > site_req,
        "charset fallback must follow the site config"
    );
    let (ok, out) = podman(&[
        "run",
        "--rm",
        fpm,
        "php",
        "-r",
        "$i = gd_info(); echo (int)$i['AVIF Support'], (int)$i['WebP Support'], (int)$i['JPEG Support'], (int)$i['FreeType Support'];",
    ]);
    assert!(
        ok && out.trim() == "1111",
        "gd lacks AVIF/WebP/JPEG/FreeType: {out}"
    );
    // No compiler in the production image.
    for bin in ["gcc", "cc", "g++", "make", "cpp"] {
        let (found, out) = podman(&["run", "--rm", fpm, "sh", "-c", &format!("command -v {bin}")]);
        assert!(!found, "{bin} must not be in the fpm image: {out}");
    }
    // Core is root-owned 644/755, so www-data cannot modify it even without a read-only rootfs.
    let (_, out) = podman(&[
        "run",
        "--rm",
        fpm,
        "sh",
        "-c",
        "touch /var/www/html/wp-includes/x 2>/dev/null && echo writable || echo denied",
    ]);
    assert_eq!(
        out.trim(),
        "denied",
        "core must not be writable by www-data"
    );

    // wp-config loads secrets, prefix and site config (fake ABSPATH to stop before wp-settings.php)
    let dir = tempfile::Builder::new()
        .prefix("iwp-test-")
        .tempdir()
        .unwrap();
    std::fs::write(
        dir.path().join("db"),
        "DB_NAME=wp_t\nDB_USER=iwp_t\nDB_PASSWORD=a;b\"c=d$e f \nDB_PREFIX=acme_\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("salts"), "<?php define('AUTH_KEY','k');").unwrap();
    std::fs::write(
        dir.path().join("site.php"),
        "<?php define('IWP_SITE_LOADED', true);",
    )
    .unwrap();
    let v = |f: &str, t: &str| format!("{}:{t}:ro,z", dir.path().join(f).display());
    let (ok, out) = podman(&[
        "run",
        "--rm",
        "-v",
        &v("db", "/run/secrets/iwp-db"),
        "-v",
        &v("salts", "/run/secrets/iwp-salts"),
        "-v",
        &v("site.php", "/etc/iwp/wp-config.site.php"),
        fpm,
        "php",
        "-r",
        "define('ABSPATH','/tmp/fake/'); @mkdir('/tmp/fake'); file_put_contents('/tmp/fake/wp-settings.php','<?php'); \
         require '/var/www/html/wp-config.php'; echo DB_NAME,'|',DB_HOST,'|',$table_prefix,'|',(int)DISALLOW_FILE_MODS,'|',(int)IWP_SITE_LOADED,'|[',DB_PASSWORD,']';",
    ]);
    assert!(ok, "{out}");
    assert_eq!(out.trim(), "wp_t|iwp-db-host|acme_|1|1|[a;b\"c=d$e f ]");

    let cli = "localhost/iwp-cli:7.1.2-php8.3";
    let (ok, out) = podman(&["run", "--rm", cli, "wp", "--version", "--allow-root"]);
    assert!(ok && out.contains("2.12.0"), "{out}");
}
