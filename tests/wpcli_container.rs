//! IWP_PODMAN_TESTS=1: the wp-cli podman invocation runs in the real cli image.
use iwp::config::{GlobalConfig, parse_site};

#[test]
fn wp_cli_starts_with_site_identity() {
    if std::env::var("IWP_PODMAN_TESTS").as_deref() != Ok("1") {
        eprintln!("skipped (set IWP_PODMAN_TESTS=1)");
        return;
    }
    let t = tempfile::tempdir().unwrap();
    let base = t.path().join("site");
    for d in [
        "current/wp-content/plugins",
        "current/wp-content/themes",
        "current/wp-content/mu-plugins",
        "current/wp-content/languages",
        "shared/uploads",
        "config",
    ] {
        std::fs::create_dir_all(base.join(d)).unwrap();
    }
    for f in ["wp-config.site.php", "zz-site.ini", "zz-site.conf"] {
        std::fs::write(
            base.join("config").join(f),
            if f.ends_with(".php") { "<?php\n" } else { "" },
        )
        .unwrap();
    }
    let site = parse_site(&format!(
        "name = \"t\"\nbase = {:?}\ndomains = [\"t.example\"]\nid = 1\n[core]\nwordpress = \"7.1.2\"\nphp = \"8.3\"\n",
        base.display().to_string()
    ))
    .unwrap();
    let g = GlobalConfig::default();
    let mut c = iwp::lifecycle::wpcli::podman_cmd(
        &g,
        &site,
        "10.88.0.1".parse().unwrap(),
        iwp::lifecycle::wpcli::Entry::Capture(&["--version".to_string()]),
        false,
        None,
    );
    // No secrets / rootful uidmap in a rootless test run: strip --secret and map options.
    let mut a = Vec::new();
    let mut it = c.args.drain(..);
    while let Some(x) = it.next() {
        if matches!(x.as_str(), "--secret" | "--uidmap" | "--gidmap") {
            it.next();
            continue;
        }
        if x.starts_with("label=level") {
            a.pop();
            continue;
        }
        a.push(x);
    }
    let out = std::process::Command::new("podman")
        .args(&a)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("WP-CLI "));
}
