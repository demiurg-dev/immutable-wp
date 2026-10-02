use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;

use iwp::config::{GlobalConfig, parse_site};
use iwp::render::{RenderEnv, render_site};

fn status(port: u16, path: &str) -> u16 {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(s, "GET {path} HTTP/1.0\r\nHost: www.example.org\r\n\r\n").unwrap();
    let mut buf = String::new();
    s.read_to_string(&mut buf).unwrap();
    buf.split_whitespace().nth(1).unwrap().parse().unwrap()
}

/// Removes the container even if an assertion or request panics.
struct Container(String);

impl Drop for Container {
    fn drop(&mut self) {
        let _ = Command::new("podman").args(["rm", "-f", &self.0]).status();
    }
}

/// Paths handed to another UID of the rootless user namespace (symlinks themselves, not their
/// targets), and taken back on drop so the temp dir can be removed.
struct Owned(Vec<std::path::PathBuf>);

impl Owned {
    fn chown(uid: u32, paths: &[&Path]) -> Self {
        let ok = Command::new("podman")
            .args(["unshare", "chown", "-R", "-h", &format!("{uid}:{uid}")])
            .args(paths)
            .status()
            .unwrap()
            .success();
        assert!(ok, "podman unshare chown failed");
        Self(paths.iter().map(|p| p.to_path_buf()).collect())
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        let _ = Command::new("podman")
            .args(["unshare", "chown", "-R", "-h", "0:0"])
            .args(&self.0)
            .status();
    }
}

/// The site's www UID inside the test's user namespace.
const WWW: u32 = 4243;
/// Another site's UID.
const OTHER: u32 = 4242;

#[test]
fn nginx_routes_requests_as_designed() {
    if std::env::var_os("IWP_PODMAN_TESTS").is_none() {
        eprintln!("skipped: set IWP_PODMAN_TESTS=1");
        return;
    }
    let mut site = parse_site(include_str!("../examples/acme.toml")).unwrap();
    site.nginx.php_entrypoints = vec!["/wp-content/plugins/p/ajax.php".into()];
    let out = render_site(&GlobalConfig::default(), &site, &RenderEnv::default()).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let iwp_dir = dir.path().join("iwp");
    std::fs::create_dir(&iwp_dir).unwrap();
    for f in ["acme.conf", "acme.fastcgi.conf"] {
        std::fs::write(iwp_dir.join(f), &out[&format!("nginx/{f}")]).unwrap();
    }
    std::fs::write(dir.path().join("nginx.conf"),
        "events {}\nhttp {\n  include /etc/nginx/mime.types;\n  server {\n    listen 8080;\n    server_name _;\n    include iwp/acme.conf;\n  }\n}\n").unwrap();
    // The production layout: <base>/current -> releases/<name> (root), whose uploads link
    // (owned by the site's www UID, as deploy leaves it) points into <base>/shared/uploads
    // (www-owned). The release itself holds static files only, like a real release.
    let base = dir.path().join("base");
    let rel = base.join("releases/20261001-100000-aaaaaaa");
    for d in ["wp-admin/css", "wp-content/plugins/p"] {
        std::fs::create_dir_all(rel.join(d)).unwrap();
    }
    std::os::unix::fs::symlink("releases/20261001-100000-aaaaaaa", base.join("current")).unwrap();
    std::fs::write(rel.join("wp-admin/css/a.css"), "x").unwrap();
    std::fs::write(rel.join("wp-content/plugins/p/a.js"), "x").unwrap();
    std::fs::write(rel.join("readme.html"), "x").unwrap();
    let up = base.join("shared/uploads");
    std::fs::create_dir_all(&up).unwrap();
    let up_link = rel.join("wp-content/uploads");
    std::os::unix::fs::symlink("../../../shared/uploads", &up_link).unwrap();
    // A file of another owner (as another site's uploads would be), and symlinks to it that
    // a compromised site could plant in its own uploads.
    let other = dir.path().join("other");
    std::fs::create_dir(&other).unwrap();
    std::fs::write(other.join("secret.jpg"), "secret").unwrap();
    std::fs::write(other.join("secret.txt"), "secret").unwrap();
    std::fs::write(up.join("ok.jpg"), "x").unwrap();
    std::os::unix::fs::symlink("ok.jpg", up.join("own.jpg")).unwrap();
    std::os::unix::fs::symlink("/other/secret.jpg", up.join("evil.jpg")).unwrap();
    std::os::unix::fs::symlink("/other/secret.txt", up.join("evil.txt")).unwrap();
    std::os::unix::fs::symlink("/other", up.join("evildir")).unwrap();
    // A link of another owner leading to one of the site's own files.
    std::os::unix::fs::symlink("ok.jpg", up.join("foreign.jpg")).unwrap();
    let _www_guard = Owned::chown(WWW, &[&up, &up_link]);
    let _other_guard = Owned::chown(OTHER, &[&other, &up.join("foreign.jpg")]);

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let name = format!("iwp-nginx-test-{port}");
    let mount = |src: &Path, dst: &str| format!("{}:{dst}:ro,Z", src.display());
    let _guard = Container(name.clone());
    let ok = Command::new("podman")
        .args([
            "run",
            "-d",
            "--rm",
            "--name",
            &name,
            "-p",
            &format!("127.0.0.1:{port}:8080"),
        ])
        .args([
            "-v",
            &mount(&dir.path().join("nginx.conf"), "/etc/nginx/nginx.conf"),
        ])
        .args(["-v", &mount(&iwp_dir, "/etc/nginx/iwp")])
        .args(["-v", &mount(&base, "/var/www/vhosts/example.org/iwp")])
        .args(["-v", &mount(&other, "/other")])
        .arg("docker.io/library/nginx:stable")
        .status()
        .unwrap()
        .success();
    assert!(ok, "podman run failed");
    std::thread::sleep(std::time::Duration::from_secs(2));

    let cases: &[(&str, u16)] = &[
        ("/wp-content/uploads/x.php", 403),
        ("/wp-content/uploads/2024/x.PHP", 403),
        ("/wp-content/wflogs/x.php", 403),
        ("/wp-content/plugins/p/other.php", 404),
        ("/wp-content/plugins/p/ajax.php", 502), // allowlisted → FastCGI (no socket in test → 502)
        ("/wp-includes/version.php", 404),
        ("/wp-cron.php", 404),
        ("/xmlrpc.php", 403),
        ("/readme.html", 403),
        ("/.git/config", 403),
        ("/index.php", 502),
        ("/wp-login.php", 502),
        ("/wp-admin/", 502),
        ("/wp-admin/network/", 502),
        ("/wp-admin/admin-ajax.php", 502),
        ("/", 502),
        ("/some/pretty/permalink/", 502),
        ("/wp-admin/css/a.css", 200),
        ("/wp-content/plugins/p/a.js", 200),
        ("/index.php/../wp-content/uploads/x.php", 403),
        ("/wp-content/uploads/x%2ephp", 403),
        ("//wp-content/uploads/x.php", 403),
        ("/INDEX.PHP", 404),
        ("/wp-admin/includes/x.php", 404),
        ("/wp-admin/maint/repair.php", 404),
        // Through `current` and the www-owned uploads link into shared/.
        ("/wp-content/uploads/ok.jpg", 200),
        ("/wp-content/uploads/own.jpg", 200), // link and target have the same owner
        ("/wp-content/uploads/foreign.jpg", 403), // planted link of another owner
        ("/wp-content/uploads/evil.jpg", 403),
        ("/wp-content/uploads/evildir/secret.jpg", 403),
        ("/wp-content/uploads/evil.txt", 502), // try_files does not see it: a WordPress route
    ];
    let results: Vec<(&str, u16, u16)> = cases
        .iter()
        .map(|(p, want)| (*p, *want, status(port, p)))
        .collect();
    let bad: Vec<_> = results.iter().filter(|(_, w, g)| w != g).collect();
    assert!(bad.is_empty(), "path, expected, got: {bad:#?}");
}
