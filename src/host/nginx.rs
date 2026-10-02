//! Install the generated nginx include safely, and check operator server blocks use it.

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use crate::config::{GlobalConfig, Site};
use crate::host::fsx::{FileSpec, ensure_dir, write_atomic};
use crate::host::install::destination;
use crate::host::{Cmd, Host, run_ok, sys};

/// Marker left when files are installed and tested but the reload has not (yet) succeeded.
const RELOAD_PENDING: &str = "/run/iwp/nginx-reload-pending";

/// Installs the rendered nginx files, tests them and reloads nginx.
///
/// Any error between the first write and a passing `nginx -t` restores every captured file
/// (best effort; restored files are written 0644 root:root, as iwp owns them). Returns
/// `Ok(true)` when something was activated (changed files, or a previously pending reload).
pub fn apply(
    host: &dyn Host,
    g: &GlobalConfig,
    site: &Site,
    rendered: &BTreeMap<String, String>,
) -> Result<bool> {
    let keys = [
        format!("nginx/{}.conf", site.name),
        format!("nginx/{}.fastcgi.conf", site.name),
    ];
    let mut files: Vec<(PathBuf, Option<Vec<u8>>, &str)> = Vec::new();
    for k in &keys {
        let body = rendered
            .get(k)
            .with_context(|| format!("render output lacks {k}"))?;
        let path = sys(host, destination(g, site, k)?);
        // Only NotFound means "absent"; anything else must stop us before we write.
        let old = match std::fs::read(&path) {
            Ok(b) => Some(b),
            Err(e) if e.kind() == ErrorKind::NotFound => None,
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        files.push((path, old, body));
    }
    let spec = FileSpec {
        mode: Some(0o644),
        owner: Some((0, 0)),
    };
    let mut changed = false;
    let marker = sys(host, RELOAD_PENDING);
    let marker_pre = marker.exists();
    let needs_write = files
        .iter()
        .any(|(_, old, body)| old.as_deref() != Some(body.as_bytes()));
    let write_marker = || -> Result<()> {
        ensure_dir(
            host,
            marker.parent().expect("has parent"),
            0o755,
            Some((0, 0)),
        )?;
        write_atomic(host, &marker, b"", &spec).map(|_| ())
    };
    let attempt = (|| -> Result<Option<String>> {
        ensure_dir(
            host,
            files[0].0.parent().expect("has parent"),
            0o755,
            Some((0, 0)),
        )?;
        // Marker first: whatever happens after the first include write, a retry path exists.
        if needs_write {
            write_marker()?;
        }
        for (path, _, body) in &files {
            changed |= write_atomic(host, path, body.as_bytes(), &spec)?;
        }
        let test = host.run(&Cmd::new("nginx").arg("-t"))?;
        Ok((test.status != 0).then(|| String::from_utf8_lossy(&test.stderr).trim().to_string()))
    })();
    // A fully restored configuration needs no reload, so the marker we added is dropped.
    let drop_marker = || {
        if !marker_pre {
            let _ = std::fs::remove_file(&marker);
        }
    };
    match attempt {
        Ok(None) => {}
        Ok(Some(stderr)) if !changed => {
            bail!("nginx -t fails with the current configuration: {stderr}")
        }
        Ok(Some(stderr)) => {
            let failures = restore(host, &files, &spec);
            if failures.is_empty() {
                drop_marker();
                bail!("nginx -t failed; previous configuration restored: {stderr}");
            }
            bail!(
                "nginx -t failed ({stderr}); restore FAILED for {}",
                failures.join("; ")
            );
        }
        Err(e) => {
            let failures = restore(host, &files, &spec);
            if failures.is_empty() {
                drop_marker();
                return Err(e.context("previous configuration restored"));
            }
            bail!("{e:#}; restore FAILED for {}", failures.join("; "));
        }
    }
    if !changed && !marker_pre {
        drop_marker();
        return Ok(false);
    }
    if !marker.exists() {
        write_marker()?;
    }
    run_ok(host, &Cmd::new("systemctl").args(["reload", "nginx"])).context(
        "files are installed and tested; run `systemctl reload nginx` or re-run `iwp nginx apply`",
    )?;
    let _ = std::fs::remove_file(&marker);
    Ok(true)
}

/// Restores every captured file (or removes it if it did not exist); returns the failures.
fn restore(
    host: &dyn Host,
    files: &[(PathBuf, Option<Vec<u8>>, &str)],
    spec: &FileSpec,
) -> Vec<String> {
    let mut failures = Vec::new();
    for (path, old, _) in files {
        let r = match old {
            Some(bytes) => write_atomic(host, path, bytes, spec).map(|_| ()),
            None => match std::fs::remove_file(path) {
                Err(e) if e.kind() != ErrorKind::NotFound => Err(e.into()),
                _ => Ok(()),
            },
        };
        if let Err(e) = r {
            failures.push(format!("{}: {e:#}", path.display()));
        }
    }
    failures
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerBlock {
    pub server_names: Vec<String>,
    pub includes: Vec<String>,
    pub has_root: bool,
    pub has_return: bool,
}

#[derive(Debug, PartialEq)]
enum Tok {
    Word(String),
    Open,
    Close,
    Semi,
}

fn tokenize(s: &str) -> Vec<Tok> {
    let mut out = Vec::new();
    let mut chars = s.chars();
    let mut word = String::new();
    let flush = |w: &mut String, out: &mut Vec<Tok>| {
        if !w.is_empty() {
            out.push(Tok::Word(std::mem::take(w)));
        }
    };
    while let Some(c) = chars.next() {
        match c {
            '#' if word.is_empty() => {
                flush(&mut word, &mut out);
                for n in chars.by_ref() {
                    if n == '\n' {
                        break;
                    }
                }
            }
            '"' | '\'' if word.is_empty() => {
                while let Some(n) = chars.next() {
                    if n == c {
                        break;
                    }
                    if n == '\\' {
                        if let Some(esc) = chars.next() {
                            word.push(esc);
                        }
                        continue;
                    }
                    word.push(n);
                }
            }
            '{' => {
                flush(&mut word, &mut out);
                out.push(Tok::Open);
            }
            '}' => {
                flush(&mut word, &mut out);
                out.push(Tok::Close);
            }
            ';' => {
                flush(&mut word, &mut out);
                out.push(Tok::Semi);
            }
            c if c.is_whitespace() => flush(&mut word, &mut out),
            c => word.push(c),
        }
    }
    flush(&mut word, &mut out);
    out
}

pub fn parse_server_blocks(nginx_t: &str) -> Vec<ServerBlock> {
    let toks = tokenize(nginx_t);
    let mut blocks = Vec::new();
    // Stack of block names; a directive's words accumulate until ';' or '{'.
    let mut stack: Vec<String> = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut current: Option<(usize, ServerBlock)> = None;
    for t in toks {
        match t {
            Tok::Word(w) => words.push(w),
            Tok::Open => {
                let name = words.first().cloned().unwrap_or_default();
                // `nginx -T` prints files included from http as their own top-level
                // sections, so a depth-0 server is an http-level one; stream/mail are not.
                if name == "server" && stack.last().is_none_or(|p| p == "http") {
                    current = Some((stack.len() + 1, ServerBlock::default()));
                }
                stack.push(name);
                words.clear();
            }
            Tok::Semi => {
                if let Some((depth, b)) = current.as_mut()
                    && stack.len() == *depth
                {
                    match words.first().map(String::as_str) {
                        Some("server_name") => b.server_names.extend(words[1..].iter().cloned()),
                        Some("include") => b.includes.extend(words[1..].iter().cloned()),
                        Some("root") => b.has_root = true,
                        Some("return") => b.has_return = true,
                        _ => {}
                    }
                }
                words.clear();
            }
            Tok::Close => {
                if let Some((depth, _)) = &current
                    && stack.len() == *depth
                {
                    blocks.push(current.take().expect("checked").1);
                }
                stack.pop();
                words.clear();
            }
        }
    }
    blocks
}

/// The `user` directive of the main context as (user, explicit group); nginx's distro build
/// default (`nginx`) when there is none.
pub fn worker_identity(nginx_t: &str) -> (String, Option<String>) {
    let mut depth = 0usize;
    let mut words: Vec<String> = Vec::new();
    let mut found = None;
    for t in tokenize(nginx_t) {
        match t {
            Tok::Word(w) => words.push(w),
            Tok::Open => {
                depth += 1;
                words.clear();
            }
            Tok::Close => {
                depth = depth.saturating_sub(1);
                words.clear();
            }
            Tok::Semi => {
                // `user` is only valid in the main context; `nginx -T` prints included files at
                // depth 0 too, but nginx refuses `user` anywhere but main, so depth 0 is it.
                if depth == 0
                    && words.first().map(String::as_str) == Some("user")
                    && let Some(u) = words.get(1)
                {
                    found = Some((u.clone(), words.get(2).cloned()));
                }
                words.clear();
            }
        }
    }
    // No directive: nginx:nginx, the Fedora/RHEL build default (--user=nginx --group=nginx).
    found.unwrap_or_else(|| ("nginx".to_string(), None))
}

/// `getent group <name>` as (gid, member names); `None` when the group does not exist.
fn getent_group(host: &dyn Host, name: &str) -> Result<Option<(u32, Vec<String>)>> {
    let out = host
        .run(&Cmd::new("getent").args(["group", name]))
        .with_context(|| format!("running getent group {name}"))?;
    if out.status != 0 {
        return Ok(None);
    }
    let line = String::from_utf8_lossy(&out.stdout);
    let mut f = line.trim().split(':');
    let gid = f.nth(2).and_then(|g| g.parse::<u32>().ok());
    let members = f
        .next()
        .unwrap_or("")
        .split(',')
        .filter(|m| !m.is_empty())
        .map(str::to_string)
        .collect();
    Ok(gid.map(|g| (g, members)))
}

/// `id <flag> <user>` as gids.
fn id_gids(host: &dyn Host, flag: &str, user: &str) -> Result<Vec<u32>> {
    let out = host
        .run(&Cmd::new("id").args([flag, user]))
        .with_context(|| format!("running id {flag} {user}"))?;
    if out.status != 0 {
        bail!(
            "nginx worker user {user:?} (from nginx's `user` directive) cannot be resolved: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .map(|g| {
            g.parse::<u32>()
                .with_context(|| format!("unexpected `id {flag} {user}` output {g:?}"))
        })
        .collect()
}

/// Fails unless nginx workers are in `g.nginx_group`: the base dir is 0750
/// root:<nginx_group> and the socket dir is reached through that group, so workers outside it
/// answer every request with 403/502 while `nginx -t` and the deploy itself succeed.
///
/// Read-only (`nginx -T`, `getent`, `id`); callers run it before their first change.
pub fn check_worker_group(host: &dyn Host, g: &GlobalConfig) -> Result<()> {
    let out = host
        .run(&Cmd::new("nginx").arg("-T"))
        .context("running nginx -T (is nginx installed?)")?;
    if out.status != 0 {
        bail!(
            "nginx -T failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let (user, group) = worker_identity(&String::from_utf8_lossy(&out.stdout));
    let (want, members) = getent_group(host, &g.nginx_group)?.with_context(|| {
        format!(
            "group {:?} not found; set nginx_group in iwp.toml",
            g.nginx_group
        )
    })?;
    // nginx: setgid(<group>) then initgroups(<user>, <group>); an omitted group means the
    // group named like the user (ngx_core_module docs). There is no fallback: when that group
    // does not exist, nginx fails at startup (getgrnam), so it is an error here too.
    let group_name = group.clone().unwrap_or_else(|| user.clone());
    let base = match getent_group(host, &group_name)? {
        Some((gid, _)) => gid,
        None if group.is_none() => bail!(
            "group {group_name:?} does not exist: nginx's `user {user};` directive names no group, so nginx uses the group named like the user and fails to start without it; create the group or write `user {user} <group>;`"
        ),
        None => bail!("group {group_name:?} from nginx's `user` directive does not exist"),
    };
    // `id -G` lists the passwd primary group too, which initgroups only adds when the user is
    // a listed member of it; the membership check below covers that case for nginx_group.
    let primary = id_gids(host, "-g", &user)?;
    let supplementary: Vec<u32> = id_gids(host, "-G", &user)?
        .into_iter()
        .filter(|gid| !primary.contains(gid))
        .collect();
    if base == want || supplementary.contains(&want) || members.contains(&user) {
        return Ok(());
    }
    let n = &g.nginx_group;
    bail!(
        "nginx workers run as {user}:{group_name} and are not in group {n}; add them: \
         usermod -aG {n} {user} && systemctl reload nginx \
         (do not set nginx_group to a group other sites' PHP runs in)"
    )
}

pub fn check(host: &dyn Host, site: &Site) -> Result<Vec<String>> {
    let out = run_ok(host, &Cmd::new("nginx").arg("-T"))?;
    let blocks = parse_server_blocks(&out);
    let want = format!("iwp/{}.conf", site.name);
    let abs_want = format!("/etc/nginx/{want}");
    let mut problems = Vec::new();
    for d in &site.domains {
        let matching: Vec<&ServerBlock> = blocks
            .iter()
            .filter(|b| b.server_names.iter().any(|n| n.eq_ignore_ascii_case(d)))
            .collect();
        if matching.is_empty() {
            problems.push(format!("no server block for {d}"));
            continue;
        }
        for b in matching {
            let includes = b.includes.iter().any(|i| i == &want || *i == abs_want);
            if !includes && !b.has_return {
                problems.push(format!("server block for {d} does not include {want}"));
            }
            if includes && b.has_root {
                problems.push(format!(
                    "server block for {d} sets root; remove it (the iwp include sets root)"
                ));
            }
        }
    }
    Ok(problems)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{GlobalConfig, parse_site};
    use crate::host::sys;
    use crate::render::{RenderEnv, render_site};
    use crate::testutil::RecordingHost;

    fn site() -> crate::config::Site {
        parse_site(include_str!("../../examples/acme.toml")).unwrap()
    }
    fn rendered() -> BTreeMap<String, String> {
        render_site(&GlobalConfig::default(), &site(), &RenderEnv::default()).unwrap()
    }

    #[test]
    fn apply_tests_then_reloads() {
        let h = RecordingHost::new(true);
        assert!(apply(&h, &GlobalConfig::default(), &site(), &rendered()).unwrap());
        let cmds: Vec<String> = h.calls().iter().map(ToString::to_string).collect();
        assert_eq!(cmds, vec!["nginx -t", "systemctl reload nginx"]);
        assert!(sys(&h, "/etc/nginx/iwp/acme.conf").is_file());
        assert!(
            !apply(&h, &GlobalConfig::default(), &site(), &rendered()).unwrap(),
            "unchanged → no nginx calls"
        );
        // Unchanged files still get `nginx -t`, but no reload.
        assert_eq!(h.calls().len(), 3);
        assert_eq!(h.calls()[2].to_string(), "nginx -t");
        assert!(!sys(&h, "/run/iwp/nginx-reload-pending").exists());
    }

    #[test]
    fn failed_test_restores_previous_files_and_skips_reload() {
        let good = RecordingHost::new(true);
        apply(&good, &GlobalConfig::default(), &site(), &rendered()).unwrap();
        let before = std::fs::read(sys(&good, "/etc/nginx/iwp/acme.conf")).unwrap();
        // Same sysroot, now nginx -t fails for a changed config.
        let mut r = rendered();
        r.insert("nginx/acme.conf".into(), "broken;\n".into());
        let h = RecordingHost::sharing(&good).respond(
            "nginx -t",
            1,
            "",
            "nginx: [emerg] unknown directive \"broken\"",
        );
        let err = apply(&h, &GlobalConfig::default(), &site(), &r).unwrap_err();
        assert!(
            format!("{err:#}").contains("previous configuration restored"),
            "{err:#}"
        );
        assert_eq!(
            std::fs::read(sys(&good, "/etc/nginx/iwp/acme.conf")).unwrap(),
            before
        );
        assert!(!h.calls().iter().any(|c| c.program == "systemctl"));
    }

    #[test]
    fn failed_first_apply_removes_new_files() {
        let h = RecordingHost::new(true).respond("nginx -t", 1, "", "emerg");
        assert!(apply(&h, &GlobalConfig::default(), &site(), &rendered()).is_err());
        assert!(!sys(&h, "/etc/nginx/iwp/acme.conf").exists());
        assert!(!sys(&h, "/etc/nginx/iwp/acme.fastcgi.conf").exists());
    }

    const NGINX_T: &str = r#"
# configuration file /etc/nginx/nginx.conf:
http {
    server { listen 80; server_name www.example.org shop.example.org; return 301 https://$host$request_uri; }
    server {
        server_name www.example.org;   # main
        include iwp/acme.conf;
        location ~ ^/(dubrovnik) { root /var/www/vhosts/example.org/non-wp-pages; }
        add_header X-Test "a { b } c";
    }
    server { server_name shop.example.org; root /var/www/x; include iwp/acme.conf; }
}
"#;

    #[test]
    fn parser_depth_one_only() {
        let blocks = parse_server_blocks(NGINX_T);
        assert_eq!(blocks.len(), 3);
        assert!(blocks[0].has_return && blocks[0].includes.is_empty());
        assert_eq!(blocks[1].includes, vec!["iwp/acme.conf"]);
        assert!(!blocks[1].has_root, "location-level root is fine");
        assert!(blocks[2].has_root);
    }

    #[test]
    fn check_reports_problems() {
        let h = RecordingHost::new(true).respond("nginx -T", 0, NGINX_T, "");
        let problems = check(&h, &site()).unwrap();
        assert_eq!(
            problems,
            vec![
                "server block for shop.example.org sets root; remove it (the iwp include sets root)"
                    .to_string(),
                "no server block for dev.example.org".to_string(),
            ]
        );
    }

    const NGINX_T_REAL: &str = r#"
# configuration file /etc/nginx/nginx.conf:
events { worker_connections 1024; }
http {
    include /etc/nginx/mime.types;
    include /etc/nginx/conf.d/*.conf;
}
include /etc/nginx/stream.conf;

# configuration file /etc/nginx/conf.d/acme.conf:
server { server_name www.example.org; include iwp/acme.conf; }
server { server_name shop.example.org; root /var/www/x; include iwp/acme.conf; }

# configuration file /etc/nginx/stream.conf:
stream { server { listen 3306; server_name dev.example.org; } }
"#;

    #[test]
    fn parser_finds_top_level_servers_from_included_files() {
        let blocks = parse_server_blocks(NGINX_T_REAL);
        assert_eq!(blocks.len(), 2, "{blocks:?}");
        assert_eq!(blocks[0].server_names, vec!["www.example.org"]);
        assert!(blocks[1].has_root);
        let h = RecordingHost::new(true).respond("nginx -T", 0, NGINX_T_REAL, "");
        assert_eq!(
            check(&h, &site()).unwrap(),
            vec![
                "server block for shop.example.org sets root; remove it (the iwp include sets root)"
                    .to_string(),
                "no server block for dev.example.org".to_string(),
            ]
        );
    }

    use std::cell::{Cell, RefCell};
    use std::path::Path;

    /// Wraps a RecordingHost with injectable failures.
    struct Wrap {
        inner: RecordingHost,
        nginx_spawn_fails: Cell<bool>,
        nginx_t_fails: Cell<bool>,
        reload_fails: Cell<bool>,
        chown_fail_at: Cell<usize>,
        chown_calls: Cell<usize>,
        log: RefCell<Vec<String>>,
    }
    impl Wrap {
        fn new(inner: RecordingHost) -> Self {
            Self {
                inner,
                nginx_spawn_fails: Cell::new(false),
                nginx_t_fails: Cell::new(false),
                reload_fails: Cell::new(false),
                chown_fail_at: Cell::new(0),
                chown_calls: Cell::new(0),
                log: RefCell::new(Vec::new()),
            }
        }
    }
    impl Host for Wrap {
        fn run(&self, cmd: &Cmd) -> Result<crate::host::CmdOutput> {
            self.log.borrow_mut().push(cmd.to_string());
            if cmd.program == "nginx" && self.nginx_spawn_fails.get() {
                bail!("spawn nginx: injected");
            }
            let fail = |stderr: &str| crate::host::CmdOutput {
                status: 1,
                stdout: vec![],
                stderr: stderr.into(),
            };
            if cmd.to_string() == "nginx -t" && self.nginx_t_fails.get() {
                return Ok(fail("emerg"));
            }
            if cmd.program == "systemctl" && self.reload_fails.get() {
                return Ok(fail("boom"));
            }
            self.inner.run(cmd)
        }
        fn run_streaming(
            &self,
            cmd: &Cmd,
            stdin: Option<&mut (dyn std::io::Read + Send)>,
            stdout: &mut dyn std::io::Write,
        ) -> Result<crate::host::CmdOutput> {
            self.inner.run_streaming(cmd, stdin, stdout)
        }
        fn run_interactive(&self, cmd: &Cmd) -> Result<i32> {
            self.inner.run_interactive(cmd)
        }
        fn fchown(&self, file: &std::fs::File, path: &Path, uid: u32, gid: u32) -> Result<()> {
            self.inner.fchown(file, path, uid, gid)
        }
        fn chown(&self, path: &Path, uid: u32, gid: u32) -> Result<()> {
            let n = self.chown_calls.get() + 1;
            self.chown_calls.set(n);
            if n == self.chown_fail_at.get() {
                bail!("chown {}: injected", path.display());
            }
            self.inner.chown(path, uid, gid)
        }
        fn lchown(&self, path: &Path, uid: u32, gid: u32) -> Result<()> {
            self.inner.lchown(path, uid, gid)
        }
        fn chown_tree_nofollow(&self, root: &Path, uid: u32, gid: u32) -> Result<u64> {
            self.inner.chown_tree_nofollow(root, uid, gid)
        }
        fn owner(&self, path: &Path) -> Result<(u32, u32)> {
            self.inner.owner(path)
        }
        fn is_root(&self) -> bool {
            self.inner.is_root()
        }
        fn sysroot(&self) -> &Path {
            self.inner.sysroot()
        }
    }

    fn changed_render() -> BTreeMap<String, String> {
        let mut r = rendered();
        r.insert("nginx/acme.conf".into(), "changed-a;\n".into());
        r.insert("nginx/acme.fastcgi.conf".into(), "changed-b;\n".into());
        r
    }
    const A: &str = "/etc/nginx/iwp/acme.conf";
    const B: &str = "/etc/nginx/iwp/acme.fastcgi.conf";
    const MARKER: &str = "/run/iwp/nginx-reload-pending";

    #[test]
    fn partial_write_failure_restores_first_file() {
        if crate::testutil::skip_if_root() {
            return;
        }
        let good = RecordingHost::new(true);
        apply(&good, &GlobalConfig::default(), &site(), &rendered()).unwrap();
        let (a0, b0) = (
            std::fs::read(sys(&good, A)).unwrap(),
            std::fs::read(sys(&good, B)).unwrap(),
        );
        let h = Wrap::new(RecordingHost::sharing(&good));
        // dir(1), marker dir(2) + tmp(3) + target(4), A tmp(5) + target(6), B tmp(7) fails.
        h.chown_fail_at.set(7);
        let err = apply(&h, &GlobalConfig::default(), &site(), &changed_render()).unwrap_err();
        assert!(format!("{err:#}").contains("injected"), "{err:#}");
        assert_eq!(std::fs::read(sys(&good, A)).unwrap(), a0);
        assert_eq!(std::fs::read(sys(&good, B)).unwrap(), b0);
        assert!(h.log.borrow().is_empty(), "no nginx/systemctl calls");
    }

    #[test]
    fn partial_write_failure_on_first_install_removes_first_file() {
        if crate::testutil::skip_if_root() {
            return;
        }
        let h = Wrap::new(RecordingHost::new(true));
        h.chown_fail_at.set(7);
        assert!(apply(&h, &GlobalConfig::default(), &site(), &rendered()).is_err());
        assert!(!sys(&h, A).exists());
        assert!(!sys(&h, B).exists());
        assert!(h.log.borrow().is_empty());
    }

    #[test]
    fn nginx_spawn_error_restores_files() {
        let good = RecordingHost::new(true);
        apply(&good, &GlobalConfig::default(), &site(), &rendered()).unwrap();
        let a0 = std::fs::read(sys(&good, A)).unwrap();
        let h = Wrap::new(RecordingHost::sharing(&good));
        h.nginx_spawn_fails.set(true);
        let err = apply(&h, &GlobalConfig::default(), &site(), &changed_render()).unwrap_err();
        assert!(format!("{err:#}").contains("spawn nginx"), "{err:#}");
        assert_eq!(std::fs::read(sys(&good, A)).unwrap(), a0);
        assert_ne!(std::fs::read(sys(&good, B)).unwrap(), b"changed-b;\n");
    }

    #[test]
    fn both_files_restored_when_test_fails() {
        let good = RecordingHost::new(true);
        apply(&good, &GlobalConfig::default(), &site(), &rendered()).unwrap();
        let (a0, b0) = (
            std::fs::read(sys(&good, A)).unwrap(),
            std::fs::read(sys(&good, B)).unwrap(),
        );
        let h = Wrap::new(RecordingHost::sharing(&good));
        h.nginx_t_fails.set(true);
        let err = apply(&h, &GlobalConfig::default(), &site(), &changed_render()).unwrap_err();
        assert!(format!("{err:#}").contains("previous configuration restored"));
        assert_eq!(std::fs::read(sys(&good, A)).unwrap(), a0);
        assert_eq!(std::fs::read(sys(&good, B)).unwrap(), b0);
    }

    #[test]
    fn restore_failure_is_reported_not_claimed_restored() {
        if crate::testutil::skip_if_root() {
            return;
        }
        let good = RecordingHost::new(true);
        apply(&good, &GlobalConfig::default(), &site(), &rendered()).unwrap();
        let h = Wrap::new(RecordingHost::sharing(&good));
        h.nginx_t_fails.set(true);
        // dir(1), marker dir(2) + tmp(3) + target(4), A tmp(5) + target(6), B tmp(7) + target(8),
        // restore A tmp(9) fails.
        h.chown_fail_at.set(9);
        let err = format!(
            "{:#}",
            apply(&h, &GlobalConfig::default(), &site(), &changed_render()).unwrap_err()
        );
        assert!(err.contains("restore FAILED"), "{err}");
        assert!(err.contains("emerg"), "{err}");
        assert!(!err.contains("previous configuration restored"), "{err}");
        assert!(
            sys(&h, MARKER).exists(),
            "marker written before the includes survives a failed restore"
        );
    }

    #[test]
    fn marker_is_dropped_after_successful_restore_and_not_left_behind() {
        let good = RecordingHost::new(true);
        apply(&good, &GlobalConfig::default(), &site(), &rendered()).unwrap();
        let h = Wrap::new(RecordingHost::sharing(&good));
        h.nginx_t_fails.set(true);
        assert!(apply(&h, &GlobalConfig::default(), &site(), &changed_render()).is_err());
        assert!(!sys(&h, MARKER).exists());
    }

    #[test]
    fn reload_failure_keeps_files_and_marker_then_retry_reloads() {
        let h = Wrap::new(RecordingHost::new(true));
        h.reload_fails.set(true);
        let err = apply(&h, &GlobalConfig::default(), &site(), &rendered()).unwrap_err();
        assert!(format!("{err:#}").contains("systemctl"), "{err:#}");
        assert!(sys(&h, A).is_file() && sys(&h, B).is_file());
        assert!(sys(&h, MARKER).exists());
        h.reload_fails.set(false);
        h.log.borrow_mut().clear();
        assert!(apply(&h, &GlobalConfig::default(), &site(), &rendered()).unwrap());
        assert_eq!(*h.log.borrow(), vec!["nginx -t", "systemctl reload nginx"]);
        assert!(!sys(&h, MARKER).exists());
        assert!(!apply(&h, &GlobalConfig::default(), &site(), &rendered()).unwrap());
    }

    #[test]
    fn unchanged_but_nginx_test_failing_errors_and_keeps_files() {
        let h = Wrap::new(RecordingHost::new(true));
        apply(&h, &GlobalConfig::default(), &site(), &rendered()).unwrap();
        let before = std::fs::read(sys(&h, A)).unwrap();
        h.nginx_t_fails.set(true);
        let err = apply(&h, &GlobalConfig::default(), &site(), &rendered()).unwrap_err();
        assert!(
            format!("{err:#}").contains("nginx -t fails with the current configuration: emerg"),
            "{err:#}"
        );
        assert_eq!(std::fs::read(sys(&h, A)).unwrap(), before);
        assert!(sys(&h, B).is_file());
    }

    #[test]
    fn unreadable_previous_file_bails_before_writing() {
        let h = RecordingHost::new(true);
        std::fs::create_dir_all(sys(&h, B)).unwrap(); // reading a directory is not NotFound
        assert!(apply(&h, &GlobalConfig::default(), &site(), &rendered()).is_err());
        assert!(!sys(&h, A).exists());
        assert!(h.calls().is_empty());
    }

    #[test]
    fn tokenizer_keeps_mid_word_hash_and_quotes() {
        let t = "http { server { return 301 https://example.org/#top; server_name www.example.org; } \
                 server { server_name it's.example.org; } }";
        let b = parse_server_blocks(t);
        assert_eq!(b[0].server_names, vec!["www.example.org"]);
        assert!(b[0].has_return);
        assert_eq!(b[1].server_names, vec!["it's.example.org"]);
    }

    #[test]
    fn check_accepts_absolute_include_and_ignores_case() {
        let t = "http { server { server_name WWW.Example.ORG shop.example.org dev.example.org; \
                 include /etc/nginx/iwp/acme.conf; } }";
        let h = RecordingHost::new(true).respond("nginx -T", 0, t, "");
        assert_eq!(check(&h, &site()).unwrap(), Vec::<String>::new());
    }

    // ---- Nginx worker identity ----

    const MAIN_NGINX_USER: &str = "# configuration file /etc/nginx/nginx.conf:\n\
        user nginx;\nworker_processes auto;\nhttp { include /etc/nginx/conf.d/*.conf; }\n";

    fn g_with_group(name: &str) -> GlobalConfig {
        GlobalConfig {
            nginx_group: name.into(),
            ..GlobalConfig::default()
        }
    }

    fn worker_err(h: &RecordingHost, g: &GlobalConfig) -> String {
        format!("{:#}", check_worker_group(h, g).unwrap_err())
    }

    #[test]
    fn worker_group_default_user_in_its_own_group() {
        // No `user` directive: the distro default `nginx`, group `nginx`.
        let h = RecordingHost::new(true)
            .respond("nginx -T", 0, "worker_processes auto;\nhttp { }\n", "")
            .respond("getent group nginx", 0, "nginx:x:991:\n", "")
            .respond("id -g nginx", 0, "991\n", "")
            .respond("id -G nginx", 0, "991\n", "");
        check_worker_group(&h, &g_with_group("nginx")).unwrap();
        let calls: Vec<String> = h.calls().iter().map(|c| c.to_string()).collect();
        assert!(calls.contains(&"nginx -T".to_string()), "{calls:?}");
    }

    #[test]
    fn worker_group_explicit_group_is_the_nginx_group() {
        let h = RecordingHost::new(true)
            .respond("nginx -T", 0, "user www-data www;\nhttp { }\n", "")
            .respond("getent group www", 0, "www:x:1500:\n", "")
            .respond("id -g www-data", 0, "33\n", "")
            .respond("id -G www-data", 0, "33\n", "");
        check_worker_group(&h, &g_with_group("www")).unwrap();
    }

    #[test]
    fn worker_group_explicit_group_other_but_supplementary_has_it() {
        let h = RecordingHost::new(true)
            .respond("nginx -T", 0, "user nginx www-users;\nhttp { }\n", "")
            .respond("getent group www-users", 0, "www-users:x:2000:\n", "")
            .respond("getent group nginx", 0, "nginx:x:991:\n", "")
            .respond("id -g nginx", 0, "991\n", "")
            .respond("id -G nginx", 0, "991 2000 3000\n", "");
        check_worker_group(&h, &g_with_group("www-users")).unwrap();
        // nginx is a listed member of a third group: initgroups gives it that too.
        let h = RecordingHost::new(true)
            .respond("nginx -T", 0, "user nginx www-users;\nhttp { }\n", "")
            .respond("getent group www-users", 0, "www-users:x:2000:\n", "")
            .respond("getent group sites", 0, "sites:x:3000:nginx,apache\n", "")
            .respond("id -g nginx", 0, "991\n", "")
            .respond("id -G nginx", 0, "991 3000\n", "");
        check_worker_group(&h, &g_with_group("sites")).unwrap();
    }

    #[test]
    fn worker_group_missing_fails_with_the_fix() {
        // The staging failure: `user nginx www-users;` and nginx only has nginx as its
        // *primary* group, which initgroups(user, www-users) does not include.
        let h = RecordingHost::new(true)
            .respond("nginx -T", 0, "user nginx www-users;\nhttp { }\n", "")
            .respond("getent group www-users", 0, "www-users:x:2000:\n", "")
            .respond("getent group nginx", 0, "nginx:x:991:\n", "")
            .respond("id -g nginx", 0, "991\n", "")
            .respond("id -G nginx", 0, "991\n", "");
        assert_eq!(
            worker_err(&h, &g_with_group("nginx")),
            "nginx workers run as nginx:www-users and are not in group nginx; add them: \
             usermod -aG nginx nginx && systemctl reload nginx \
             (do not set nginx_group to a group other sites' PHP runs in)"
        );
        // Nothing but lookups ran.
        for c in h.calls() {
            assert!(
                ["nginx -T", "getent ", "id "]
                    .iter()
                    .any(|p| c.to_string().starts_with(p)),
                "{c}"
            );
        }
    }

    #[test]
    fn worker_group_ignores_a_user_directive_in_a_comment() {
        let t = "# user apache apache;\n#user apache;\nuser nginx; # user apache\nhttp { }\n";
        let h = RecordingHost::new(true)
            .respond("nginx -T", 0, t, "")
            .respond("getent group nginx", 0, "nginx:x:991:\n", "")
            .respond("getent group apache", 0, "apache:x:48:\n", "")
            .respond("id -g nginx", 0, "991\n", "")
            .respond("id -G nginx", 0, "991\n", "");
        check_worker_group(&h, &g_with_group("nginx")).unwrap();
        assert!(
            !h.calls().iter().any(|c| c.to_string().contains("apache")),
            "{:?}",
            h.calls()
        );
        assert!(
            worker_err(&h, &g_with_group("apache")).starts_with("nginx workers run as nginx:nginx")
        );
    }

    #[test]
    fn worker_group_named_like_the_user_must_exist() {
        // `user www-data;` with no group named www-data: nginx itself refuses to start
        // (getgrnam fails); there is no primary-group fallback.
        let h = RecordingHost::new(true)
            .respond("nginx -T", 0, "user www-data;\nhttp { }\n", "")
            .respond("getent group nginx", 0, "nginx:x:991:\n", "")
            .respond("getent group www-data", 2, "", "")
            .respond("id -g www-data", 0, "991\n", "")
            .respond("id -G www-data", 0, "991\n", "");
        let m = worker_err(&h, &g_with_group("nginx"));
        assert!(
            m.contains("group \"www-data\"")
                && m.contains("does not exist")
                && m.contains("user www-data <group>;"),
            "{m}"
        );
        assert!(
            !h.calls().iter().any(|c| c.to_string() == "id -g www-data"),
            "{:?}",
            h.calls()
        );
    }

    #[test]
    fn worker_user_only_counts_in_the_main_context() {
        assert_eq!(
            worker_identity(MAIN_NGINX_USER),
            ("nginx".to_string(), None)
        );
        assert_eq!(
            worker_identity("http { server { user x y; } }\nuser 'w w' grp;"),
            ("w w".to_string(), Some("grp".to_string()))
        );
    }

    #[test]
    fn worker_group_missing_nginx_binary_is_a_clear_error() {
        let h = RecordingHost::new(true).fail_spawn("nginx");
        let m = worker_err(&h, &g_with_group("nginx"));
        assert!(
            m.contains("nginx -T") && m.contains("is nginx installed"),
            "{m}"
        );
        let h = RecordingHost::new(true).respond("nginx -T", 1, "", "emerg: bad");
        let m = worker_err(&h, &g_with_group("nginx"));
        assert!(m.contains("nginx -T") && m.contains("emerg: bad"), "{m}");
    }

    #[test]
    fn worker_group_unknown_nginx_group_or_user_is_an_error() {
        let h = RecordingHost::new(true)
            .respond("nginx -T", 0, "user nginx;\n", "")
            .respond("getent group nosuch", 2, "", "");
        let m = worker_err(&h, &g_with_group("nosuch"));
        assert!(
            m.contains("group \"nosuch\"") && m.contains("nginx_group"),
            "{m}"
        );
        let h = RecordingHost::new(true)
            .respond("nginx -T", 0, "user ghost;\n", "")
            .respond("getent group nginx", 0, "nginx:x:991:\n", "")
            .respond("getent group ghost", 2, "", "")
            .respond("id ", 1, "", "id: 'ghost': no such user");
        let m = worker_err(&h, &g_with_group("nginx"));
        assert!(m.contains("ghost"), "{m}");
    }
}
