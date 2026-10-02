//! SELinux: the iwp policy module (host nginx <-> container content/socket) and per-site labels.

use std::path::Path;

use anyhow::{Result, bail};

use crate::config::{GlobalConfig, Site};
use crate::hash::sha256_hex;
use crate::host::fsx::{FileSpec, ensure_dir, write_atomic};
use crate::host::identity::Identity;
use crate::host::{Cmd, Host, run_ok, sys};

pub const MODULE_TE: &str = include_str!("../../share/selinux/iwp.te");
pub const MARKER: &str = "/etc/iwp/selinux-module.sha256";

pub fn enabled(host: &dyn Host) -> Result<bool> {
    match host.run(&Cmd::new("selinuxenabled")) {
        Ok(out) => Ok(out.status == 0),
        Err(e) if format!("{e:#}").contains("starting selinuxenabled") => Ok(false),
        Err(e) => Err(e),
    }
}

pub fn install_module(host: &dyn Host) -> Result<bool> {
    if !enabled(host)? {
        return Ok(false);
    }
    let want = sha256_hex(MODULE_TE.as_bytes());
    let marker = sys(host, MARKER);
    if std::fs::read_to_string(&marker).is_ok_and(|s| s.trim() == want) {
        return Ok(false);
    }
    let dir = tempfile::Builder::new().prefix("iwp-selinux-").tempdir()?;
    let p = |f: &str| dir.path().join(f).display().to_string();
    std::fs::write(dir.path().join("iwp.te"), MODULE_TE)?;
    run_ok(
        host,
        &Cmd::new("checkmodule").args(["-M", "-m", "-o", &p("iwp.mod"), &p("iwp.te")]),
    )?;
    run_ok(
        host,
        &Cmd::new("semodule_package").args(["-o", &p("iwp.pp"), "-m", &p("iwp.mod")]),
    )?;
    run_ok(host, &Cmd::new("semodule").args(["-i", &p("iwp.pp")]))?;
    ensure_dir(
        host,
        marker.parent().expect("marker has a parent"),
        0o755,
        Some((0, 0)),
    )?;
    write_atomic(
        host,
        &marker,
        format!("{want}\n").as_bytes(),
        &FileSpec {
            mode: Some(0o644),
            owner: Some((0, 0)),
        },
    )?;
    Ok(true)
}

pub fn fcontext_rules(g: &GlobalConfig, site: &Site) -> Vec<String> {
    let esc = |p: String| regex::escape(&p);
    let base = esc(site.base_dir(g).display().to_string());
    vec![
        format!("{base}(/.*)?"),
        // /var/run, not /run: the policy's `/run /var/run` equivalency rule makes semanage
        // reject /run specs; restorecon still applies this rule to /run/iwp/<site>.
        format!("/var/run/iwp/{}(/.*)?", esc(site.name.clone())),
    ]
}

pub fn label_site(host: &dyn Host, g: &GlobalConfig, site: &Site) -> Result<bool> {
    if !enabled(host)? {
        return Ok(false);
    }
    let level = Identity::for_site(site.id, g.id_offset).selinux_level();
    for rule in fcontext_rules(g, site) {
        let cmd = |op: &str| {
            Cmd::new("semanage").args([
                "fcontext",
                op,
                "-t",
                "container_file_t",
                "-r",
                &level,
                &rule,
            ])
        };
        let out = host.run(&cmd("-a"))?;
        if out.status != 0 {
            if String::from_utf8_lossy(&out.stderr).contains("already defined") {
                run_ok(host, &cmd("-m"))?;
            } else {
                bail!(
                    "semanage fcontext -a {rule}: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
        }
    }
    let base = site.base_dir(g);
    run_ok(
        host,
        &Cmd::new("restorecon").args(["-RF".to_string(), base.display().to_string()]),
    )?;
    let run_dir = format!("/run/iwp/{}", site.name);
    if sys(host, &run_dir).exists() {
        run_ok(host, &Cmd::new("restorecon").args(["-RF", &run_dir]))?;
    }
    Ok(true)
}

pub fn relabel(host: &dyn Host, paths: &[&Path]) -> Result<()> {
    if paths.is_empty() || !enabled(host)? {
        return Ok(());
    }
    run_ok(
        host,
        &Cmd::new("restorecon")
            .arg("-RF")
            .args(paths.iter().map(|p| p.display().to_string())),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{GlobalConfig, parse_site};
    use crate::host::sys;
    use crate::testutil::RecordingHost;

    fn acme() -> crate::config::Site {
        parse_site(include_str!("../../examples/acme.toml")).unwrap()
    }

    #[test]
    fn fcontext_rules_escape_regex_metacharacters() {
        let mut s = acme();
        s.base = Some("/srv/a+b(c)[d]{e}|f?g^h$/x.y".into());
        let r = fcontext_rules(&GlobalConfig::default(), &s);
        assert_eq!(r[0], r"/srv/a\+b\(c\)\[d\]\{e\}\|f\?g\^h\$/x\.y(/.*)?");
        // semanage rejects /run specs: the policy's equivalency rule `/run /var/run` makes
        // /var/run the canonical spelling, and restorecon applies it to /run (found by e2e).
        assert_eq!(r[1], "/var/run/iwp/acme(/.*)?");
    }

    #[test]
    fn disabled_selinux_is_a_clean_noop() {
        let h = RecordingHost::new(true).respond("selinuxenabled", 1, "", "");
        assert!(!install_module(&h).unwrap());
        assert!(!label_site(&h, &GlobalConfig::default(), &acme()).unwrap());
        assert_eq!(h.calls().len(), 2, "only the two selinuxenabled probes");
    }

    #[test]
    fn install_module_once() {
        let h = RecordingHost::new(true);
        assert!(install_module(&h).unwrap());
        let cmds: Vec<String> = h.calls().iter().map(ToString::to_string).collect();
        assert!(
            cmds[1].starts_with("checkmodule -M -m -o ") && cmds[1].ends_with("/iwp.te"),
            "{cmds:?}"
        );
        assert!(cmds[2].starts_with("semodule_package -o "));
        assert!(cmds[3].starts_with("semodule -i ") && cmds[3].ends_with("/iwp.pp"));
        assert_eq!(
            std::fs::read_to_string(sys(&h, MARKER)).unwrap().trim(),
            crate::hash::sha256_hex(MODULE_TE.as_bytes())
        );
        assert!(
            !install_module(&h).unwrap(),
            "marker matches -> nothing to do"
        );
    }

    #[test]
    fn label_site_rules_and_modify_fallback() {
        let h = RecordingHost::new(true).respond(
            "semanage fcontext -a",
            1,
            "",
            "ValueError: File context for /x already defined",
        );
        assert!(label_site(&h, &GlobalConfig::default(), &acme()).unwrap());
        let cmds: Vec<String> = h.calls().iter().map(ToString::to_string).collect();
        assert!(
            cmds.contains(
                &r"semanage fcontext -a -t container_file_t -r s0:c3,c515 /var/www/vhosts/example\.org/iwp(/.*)?"
                    .to_string()
            ),
            "{cmds:#?}"
        );
        assert!(
            cmds.contains(
                &r"semanage fcontext -m -t container_file_t -r s0:c3,c515 /var/www/vhosts/example\.org/iwp(/.*)?"
                    .to_string()
            )
        );
        assert!(
            cmds.contains(
                &"semanage fcontext -m -t container_file_t -r s0:c3,c515 /var/run/iwp/acme(/.*)?"
                    .to_string()
            )
        );
        assert!(cmds.contains(&"restorecon -RF /var/www/vhosts/example.org/iwp".to_string()));
    }

    #[test]
    fn missing_selinuxenabled_binary_means_disabled() {
        struct NoBinary(RecordingHost);
        impl crate::host::Host for NoBinary {
            fn run(&self, c: &crate::host::Cmd) -> anyhow::Result<crate::host::CmdOutput> {
                if c.program == "selinuxenabled" {
                    anyhow::bail!("starting selinuxenabled (is it installed?)")
                }
                self.0.run(c)
            }
            fn run_streaming(
                &self,
                c: &crate::host::Cmd,
                i: Option<&mut (dyn std::io::Read + Send)>,
                o: &mut dyn std::io::Write,
            ) -> anyhow::Result<crate::host::CmdOutput> {
                self.0.run_streaming(c, i, o)
            }
            fn run_interactive(&self, c: &crate::host::Cmd) -> anyhow::Result<i32> {
                self.0.run_interactive(c)
            }
            fn fchown(
                &self,
                f: &std::fs::File,
                p: &std::path::Path,
                u: u32,
                g: u32,
            ) -> anyhow::Result<()> {
                self.0.fchown(f, p, u, g)
            }
            fn chown(&self, p: &std::path::Path, u: u32, g: u32) -> anyhow::Result<()> {
                self.0.chown(p, u, g)
            }
            fn lchown(&self, p: &std::path::Path, u: u32, g: u32) -> anyhow::Result<()> {
                self.0.lchown(p, u, g)
            }
            fn chown_tree_nofollow(
                &self,
                p: &std::path::Path,
                u: u32,
                g: u32,
            ) -> anyhow::Result<u64> {
                self.0.chown_tree_nofollow(p, u, g)
            }
            fn owner(&self, p: &std::path::Path) -> anyhow::Result<(u32, u32)> {
                self.0.owner(p)
            }
            fn is_root(&self) -> bool {
                true
            }
            fn sysroot(&self) -> &std::path::Path {
                self.0.sysroot()
            }
        }
        assert!(!enabled(&NoBinary(RecordingHost::new(true))).unwrap());
    }
}
