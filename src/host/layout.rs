//! Per-site directory layout with its owners and modes.

use std::path::Path;

use std::os::unix::fs::PermissionsExt;

use anyhow::{Context, Result};

use crate::config::{GlobalConfig, Site, shared_rel};
use crate::host::fsx::{ensure_dir_nofollow, ensure_tree_nofollow, walk_nofollow};
use crate::host::identity::Identity;
use crate::host::{Host, sys};

/// GID of `name` from /etc/group (the static binary has no NSS, and neither does musl).
fn group_gid(host: &dyn Host, name: &str) -> Result<u32> {
    let text = std::fs::read_to_string(sys(host, "/etc/group")).context("reading /etc/group")?;
    text.lines()
        .find_map(|l| {
            let mut f = l.split(':');
            (f.next() == Some(name))
                .then(|| f.nth(1)?.parse::<u32>().ok())
                .flatten()
        })
        .with_context(|| {
            format!("group {name:?} not found in /etc/group; set nginx_group in iwp.toml")
        })
}

pub fn prepare_site_dirs(host: &dyn Host, g: &GlobalConfig, site: &Site) -> Result<()> {
    let base = sys(host, site.base_dir(g));
    let www = Identity::for_site(site.id, g.id_offset).www_uid;
    let root = Some((0, 0));
    // Resolved before anything is created. The base is closed to "other", which is what every
    // other site's UID range is: nginx gets in through its group, and the site's own container
    // reaches its content through bind mounts, not by walking the host path.
    let nginx_gid = group_gid(host, &g.nginx_group)?;
    ensure_dir_nofollow(host, &base, 0o750, Some((0, nginx_gid)))?;
    for (d, m) in [("releases", 0o755), ("config", 0o755), ("backups", 0o700)] {
        ensure_dir_nofollow(host, &base.join(d), m, root)?;
    }
    let ctx = |r: Result<()>| r.context("preparing shared/");
    ctx(ensure_tree_nofollow(
        host,
        &base,
        Path::new("shared"),
        0o755,
        Some((www, www)),
    ))?;
    let mut rels = vec!["uploads".to_string()];
    rels.extend(
        site.writable_paths()
            .into_iter()
            .map(|w| shared_rel(w).to_string()),
    );
    for rel in rels {
        let mut first = true;
        ctx(walk_nofollow(
            &base,
            &Path::new("shared").join(&rel),
            &mut |dir, path| {
                if std::mem::take(&mut first) {
                    return Ok(()); // `shared` itself: already 0755 www:www above
                }
                host.fchown(dir, path, www, www)?;
                dir.set_permissions(std::fs::Permissions::from_mode(0o2755))
                    .with_context(|| format!("chmod {}", path.display()))
            },
        ))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{GlobalConfig, parse_site};
    use crate::host::sys;
    use crate::testutil::RecordingHost;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn layout_modes_and_owners() {
        let h = RecordingHost::new(true);
        let g = GlobalConfig::default();
        let mut s = parse_site(include_str!("../../examples/acme.toml")).unwrap();
        s.plugins[1].writable = vec!["wp-content/cache/wf".into()];
        prepare_site_dirs(&h, &g, &s).unwrap();
        let b = sys(&h, s.base_dir(&g));
        let mode = |p: &str| std::fs::metadata(b.join(p)).unwrap().permissions().mode() & 0o7777;
        // Only root and the nginx group may enter a site tree: other sites' UIDs are "other".
        assert_eq!(mode(""), 0o750);
        assert_eq!(
            h.chowns()
                .iter()
                .rev()
                .find(|(q, _, _)| q == &b)
                .map(|c| (c.1, c.2)),
            Some((0, 991))
        );
        assert_eq!(mode("releases"), 0o755);
        assert_eq!(mode("backups"), 0o700);
        assert_eq!(mode("shared/uploads"), 0o2755);
        assert_eq!(mode("shared/cache"), 0o2755);
        assert_eq!(mode("shared/cache/wf"), 0o2755);
        let www = crate::host::identity::Identity::for_site(s.id, g.id_offset).www_uid;
        let owner = |p: &str| {
            h.chowns()
                .iter()
                .find(|(q, _, _)| q == &b.join(p))
                .map(|c| (c.1, c.2))
        };
        assert_eq!(owner("shared/uploads"), Some((www, www)));
        assert_eq!(owner("config"), Some((0, 0)));
        assert!(
            h.chowns().iter().all(|(p, _, _)| p.starts_with(&b)),
            "no chown outside base"
        );
    }

    #[test]
    fn unknown_nginx_group_is_an_error_before_any_change() {
        let h = RecordingHost::new(true);
        let g = GlobalConfig {
            nginx_group: "nosuch".into(),
            ..GlobalConfig::default()
        };
        let s = parse_site(include_str!("../../examples/simple.toml")).unwrap();
        let m = format!("{:#}", prepare_site_dirs(&h, &g, &s).unwrap_err());
        assert!(
            m.contains("group \"nosuch\"") && m.contains("nginx_group"),
            "{m}"
        );
        assert!(!sys(&h, s.base_dir(&g)).exists());
    }

    #[test]
    fn symlink_under_shared_is_refused_and_target_untouched() {
        let h = RecordingHost::new(true);
        let g = GlobalConfig::default();
        let mut s = parse_site(include_str!("../../examples/acme.toml")).unwrap();
        s.plugins[1].writable = vec!["wp-content/cache/wf".into()];
        let b = sys(&h, s.base_dir(&g));
        let target = crate::testutil::tmp();
        std::fs::set_permissions(target.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir_all(b.join("shared")).unwrap();
        std::os::unix::fs::symlink(target.path(), b.join("shared/cache")).unwrap();
        let err = prepare_site_dirs(&h, &g, &s).unwrap_err();
        let m = format!("{err:#}");
        assert!(
            m.contains("refusing to follow symlink") && m.contains("preparing shared/"),
            "{m}"
        );
        assert!(
            h.chowns()
                .iter()
                .all(|(p, _, _)| !p.starts_with(target.path()))
        );
        assert!(
            h.chowns()
                .iter()
                .all(|(p, _, _)| p != &b.join("shared/cache"))
        );
        assert_eq!(
            std::fs::metadata(target.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
    }
}
