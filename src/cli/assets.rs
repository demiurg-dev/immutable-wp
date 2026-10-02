//! `iwp assets export`: writes the files compiled into the binary (the `share/` trees).

use std::path::{Path, PathBuf};

use anyhow::Context;
use include_dir::Dir;

use super::*;

/// Every embedded asset as (path relative to `share/`, contents).
pub(super) fn embedded() -> Vec<(PathBuf, &'static [u8])> {
    let mut out = Vec::new();
    let trees: [(&str, &Dir<'static>); 3] = [
        ("containerfile", &crate::host::image::CONTAINERFILE),
        ("mu-plugin", &crate::build::MU_PLUGIN),
        ("templates", &crate::render::TEMPLATES),
    ];
    for (prefix, dir) in trees {
        collect(dir, Path::new(prefix), &mut out);
    }
    out.push((
        PathBuf::from("selinux/iwp.te"),
        crate::host::selinux::MODULE_TE.as_bytes(),
    ));
    out.sort();
    out
}

fn collect(dir: &Dir<'static>, prefix: &Path, out: &mut Vec<(PathBuf, &'static [u8])>) {
    // include_dir paths are relative to the embedded root, so nested entries already carry
    // their sub-directory.
    for f in dir.files() {
        out.push((prefix.join(f.path()), f.contents()));
    }
    for d in dir.dirs() {
        collect(d, prefix, out);
    }
}

/// Refuses (as root) a target that another user could have prepared or can change: `dir`
/// itself when it exists, else its parent, must be a root-owned directory without group or
/// other write permission.
fn check_root_target(dir: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let (what, m) = match std::fs::symlink_metadata(dir) {
        Ok(m) => (dir.to_path_buf(), m),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let parent = match dir.parent() {
                Some(p) if !p.as_os_str().is_empty() => p,
                _ => Path::new("."),
            };
            let m = std::fs::symlink_metadata(parent)
                .with_context(|| format!("inspecting {}", parent.display()))?;
            (parent.to_path_buf(), m)
        }
        Err(e) => {
            return Err(anyhow::Error::new(e).context(format!("inspecting {}", dir.display())));
        }
    };
    let refuse = |why: String| -> Result<()> {
        Err(UsageError(format!(
            "as root, iwp assets export only writes into a root-owned directory that only root can write to: {} {why}",
            what.display()
        ))
        .into())
    };
    if !m.is_dir() {
        return refuse("is not a directory (or is a symlink)".into());
    }
    if m.mode() & 0o022 != 0 {
        return refuse(format!(
            "is group or other writable (mode {:o})",
            m.mode() & 0o7777
        ));
    }
    if m.uid() != 0 {
        return refuse(format!("is owned by uid {}", m.uid()));
    }
    Ok(())
}

/// Creates `p` (which must not exist; never through a symlink) with `body`.
fn write_new(p: &Path, body: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)
        .with_context(|| format!("creating {}", p.display()))?;
    f.write_all(body)
        .with_context(|| format!("writing {}", p.display()))
}

/// Creates the directory `p` unless it already is a real directory (never a symlink).
fn make_dir(p: &Path) -> Result<()> {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => Ok(()),
        Ok(_) => anyhow::bail!("{} exists and is not a directory", p.display()),
        Err(_) => std::fs::create_dir(p).with_context(|| format!("creating {}", p.display())),
    }
}

/// Writes every embedded asset under `dir` (which must be absent or empty) and returns the
/// written paths. As root (`as_root`), `dir` (or, when absent, its parent) must be root-owned
/// and not group/other-writable; files are always created new, never through a symlink.
pub(super) fn export(dir: &Path, as_root: bool) -> Result<Vec<PathBuf>> {
    if as_root {
        check_root_target(dir)?;
    }
    match std::fs::read_dir(dir) {
        Ok(mut entries) => {
            if entries.next().is_some() {
                return Err(UsageError(format!("{} is not empty", dir.display())).into());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotADirectory => {
            return Err(UsageError(format!("{} is not a directory", dir.display())).into());
        }
        Err(e) => {
            return Err(anyhow::Error::new(e).context(format!("reading {}", dir.display())));
        }
    }
    if as_root {
        make_dir(dir)?;
    } else {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let mut written = Vec::new();
    for (rel, body) in embedded() {
        let p = dir.join(&rel);
        let mut cur = dir.to_path_buf();
        for c in rel.parent().into_iter().flat_map(Path::components) {
            cur.push(c);
            make_dir(&cur)?;
        }
        write_new(&p, body)?;
        written.push(p);
    }
    Ok(written)
}

pub(super) fn assets_cmd(action: AssetsAction) -> Result<ExitCode> {
    match action {
        AssetsAction::Export { dir } => {
            let as_root = crate::host::SystemHost::new().is_root();
            for p in export(&dir, as_root)? {
                println!("{}", p.display());
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_writes_each_embedded_file_byte_for_byte() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("out");
        let written = export(&dir, false).unwrap();
        let assets = embedded();
        assert_eq!(written.len(), assets.len());
        for (rel, body) in &assets {
            assert_eq!(
                std::fs::read(dir.join(rel)).unwrap(),
                *body,
                "{}",
                rel.display()
            );
            assert!(written.contains(&dir.join(rel)));
        }
        for rel in [
            "containerfile/Containerfile",
            "mu-plugin/iwp.php",
            "selinux/iwp.te",
            "templates/nginx-site.conf.j2",
        ] {
            assert!(assets.iter().any(|(p, _)| p == Path::new(rel)), "{rel}");
        }
    }

    #[test]
    fn embedded_covers_the_whole_share_tree() {
        let share = Path::new(env!("CARGO_MANIFEST_DIR")).join("share");
        let on_disk: Vec<PathBuf> = walkdir::WalkDir::new(&share)
            .sort_by_file_name()
            .into_iter()
            .map(|e| e.unwrap())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.path().strip_prefix(&share).unwrap().to_path_buf())
            .collect();
        let mut embedded: Vec<PathBuf> = embedded().into_iter().map(|(p, _)| p).collect();
        embedded.sort();
        let mut on_disk = on_disk;
        on_disk.sort();
        assert_eq!(embedded, on_disk);
    }

    #[test]
    fn export_refuses_a_non_empty_dir_with_a_usage_error() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("x"), "keep").unwrap();
        let e = export(tmp.path(), false).unwrap_err();
        assert!(e.downcast_ref::<UsageError>().is_some(), "{e:#}");
        assert!(e.to_string().contains("not empty"), "{e:#}");
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("x")).unwrap(),
            "keep"
        );
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 1);
    }

    #[test]
    fn export_into_an_existing_empty_dir_works() {
        let tmp = tempfile::tempdir().unwrap();
        let written = export(tmp.path(), false).unwrap();
        assert_eq!(written.len(), embedded().len());
    }

    // ---- F6: as root, only into a root-owned, non-group/other-writable directory ----

    fn euid() -> u32 {
        // SAFETY: no preconditions.
        unsafe { libc::geteuid() }
    }

    #[test]
    fn as_root_refuses_group_or_other_writable_dirs_and_parents() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let open = tmp.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        let e = export(&open, true).unwrap_err();
        assert!(e.downcast_ref::<UsageError>().is_some(), "{e:#}");
        assert!(format!("{e:#}").contains("writable"), "{e:#}");
        assert_eq!(std::fs::read_dir(&open).unwrap().count(), 0);
        // Missing dir: its parent is judged instead.
        let e = export(&open.join("new"), true).unwrap_err();
        assert!(e.downcast_ref::<UsageError>().is_some(), "{e:#}");
        assert!(!open.join("new").exists());
    }

    #[test]
    fn as_root_refuses_a_dir_not_owned_by_root() {
        if euid() == 0 {
            return; // everything a userns root creates is owned by root
        }
        let tmp = tempfile::tempdir().unwrap();
        let e = export(tmp.path(), true).unwrap_err();
        assert!(e.downcast_ref::<UsageError>().is_some(), "{e:#}");
        assert!(format!("{e:#}").contains("owned by uid"), "{e:#}");
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
    }

    #[test]
    fn as_root_into_a_safe_root_owned_dir_works() {
        use std::os::unix::fs::PermissionsExt;
        if euid() != 0 {
            eprintln!("skipped: needs root (run under `podman unshare`)");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let d = tmp.path().join("out");
        assert_eq!(export(&d, true).unwrap().len(), embedded().len());
    }

    #[test]
    fn files_are_created_new_and_never_through_a_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target");
        std::fs::write(&target, "keep").unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(write_new(&link, b"x").is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
        assert!(write_new(&target, b"x").is_err());
        write_new(&tmp.path().join("fresh"), b"x").unwrap();
    }
}
