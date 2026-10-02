//! Hashing helpers. `tree_hash` is the pin format for `path`/`git` sources.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{Context, Result, bail};
use md5::Md5;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn md5_hex(bytes: &[u8]) -> String {
    hex::encode(Md5::digest(bytes))
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let mut f = fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = [0; 8192];
    loop {
        let n = std::io::Read::read(&mut f, &mut buf)
            .with_context(|| format!("reading {}", path.display()))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

/// Regular files under `root` as (`/`-separated relative path, executable), sorted by path.
/// Errors on symlinks and special files; directories are traversed but not listed.
pub fn list_files(root: &Path) -> Result<Vec<(String, bool)>> {
    let md =
        fs::symlink_metadata(root).with_context(|| format!("inspecting {}", root.display()))?;
    if md.file_type().is_symlink() {
        bail!("{}: symlink not allowed as a tree root", root.display());
    }
    if !md.is_dir() {
        bail!("{}: not a directory", root.display());
    }
    let mut out = Vec::new();
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry.with_context(|| format!("walking {}", root.display()))?;
        if entry.depth() == 0 {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(root)
            .expect("walkdir yields paths under root")
            .to_str()
            .with_context(|| format!("non-UTF-8 path under {}", root.display()))?
            .to_string();
        if rel.chars().any(char::is_control) {
            bail!("{rel:?}: control character in file name");
        }
        let ft = entry.file_type();
        if ft.is_dir() {
            continue;
        }
        if !ft.is_file() {
            let kind = if ft.is_symlink() {
                "symlink"
            } else {
                "special file"
            };
            bail!("{rel}: {kind} not allowed (only regular files and directories)");
        }
        let exec = entry.metadata()?.permissions().mode() & 0o111 != 0;
        out.push((rel, exec));
    }
    out.sort();
    Ok(out)
}

pub fn tree_hash(root: &Path) -> Result<String> {
    let mut h = Sha256::new();
    for (rel, exec) in list_files(root)? {
        let file_hash = sha256_file(&root.join(&rel))?;
        h.update(format!(
            "{} {file_hash} {rel}\n",
            if exec { "x" } else { "-" }
        ));
    }
    Ok(hex::encode(h.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("iwp-test-")
            .tempdir()
            .unwrap()
    }

    #[test]
    fn known_digests() {
        assert_eq!(
            sha256_hex(b"a"),
            "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
        );
        assert_eq!(md5_hex(b"a"), "0cc175b9c0f1b6a831c399e269772661");
    }

    #[test]
    fn tree_hash_matches_definition() {
        let d = tmp();
        std::fs::create_dir(d.path().join("sub")).unwrap();
        std::fs::write(d.path().join("sub/b.txt"), "b").unwrap();
        std::fs::write(d.path().join("a.txt"), "a").unwrap();
        let expected = sha256_hex(
            format!(
                "- {} a.txt\n- {} sub/b.txt\n",
                sha256_hex(b"a"),
                sha256_hex(b"b")
            )
            .as_bytes(),
        );
        assert_eq!(tree_hash(d.path()).unwrap(), expected);
    }

    #[test]
    fn tree_hash_ignores_creation_order_and_empty_dirs() {
        let a = tmp();
        let b = tmp();
        std::fs::write(a.path().join("x"), "1").unwrap();
        std::fs::write(a.path().join("y"), "2").unwrap();
        std::fs::write(b.path().join("y"), "2").unwrap();
        std::fs::write(b.path().join("x"), "1").unwrap();
        std::fs::create_dir(b.path().join("empty")).unwrap();
        assert_eq!(tree_hash(a.path()).unwrap(), tree_hash(b.path()).unwrap());
    }

    #[test]
    fn tree_hash_sees_exec_bit_and_content() {
        let d = tmp();
        let f = d.path().join("run.sh");
        std::fs::write(&f, "x").unwrap();
        let h1 = tree_hash(d.path()).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        let h2 = tree_hash(d.path()).unwrap();
        assert_ne!(h1, h2);
        std::fs::write(&f, "y").unwrap();
        assert_ne!(h2, tree_hash(d.path()).unwrap());
    }

    #[test]
    fn symlinks_are_rejected() {
        let d = tmp();
        std::fs::write(d.path().join("real"), "r").unwrap();
        std::os::unix::fs::symlink("real", d.path().join("link")).unwrap();
        let err = tree_hash(d.path()).unwrap_err();
        assert!(format!("{err:#}").contains("link"), "{err:#}");
    }

    #[test]
    fn sha256_file_matches_bytes() {
        let d = tmp();
        std::fs::write(d.path().join("f"), "hello").unwrap();
        assert_eq!(
            sha256_file(&d.path().join("f")).unwrap(),
            sha256_hex(b"hello")
        );
    }

    #[test]
    fn control_characters_in_file_names_rejected() {
        let d = tmp();
        std::fs::write(d.path().join("a\nb"), "x").unwrap();
        let err = list_files(d.path()).unwrap_err();
        assert!(format!("{err:#}").contains("control character"), "{err:#}");
        assert!(tree_hash(d.path()).is_err());
    }

    #[test]
    fn root_must_be_a_real_directory() {
        let d = tmp();
        std::fs::write(d.path().join("f"), "x").unwrap();
        assert!(
            format!("{:#}", list_files(&d.path().join("f")).unwrap_err()).contains("directory")
        );
        std::fs::create_dir(d.path().join("real")).unwrap();
        std::os::unix::fs::symlink("real", d.path().join("link")).unwrap();
        let err = tree_hash(&d.path().join("link")).unwrap_err();
        assert!(format!("{err:#}").contains("symlink"), "{err:#}");
        assert!(list_files(&d.path().join("missing")).is_err());
    }
}
