//! Atomic, fsynced file replacement that keeps symlinks, mode and owner.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::host::Host;

#[derive(Debug, Clone, Copy, Default)]
pub struct FileSpec {
    pub mode: Option<u32>,
    pub owner: Option<(u32, u32)>,
}

fn resolve(path: &Path) -> Result<PathBuf> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            fs::canonicalize(path).with_context(|| format!("resolving symlink {}", path.display()))
        }
        _ => Ok(path.to_path_buf()),
    }
}

fn parent_dir(p: &Path) -> &Path {
    match p.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    }
}

pub fn write_atomic(host: &dyn Host, path: &Path, bytes: &[u8], spec: &FileSpec) -> Result<bool> {
    let target = resolve(path)?;
    let existing = fs::metadata(&target).ok();
    let mode = spec
        .mode
        .or(existing.as_ref().map(|m| m.permissions().mode() & 0o7777))
        .unwrap_or(0o644);
    if let Some(m) = &existing
        && m.permissions().mode() & 0o7777 == mode
        && spec
            .owner
            .is_none_or(|o| host.owner(&target).is_ok_and(|cur| cur == o))
        && fs::read(&target).is_ok_and(|b| b == bytes)
    {
        return Ok(false);
    }
    let dir = parent_dir(&target);
    let mut tmp = tempfile::NamedTempFile::new_in(dir)
        .with_context(|| format!("creating temp file in {}", dir.display()))?;
    tmp.write_all(bytes)?;
    // chown before chmod: Linux clears setuid/setgid bits on chown.
    let owner = match spec.owner {
        Some(o) => Some(o),
        None if existing.is_some() => host.owner(&target).ok(),
        None => None,
    };
    if let Some((uid, gid)) = owner {
        let cur = tmp.as_file().metadata()?;
        if (cur.uid(), cur.gid()) != (uid, gid) {
            host.chown(tmp.path(), uid, gid)?;
        }
    }
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(mode))?;
    tmp.as_file().sync_all()?;
    tmp.persist(&target)
        .with_context(|| format!("replacing {}", target.display()))?;
    fs::File::open(dir)?.sync_all()?;
    // The temp file was chowned before persist so there is never a window with a wrong
    // owner. Re-assert on the target when the host does not see it as owned correctly
    // (a no-op on a real host, where the owner already carried over through the rename;
    // needed so simulated hosts track the owner by the final path).
    if let Some((uid, gid)) = owner
        && host.owner(&target).is_ok_and(|cur| cur != (uid, gid))
    {
        host.chown(&target, uid, gid)?;
    }
    Ok(true)
}

pub fn ensure_dir(
    host: &dyn Host,
    path: &Path,
    mode: u32,
    owner: Option<(u32, u32)>,
) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {}", path.display()))?;
    if let Some((uid, gid)) = owner {
        host.chown(path, uid, gid)?;
    }
    Ok(())
}

/// Like `ensure_dir`, but the final component is never followed if it is a symlink: a symlink
/// or non-directory there is an error, and mode/owner are applied through a no-follow handle
/// and `lchown`. Missing parent directories are created normally.
pub fn ensure_dir_nofollow(
    host: &dyn Host,
    path: &Path,
    mode: u32,
    owner: Option<(u32, u32)>,
) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            anyhow::bail!("refusing to follow symlink {}", path.display())
        }
        Ok(m) if !m.is_dir() => anyhow::bail!("{} exists and is not a directory", path.display()),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            match fs::create_dir(path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e).with_context(|| format!("creating {}", path.display())),
            }
        }
        Err(e) => return Err(e).with_context(|| format!("stat {}", path.display())),
    }
    // O_NOFOLLOW|O_DIRECTORY closes the check/use window: a symlink swapped in now fails the open.
    let dir = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)
        .with_context(|| {
            format!(
                "refusing to follow symlink {} (or not a directory)",
                path.display()
            )
        })?;
    // chown before chmod: Linux clears setuid/setgid bits on chown.
    if let Some((uid, gid)) = owner {
        host.lchown(path, uid, gid)?;
    }
    dir.set_permissions(fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {}", path.display()))?;
    Ok(())
}

pub(crate) fn cstr(s: &std::ffi::OsStr) -> Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(s.as_bytes()).context("path contains NUL")
}

pub(crate) fn nofollow_err(e: std::io::Error, full: &Path) -> anyhow::Error {
    match e.raw_os_error() {
        Some(libc::ELOOP) | Some(libc::ENOTDIR) => anyhow::anyhow!(
            "refusing to follow symlink {} (or not a directory)",
            full.display()
        ),
        _ => anyhow::Error::new(e).context(format!("opening {}", full.display())),
    }
}

/// Walks `root/rel` one component at a time through directory handles (openat + O_NOFOLLOW),
/// creating missing components (mode 0700 until `each` adjusts them). No component, including
/// `root`, is ever reached through a symlink. `each` runs for every component of `rel`.
pub fn walk_nofollow(
    root: &Path,
    rel: &Path,
    each: &mut dyn FnMut(&fs::File, &Path) -> Result<()>,
) -> Result<()> {
    walk(root, rel, true, each).map(|_| ())
}

/// The walk behind `walk_nofollow`. With `create == false` a missing component ends the walk
/// with `Ok(None)`; otherwise the handle of `root/rel` is returned.
fn walk(
    root: &Path,
    rel: &Path,
    create: bool,
    each: &mut dyn FnMut(&fs::File, &Path) -> Result<()>,
) -> Result<Option<fs::File>> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Component;
    let mut cur = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(root)
        .map_err(|e| nofollow_err(e, root))?;
    let mut full = root.to_path_buf();
    for comp in rel.components() {
        let Component::Normal(name) = comp else {
            anyhow::bail!("{} must be a plain relative path", rel.display());
        };
        full.push(name);
        let c = cstr(name)?;
        if create {
            // SAFETY: valid dirfd and NUL-terminated name.
            if unsafe { libc::mkdirat(cur.as_raw_fd(), c.as_ptr(), 0o700) } != 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() != Some(libc::EEXIST) {
                    return Err(e).with_context(|| format!("creating {}", full.display()));
                }
            }
        }
        let next = match open_dir_at_raw(&cur, name)? {
            Ok(f) => f,
            Err(e) if !create && e.raw_os_error() == Some(libc::ENOENT) => return Ok(None),
            Err(e) => return Err(nofollow_err(e, &full)),
        };
        each(&next, &full)?;
        cur = next;
    }
    Ok(Some(cur))
}

/// `openat(O_NOFOLLOW|O_DIRECTORY)`; the inner error is the raw OS error.
pub(crate) fn open_dir_at_raw(
    parent: &fs::File,
    name: &std::ffi::OsStr,
) -> Result<std::io::Result<fs::File>> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let c = cstr(name)?;
    // SAFETY: valid dirfd and NUL-terminated name; the returned fd is owned by the File.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Ok(Err(std::io::Error::last_os_error()));
    }
    // SAFETY: fd is a fresh, owned descriptor.
    Ok(Ok(unsafe { fs::File::from_raw_fd(fd) }))
}

/// Names in the directory open as `dir` (without `.` and `..`), read through a duplicate fd.
pub(crate) fn dir_entries(dir: &fs::File, full: &Path) -> Result<Vec<std::ffi::OsString>> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: dup of a valid fd; on success the new fd is owned by the DIR stream below.
    let fd = unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("dup {}", full.display()));
    }
    // SAFETY: fd is a fresh directory descriptor; fdopendir takes ownership on success.
    let dirp = unsafe { libc::fdopendir(fd) };
    if dirp.is_null() {
        let e = std::io::Error::last_os_error();
        // SAFETY: fdopendir failed, so fd is still ours to close.
        unsafe { libc::close(fd) };
        return Err(e).with_context(|| format!("reading {}", full.display()));
    }
    // The duplicate shares the file offset with `dir`; start from the beginning.
    // SAFETY: dirp is a valid stream.
    unsafe { libc::rewinddir(dirp) };
    let mut out = Vec::new();
    let result = loop {
        // SAFETY: errno is thread-local; reset it to tell end-of-stream from an error.
        unsafe { *libc::__errno_location() = 0 };
        // SAFETY: dirp is a valid stream.
        let ent = unsafe { libc::readdir(dirp) };
        if ent.is_null() {
            let e = std::io::Error::last_os_error();
            break if e.raw_os_error().unwrap_or(0) == 0 {
                Ok(())
            } else {
                Err(e)
            };
        }
        // SAFETY: d_name is NUL-terminated inside the dirent readdir returned.
        let name = unsafe { std::ffi::CStr::from_ptr((*ent).d_name.as_ptr()) };
        let b = name.to_bytes();
        if b != b"." && b != b".." {
            out.push(std::ffi::OsStr::from_bytes(b).to_os_string());
        }
    };
    // SAFETY: closes the stream and the fd it owns.
    unsafe { libc::closedir(dirp) };
    result.with_context(|| format!("reading {}", full.display()))?;
    Ok(out)
}

/// Removes everything inside the directory open as `dir`, never following a symlink and never
/// changing a mode. Entries that vanish concurrently (ENOENT) are fine.
fn empty_at(dir: &fs::File, full: &Path) -> Result<()> {
    use std::os::fd::AsRawFd;
    for name in dir_entries(dir, full)? {
        let path = full.join(&name);
        let c = cstr(&name)?;
        // SAFETY: zeroed stat is a valid out-buffer; valid dirfd and NUL-terminated name.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::fstatat(
                dir.as_raw_fd(),
                c.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ENOENT) {
                continue;
            }
            return Err(e).with_context(|| format!("stat {}", path.display()));
        }
        let flags = if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
            match open_dir_at_raw(dir, &name)? {
                Ok(sub) => empty_at(&sub, &path)?,
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue,
                Err(e) => return Err(nofollow_err(e, &path)),
            }
            libc::AT_REMOVEDIR
        } else {
            0
        };
        // SAFETY: valid dirfd and NUL-terminated name.
        if unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), flags) } != 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::ENOENT) {
                return Err(e).with_context(|| format!("removing {}", path.display()));
            }
        }
    }
    Ok(())
}

/// Deletes the contents (not the directory itself) of `root/rel`. Every component is reached
/// through a no-follow handle walk; nothing is created. A missing component is `Ok`; a symlink
/// at any component (including the last, which is left in place) or a non-directory is an
/// error. Symlinks inside are removed, never followed; modes are never changed.
pub fn empty_dir_nofollow(root: &Path, rel: &Path) -> Result<()> {
    match walk(root, rel, false, &mut |_, _| Ok(()))? {
        Some(dir) => empty_at(&dir, &root.join(rel)),
        None => Ok(()),
    }
}

/// `walk_nofollow` that fchowns (when `owner` is set) then fchmods every component.
pub fn ensure_tree_nofollow(
    host: &dyn Host,
    root: &Path,
    rel: &Path,
    mode: u32,
    owner: Option<(u32, u32)>,
) -> Result<()> {
    walk_nofollow(root, rel, &mut |dir, path| {
        // chown before chmod: Linux clears setuid/setgid bits on chown.
        if let Some((uid, gid)) = owner {
            host.fchown(dir, path, uid, gid)?;
        }
        dir.set_permissions(fs::Permissions::from_mode(mode))
            .with_context(|| format!("chmod {}", path.display()))
    })
}

/// Changes the owner of `root` and of everything below it, never following a symlink (a
/// symlink gets its own owner changed; nothing is reached through one). `root` itself must not
/// be a symlink. Returns the number of entries changed. Goes through `Host`.
pub fn chown_tree_nofollow(host: &dyn Host, root: &Path, uid: u32, gid: u32) -> Result<u64> {
    host.chown_tree_nofollow(root, uid, gid)
}

/// The real walk behind `SystemHost::chown_tree_nofollow`: directories are opened with
/// `openat(O_NOFOLLOW|O_DIRECTORY)` and changed with `fchown`; everything else with
/// `fchownat(AT_SYMLINK_NOFOLLOW)` relative to its parent's handle.
pub fn chown_tree_real(root: &Path, uid: u32, gid: u32) -> Result<u64> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(root)
        .map_err(|e| nofollow_err(e, root))?;
    std::os::unix::fs::fchown(&dir, Some(uid), Some(gid))
        .with_context(|| format!("chown {}", root.display()))?;
    Ok(1 + chown_at(&dir, root, uid, gid)?)
}

fn chown_at(dir: &fs::File, full: &Path, uid: u32, gid: u32) -> Result<u64> {
    use std::os::fd::AsRawFd;
    let mut n = 0;
    for name in dir_entries(dir, full)? {
        let path = full.join(&name);
        let c = cstr(&name)?;
        // SAFETY: zeroed stat is a valid out-buffer; valid dirfd and NUL-terminated name.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::fstatat(
                dir.as_raw_fd(),
                c.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ENOENT) {
                continue;
            }
            return Err(e).with_context(|| format!("stat {}", path.display()));
        }
        if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
            let sub = match open_dir_at_raw(dir, &name)? {
                Ok(sub) => sub,
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue,
                Err(e) => return Err(nofollow_err(e, &path)),
            };
            std::os::unix::fs::fchown(&sub, Some(uid), Some(gid))
                .with_context(|| format!("chown {}", path.display()))?;
            n += 1 + chown_at(&sub, &path, uid, gid)?;
        } else {
            // SAFETY: valid dirfd and NUL-terminated name.
            if unsafe {
                libc::fchownat(
                    dir.as_raw_fd(),
                    c.as_ptr(),
                    uid,
                    gid,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::ENOENT) {
                    continue;
                }
                return Err(e).with_context(|| format!("chown {}", path.display()));
            }
            n += 1;
        }
    }
    Ok(n)
}

/// The directory `root/rel`, every component (including `root`) opened without following a
/// symlink; `Ok(None)` when a component is missing. Nothing is created.
pub fn open_dir_nofollow(root: &Path, rel: &Path) -> Result<Option<fs::File>> {
    walk(root, rel, false, &mut |_, _| Ok(()))
}

/// `fstatat(AT_SYMLINK_NOFOLLOW)` of `name` in the directory open as `dir`.
pub(crate) fn lstat_at(
    dir: &fs::File,
    name: &std::ffi::OsStr,
) -> Result<std::io::Result<libc::stat>> {
    use std::os::fd::AsRawFd;
    let c = cstr(name)?;
    // SAFETY: zeroed stat is a valid out-buffer; valid dirfd and NUL-terminated name.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let r = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            c.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    Ok(if r == 0 {
        Ok(st)
    } else {
        Err(std::io::Error::last_os_error())
    })
}

/// Opens the regular file `name` in the directory open as `dir` for reading, refusing a
/// symlink (`O_NOFOLLOW`) and anything that is not a regular file (`O_NONBLOCK` keeps a FIFO
/// swapped in from blocking the open). `full` names it in errors.
pub(crate) fn open_file_at(
    dir: &fs::File,
    name: &std::ffi::OsStr,
    full: &Path,
) -> Result<fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let c = cstr(name)?;
    // SAFETY: valid dirfd and NUL-terminated name; the returned fd is owned by the File.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ELOOP) {
            anyhow::bail!("{}: symlink refused", full.display());
        }
        return Err(e).with_context(|| format!("opening {}", full.display()));
    }
    // SAFETY: fd is a fresh, owned descriptor.
    let f = unsafe { fs::File::from_raw_fd(fd) };
    if !f.metadata()?.is_file() {
        anyhow::bail!("{}: not a regular file", full.display());
    }
    Ok(f)
}

/// What `lstat_at` + `open_file_at` found at a name inside a directory handle.
#[derive(Debug)]
pub enum NofollowEntry {
    Missing,
    Symlink,
    /// Exists but is neither a regular file nor a symlink.
    Other,
    Regular(fs::File),
}

/// Looks at `name` in the directory open as `dir` without following a symlink: a regular file
/// is opened (`O_NOFOLLOW`, regular files only); `full` names it in errors.
pub fn entry_nofollow(
    dir: &fs::File,
    name: &std::ffi::OsStr,
    full: &Path,
) -> Result<NofollowEntry> {
    let st = match lstat_at(dir, name)? {
        Ok(st) => st,
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(NofollowEntry::Missing),
        Err(e) => return Err(e).with_context(|| format!("stat {}", full.display())),
    };
    Ok(match st.st_mode & libc::S_IFMT {
        libc::S_IFLNK => NofollowEntry::Symlink,
        libc::S_IFREG => NofollowEntry::Regular(open_file_at(dir, name, full)?),
        _ => NofollowEntry::Other,
    })
}

/// Reads the regular file `path` as root would, but never through a symlink at its last
/// component: a symlink (or anything but a regular file) is a usage error naming the path.
pub fn read_regular_file(path: &Path) -> Result<String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        anyhow::bail!("{} is not a file path", path.display());
    };
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let dir = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(parent)
        .with_context(|| format!("opening {}", parent.display()))?;
    let mut f = match entry_nofollow(&dir, name, path)? {
        NofollowEntry::Regular(f) => f,
        NofollowEntry::Missing => anyhow::bail!("{} does not exist", path.display()),
        NofollowEntry::Symlink => {
            return Err(crate::error::UsageError(format!(
                "{} is a symlink; refusing to read it as root: point at a regular, root-readable copy",
                path.display()
            ))
            .into());
        }
        NofollowEntry::Other => {
            return Err(crate::error::UsageError(format!(
                "{} is not a regular file",
                path.display()
            ))
            .into());
        }
    };
    let mut s = String::new();
    f.read_to_string(&mut s)
        .with_context(|| format!("reading {}", path.display()))?;
    Ok(s)
}

pub fn mkdirs_nofollow(root: &Path, rel: &Path) -> Result<()> {
    walk_nofollow(root, rel, &mut |_, _| Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{RecordingHost, tmp};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn walk_refuses_intermediate_symlink_and_leaves_target_alone() {
        let h = RecordingHost::new(true);
        let root = h.sysroot().join("base");
        let target = h.sysroot().join("elsewhere");
        fs::create_dir_all(root.join("shared")).unwrap();
        fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&target, root.join("shared/cache")).unwrap();
        let e = ensure_tree_nofollow(
            &h,
            &root,
            Path::new("shared/cache/wf"),
            0o2755,
            Some((5, 5)),
        )
        .unwrap_err();
        assert!(
            format!("{e:#}").contains("refusing to follow symlink"),
            "{e:#}"
        );
        assert!(!target.join("wf").exists());
        // Only the component before the symlink was touched.
        assert_eq!(h.chowns(), vec![(root.join("shared"), 5, 5)]);
    }

    #[test]
    fn walk_creates_and_sets_every_component() {
        let h = RecordingHost::new(true);
        let root = h.sysroot().join("base");
        fs::create_dir(&root).unwrap();
        ensure_tree_nofollow(&h, &root, Path::new("shared/a/b"), 0o2755, Some((5, 6))).unwrap();
        for p in ["shared", "shared/a", "shared/a/b"] {
            let m = fs::metadata(root.join(p)).unwrap().permissions().mode() & 0o7777;
            assert_eq!(m, 0o2755, "{p}");
        }
        assert_eq!(h.chowns().len(), 3);
    }

    #[test]
    fn walk_rejects_root_symlink_and_bad_rel() {
        let t = tmp();
        let real = t.path().join("real");
        fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, t.path().join("link")).unwrap();
        assert!(mkdirs_nofollow(&t.path().join("link"), Path::new("x")).is_err());
        assert!(!real.join("x").exists());
        assert!(mkdirs_nofollow(&real, Path::new("../x")).is_err());
        assert!(mkdirs_nofollow(&real, Path::new("/abs")).is_err());
    }

    fn spec(mode: Option<u32>) -> FileSpec {
        FileSpec { mode, owner: None }
    }

    #[test]
    fn writes_new_file_with_default_mode_and_reports_change() {
        let h = RecordingHost::new(false);
        let d = tmp();
        let p = d.path().join("f");
        assert!(write_atomic(&h, &p, b"a", &spec(None)).unwrap());
        assert_eq!(std::fs::read(&p).unwrap(), b"a");
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert!(
            !write_atomic(&h, &p, b"a", &spec(None)).unwrap(),
            "unchanged content is a no-op"
        );
    }

    #[test]
    fn keeps_existing_mode_and_owner() {
        let h = RecordingHost::new(false);
        let d = tmp();
        let p = d.path().join("f");
        std::fs::write(&p, "old").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        write_atomic(&h, &p, b"new", &spec(None)).unwrap();
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(h.chowns().is_empty(), "already the right owner: no chown");
    }

    #[test]
    fn preserves_symlink() {
        let h = RecordingHost::new(false);
        let d = tmp();
        let real = d.path().join("real.toml");
        std::fs::write(&real, "old").unwrap();
        let link = d.path().join("link.toml");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        write_atomic(&h, &link, b"new", &spec(None)).unwrap();
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read(&real).unwrap(), b"new");
    }

    #[test]
    fn no_temp_left_and_target_untouched_on_error() {
        if crate::testutil::skip_if_root() {
            return;
        }
        let h = RecordingHost::new(false);
        let d = tmp();
        let dir = d.path().join("ro");
        std::fs::create_dir(&dir).unwrap();
        let p = dir.join("f");
        std::fs::write(&p, "keep").unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        assert!(write_atomic(&h, &p, b"x", &spec(None)).is_err());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"keep");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
    }

    #[test]
    fn ensure_dir_sets_mode_and_owner() {
        let h = RecordingHost::new(true);
        let d = tmp();
        let p = d.path().join("a/b");
        ensure_dir(&h, &p, 0o2755, Some((1000, 1000))).unwrap();
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o7777,
            0o2755
        );
        assert_eq!(h.chowns(), vec![(p.clone(), 1000, 1000)]);
    }

    #[test]
    fn nofollow_refuses_symlink_and_leaves_target_alone() {
        let h = RecordingHost::new(true);
        let d = tmp();
        let target = d.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = ensure_dir_nofollow(&h, &link, 0o2755, Some((1000, 1000))).unwrap_err();
        assert!(
            format!("{err:#}").contains("refusing to follow symlink"),
            "{err:#}"
        );
        assert!(h.chowns().is_empty());
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
            0o700
        );
        let f = d.path().join("file");
        std::fs::write(&f, "x").unwrap();
        assert!(ensure_dir_nofollow(&h, &f, 0o755, None).is_err());
        let ok = d.path().join("a/b");
        ensure_dir_nofollow(&h, &ok, 0o2755, Some((1, 2))).unwrap();
        assert_eq!(
            std::fs::metadata(&ok).unwrap().permissions().mode() & 0o7777,
            0o2755
        );
        assert_eq!(h.chowns(), vec![(ok.clone(), 1, 2)]);
    }

    #[test]
    fn setgid_mode_survives_on_new_file() {
        let h = RecordingHost::new(false);
        let d = tmp();
        let p = d.path().join("f");
        write_atomic(&h, &p, b"a", &spec(Some(0o2755))).unwrap();
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o7777,
            0o2755
        );
    }

    #[test]
    fn differing_owner_defeats_noop_path() {
        if crate::testutil::skip_if_root() {
            return;
        }
        let h = RecordingHost::new(false);
        let d = tmp();
        let p = d.path().join("f");
        std::fs::write(&p, "a").unwrap();
        let s = FileSpec {
            mode: None,
            owner: Some((0, 0)),
        };
        assert!(write_atomic(&h, &p, b"a", &s).unwrap());
        let last = h.chowns().pop().unwrap();
        assert_eq!(last, (p.clone(), 0, 0), "target ends up owned by 0:0");
        assert!(!write_atomic(&h, &p, b"a", &s).unwrap(), "now a no-op");
    }

    #[test]
    fn bare_filename_parent_is_dot() {
        assert_eq!(parent_dir(Path::new("f.toml")), Path::new("."));
        assert_eq!(parent_dir(Path::new("/a/f")), Path::new("/a"));
    }

    #[test]
    fn chown_failure_leaves_target_and_no_temp() {
        if crate::testutil::skip_if_root() {
            return;
        }
        let h = RecordingHost::new(false).fail_chown();
        let d = tmp();
        let p = d.path().join("f");
        std::fs::write(&p, "keep").unwrap();
        let s = FileSpec {
            mode: None,
            owner: Some((0, 0)),
        };
        assert!(write_atomic(&h, &p, b"new", &s).is_err());
        assert_eq!(std::fs::read(&p).unwrap(), b"keep");
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 1);
    }

    fn cache_tree(h: &RecordingHost) -> (PathBuf, PathBuf) {
        let root = h.sysroot().join("base");
        let target = h.sysroot().join("elsewhere");
        fs::create_dir_all(root.join("shared")).unwrap();
        fs::create_dir_all(target.join("sub")).unwrap();
        fs::write(target.join("keep.txt"), b"k").unwrap();
        (root, target)
    }

    #[test]
    fn empty_dir_removes_contents_but_keeps_dir_and_link_targets() {
        let h = RecordingHost::new(true);
        let (root, target) = cache_tree(&h);
        let c = root.join("shared/cache");
        fs::create_dir_all(c.join("a/b")).unwrap();
        fs::write(c.join("f"), b"x").unwrap();
        fs::write(c.join("a/b/g"), b"y").unwrap();
        std::os::unix::fs::symlink(&target, c.join("link")).unwrap();
        std::os::unix::fs::symlink(&target, c.join("a/dirlink")).unwrap();
        fs::set_permissions(&c, fs::Permissions::from_mode(0o2755)).unwrap();
        empty_dir_nofollow(&root, Path::new("shared/cache")).unwrap();
        assert!(c.is_dir());
        assert_eq!(fs::read_dir(&c).unwrap().count(), 0);
        assert_eq!(
            fs::metadata(&c).unwrap().permissions().mode() & 0o7777,
            0o2755
        );
        assert!(target.join("keep.txt").exists() && target.join("sub").is_dir());
    }

    #[test]
    fn empty_dir_refuses_intermediate_symlink() {
        let h = RecordingHost::new(true);
        let (root, target) = cache_tree(&h);
        std::os::unix::fs::symlink(&target, root.join("shared/w")).unwrap();
        let e = empty_dir_nofollow(&root, Path::new("shared/w/sub")).unwrap_err();
        assert!(
            format!("{e:#}").contains("refusing to follow symlink"),
            "{e:#}"
        );
        assert!(target.join("keep.txt").exists() && target.join("sub").is_dir());
    }

    #[test]
    fn empty_dir_refuses_final_symlink_and_leaves_it() {
        let h = RecordingHost::new(true);
        let (root, target) = cache_tree(&h);
        let link = root.join("shared/cache");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let e = empty_dir_nofollow(&root, Path::new("shared/cache")).unwrap_err();
        assert!(
            format!("{e:#}").contains("refusing to follow symlink"),
            "{e:#}"
        );
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(target.join("keep.txt").exists() && target.join("sub").is_dir());
    }

    #[test]
    fn empty_dir_non_directory_is_an_error_and_missing_is_ok() {
        let h = RecordingHost::new(true);
        let (root, _) = cache_tree(&h);
        fs::write(root.join("shared/file"), b"x").unwrap();
        assert!(empty_dir_nofollow(&root, Path::new("shared/file")).is_err());
        assert!(root.join("shared/file").exists());
        empty_dir_nofollow(&root, Path::new("shared/missing/deeper")).unwrap();
        assert!(!root.join("shared/missing").exists(), "nothing is created");
    }

    /// base/{a/{f1, b/{f2}}, top.txt, out -> outside/}; outside/{secret}.
    fn chown_fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let t = tmp();
        let base = t.path().join("base");
        let outside = t.path().join("outside");
        fs::create_dir_all(base.join("a/b")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(base.join("a/f1"), b"1").unwrap();
        fs::write(base.join("a/b/f2"), b"2").unwrap();
        fs::write(base.join("top.txt"), b"t").unwrap();
        fs::write(outside.join("secret"), b"s").unwrap();
        std::os::unix::fs::symlink(&outside, base.join("out")).unwrap();
        (t, base, outside)
    }

    #[test]
    fn chown_tree_walks_everything_but_never_through_a_symlink() {
        let (_t, base, _outside) = chown_fixture();
        // SAFETY: no preconditions.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        // Same owner: exercises the walk as a non-root runner. base, a, a/f1, a/b, a/b/f2,
        // top.txt and the link itself; nothing under outside/.
        assert_eq!(chown_tree_real(&base, uid, gid).unwrap(), 7);
        // Root symlink refused.
        let e = chown_tree_real(&base.join("out"), uid, gid).unwrap_err();
        assert!(
            format!("{e:#}").contains("refusing to follow symlink"),
            "{e:#}"
        );
    }

    #[test]
    fn chown_tree_changes_owner_under_userns_root() {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipped: needs root (run under `podman unshare`)");
            return;
        }
        let (_t, base, outside) = chown_fixture();
        let before = fs::metadata(outside.join("secret")).unwrap().uid();
        assert_eq!(chown_tree_real(&base, 1234, 1235).unwrap(), 7);
        for p in ["", "a", "a/f1", "a/b", "a/b/f2", "top.txt", "out"] {
            let m = fs::symlink_metadata(base.join(p)).unwrap();
            assert_eq!((m.uid(), m.gid()), (1234, 1235), "{p}");
        }
        assert_eq!(fs::metadata(&outside).unwrap().uid(), before);
        assert_eq!(fs::metadata(outside.join("secret")).unwrap().uid(), before);
    }

    #[test]
    fn chown_tree_is_one_recorded_call() {
        let h = RecordingHost::new(true);
        let p = h.sysroot().join("up");
        assert_eq!(chown_tree_nofollow(&h, &p, 5, 6).unwrap(), 0);
        let calls: Vec<String> = h.calls().iter().map(ToString::to_string).collect();
        assert_eq!(calls, vec![format!("chown_tree {} 5 6", p.display())]);
    }
}
