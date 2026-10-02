//! Per-site and host-wide nginx locks (flock on files under /run/iwp), and the guard every
//! iwp flock is held through.

use std::fs::{self, File, TryLockError};

use anyhow::{Context, Result};

use crate::host::{Host, sys};

fn open(host: &dyn Host, name: &str) -> Result<File> {
    let dir = sys(host, "/run/iwp");
    if !dir.is_dir() {
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755))?;
    }
    let p = dir.join(name);
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&p)
        .with_context(|| format!("opening {}", p.display()))
}

/// A held `flock` that is released explicitly when dropped.
///
/// A flock belongs to the open file description, not the fd. A child forked by any thread
/// (every `Command::spawn`) holds a duplicate of each fd until it execs, so merely closing our
/// fd can leave the lock held by that child for a while, and an immediate re-acquire then sees
/// WouldBlock. `LOCK_UN` through our fd releases it on the shared description at once.
#[derive(Debug)]
pub struct FileLock(File);

impl FileLock {
    /// Takes ownership of a file whose lock the caller has just acquired.
    pub fn held(f: File) -> Self {
        Self(f)
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

#[derive(Debug)]
pub struct SiteLock(#[allow(dead_code)] FileLock);

impl SiteLock {
    pub fn acquire(host: &dyn Host, site: &str) -> Result<Self> {
        let f = open(host, &format!("{site}.lock"))?;
        match f.try_lock() {
            Ok(()) => Ok(Self(FileLock::held(f))),
            Err(TryLockError::WouldBlock) => {
                anyhow::bail!("another iwp operation on {site} is in progress")
            }
            Err(TryLockError::Error(e)) => Err(e).context("locking site lock"),
        }
    }
}

#[derive(Debug)]
pub struct NginxLock(#[allow(dead_code)] FileLock);

impl NginxLock {
    pub fn acquire(host: &dyn Host) -> Result<Self> {
        let f = open(host, "nginx.lock")?;
        f.lock().context("locking nginx lock")?;
        Ok(Self(FileLock::held(f)))
    }
}

/// Host-wide lock around site creation (`new`, `import`): id assignment and the site-file
/// installation happen under it, so two concurrent creations never get the same id.
#[derive(Debug)]
pub struct SitesLock(#[allow(dead_code)] FileLock);

impl SitesLock {
    /// Blocks until the lock is free.
    pub fn acquire(host: &dyn Host) -> Result<Self> {
        let f = open(host, "sites.lock")?;
        f.lock().context("locking the sites lock")?;
        Ok(Self(FileLock::held(f)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::RecordingHost;

    #[test]
    fn site_lock_is_exclusive_per_site() {
        let h = RecordingHost::new(true);
        let a = SiteLock::acquire(&h, "a").unwrap();
        let e = SiteLock::acquire(&h, "a").unwrap_err();
        assert_eq!(format!("{e}"), "another iwp operation on a is in progress");
        let _b = SiteLock::acquire(&h, "b").unwrap();
        drop(a);
        SiteLock::acquire(&h, "a").unwrap();
    }

    #[test]
    fn nginx_lock_blocks_until_released() {
        let h = RecordingHost::new(true);
        let first = NginxLock::acquire(&h).unwrap();
        let root = h.sysroot().to_path_buf();
        let (tx, rx) = std::sync::mpsc::channel();
        let t = std::thread::spawn(move || {
            let h2 = RecordingHost::with_root(&root);
            let _l = NginxLock::acquire(&h2).unwrap();
            tx.send(()).unwrap();
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(200))
                .is_err()
        );
        drop(first);
        rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        t.join().unwrap();
    }

    /// Forks a child that inherits every fd and holds it (without exec) until the parent says
    /// so, as a concurrent `Command::spawn` from another thread does between fork and exec.
    /// Returns the child pid and the write end of its release pipe.
    fn fork_holding_fds() -> (libc::pid_t, libc::c_int) {
        let mut p = [0 as libc::c_int; 2];
        assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0);
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            // Child: only async-signal-safe calls. Block until the parent closes the pipe.
            unsafe {
                libc::close(p[1]);
                let mut b = 0u8;
                libc::read(p[0], (&mut b as *mut u8).cast(), 1);
                libc::_exit(0);
            }
        }
        unsafe { libc::close(p[0]) };
        (pid, p[1])
    }

    fn reap(pid: libc::pid_t, release: libc::c_int) {
        unsafe {
            libc::close(release);
            let mut st = 0;
            libc::waitpid(pid, &mut st, 0);
        }
    }

    /// A forked child keeps the lock's open file description alive; dropping the guard
    /// must still release the lock (flock locks belong to the description, not the fd).
    #[test]
    fn dropped_locks_are_released_while_a_forked_child_holds_the_fd() {
        let _spawn = crate::testutil::spawn_guard();
        let h = RecordingHost::new(true);
        let site = SiteLock::acquire(&h, "a").unwrap();
        let nginx = NginxLock::acquire(&h).unwrap();
        let (pid, release) = fork_holding_fds();
        drop(site);
        drop(nginx);
        let again = SiteLock::acquire(&h, "a");
        let nginx_free = {
            let f = open(&h, "nginx.lock").unwrap();
            let r = f.try_lock().is_ok();
            drop(f);
            r
        };
        reap(pid, release);
        again.unwrap();
        assert!(nginx_free, "nginx lock still held by the forked child");
    }
}
