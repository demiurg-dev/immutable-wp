//! Test helpers shared by unit tests across modules.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::Write;

/// Serialises tests that take the build flock against tests that spawn child
/// processes: a forked child briefly shares the parent's open file descriptions until exec,
/// which can keep a lock alive past `drop`. Poisoning is ignored.
static SPAWN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn spawn_guard() -> std::sync::MutexGuard<'static, ()> {
    SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn tmp() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("iwp-test-")
        .tempdir()
        .unwrap()
}

pub fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default();
    for (name, body) in entries {
        if name.ends_with('/') {
            w.add_directory(*name, opts).unwrap();
        } else {
            w.start_file(*name, opts).unwrap();
            w.write_all(body).unwrap();
        }
    }
    w.finish().unwrap().into_inner()
}

pub fn make_zip_with_symlink(name: &str, target: &str) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default();
    w.add_symlink(name, target, opts).unwrap();
    w.finish().unwrap().into_inner()
}

#[derive(Default)]
pub struct FakeFetcher {
    responses: BTreeMap<String, Vec<u8>>,
    calls: RefCell<Vec<String>>,
}

impl FakeFetcher {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with(mut self, url: &str, body: impl Into<Vec<u8>>) -> Self {
        self.responses.insert(url.to_string(), body.into());
        self
    }
    pub fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }
}

impl crate::fetch::net::Fetcher for FakeFetcher {
    fn get(&self, url: &str) -> anyhow::Result<Vec<u8>> {
        self.calls.borrow_mut().push(url.to_string());
        self.responses.get(url).cloned().ok_or_else(|| {
            anyhow::Error::new(ureq::Error::StatusCode(404)).context(format!("GET {url}"))
        })
    }
}

pub struct RecordingHost {
    root: std::path::PathBuf,
    _tmp: Option<tempfile::TempDir>,
    is_root: bool,
    rules: Vec<(String, crate::host::CmdOutput)>,
    once: RefCell<Vec<(String, crate::host::CmdOutput)>>,
    spawn_fail: Vec<String>,
    calls: RefCell<Vec<crate::host::Cmd>>,
    chowns: RefCell<Vec<(std::path::PathBuf, u32, u32)>>,
    fail_chown: bool,
}

impl RecordingHost {
    pub fn new(is_root: bool) -> Self {
        let t = tmp();
        // Hosts have an nginx group; `prepare_site_dirs` resolves it from /etc/group.
        std::fs::create_dir_all(t.path().join("etc")).unwrap();
        std::fs::write(t.path().join("etc/group"), "root:x:0:\nnginx:x:991:\n").unwrap();
        Self {
            root: t.path().to_path_buf(),
            _tmp: Some(t),
            is_root,
            rules: Vec::new(),
            once: RefCell::new(Vec::new()),
            spawn_fail: Vec::new(),
            calls: RefCell::new(Vec::new()),
            chowns: RefCell::new(Vec::new()),
            fail_chown: false,
        }
    }
    /// A fresh recorder (no rules, no calls) operating on `other`'s sysroot; `other` must outlive it.
    pub fn sharing(other: &RecordingHost) -> Self {
        Self {
            root: other.root.clone(),
            _tmp: None,
            is_root: other.is_root,
            rules: Vec::new(),
            once: RefCell::new(Vec::new()),
            spawn_fail: Vec::new(),
            calls: RefCell::new(Vec::new()),
            chowns: RefCell::new(Vec::new()),
            fail_chown: false,
        }
    }
    /// A fresh recorder (no rules, no calls) operating on an existing directory; does not own it.
    pub fn with_root(root: &std::path::Path) -> Self {
        Self {
            root: root.to_path_buf(),
            _tmp: None,
            is_root: true,
            rules: Vec::new(),
            once: RefCell::new(Vec::new()),
            spawn_fail: Vec::new(),
            calls: RefCell::new(Vec::new()),
            chowns: RefCell::new(Vec::new()),
            fail_chown: false,
        }
    }
    /// Makes every `chown` return an error.
    pub fn fail_chown(mut self) -> Self {
        self.fail_chown = true;
        self
    }
    pub fn respond(mut self, prefix: &str, status: i32, stdout: &str, stderr: &str) -> Self {
        self.rules.push((
            prefix.to_string(),
            crate::host::CmdOutput {
                status,
                stdout: stdout.into(),
                stderr: stderr.into(),
            },
        ));
        self
    }
    /// Like `respond`, but consumed on first match and checked before persistent rules.
    pub fn respond_once(self, prefix: &str, status: i32, stdout: &str, stderr: &str) -> Self {
        self.once.borrow_mut().push((
            prefix.to_string(),
            crate::host::CmdOutput {
                status,
                stdout: stdout.into(),
                stderr: stderr.into(),
            },
        ));
        self
    }
    /// Makes `run`, `run_streaming` and `run_interactive` fail to spawn commands matching `prefix`.
    pub fn fail_spawn(mut self, prefix: &str) -> Self {
        self.spawn_fail.push(prefix.to_string());
        self
    }
    fn check_spawn(&self, cmd: &crate::host::Cmd) -> anyhow::Result<()> {
        let line = cmd.to_string();
        if self.spawn_fail.iter().any(|p| line.starts_with(p.as_str())) {
            anyhow::bail!("spawn {}: injected failure", cmd.program);
        }
        Ok(())
    }
    pub fn calls(&self) -> Vec<crate::host::Cmd> {
        self.calls.borrow().clone()
    }
    pub fn chowns(&self) -> Vec<(std::path::PathBuf, u32, u32)> {
        self.chowns.borrow().clone()
    }
    fn lookup(&self, cmd: &crate::host::Cmd) -> crate::host::CmdOutput {
        let line = cmd.to_string();
        {
            let mut once = self.once.borrow_mut();
            if let Some(i) = once.iter().position(|(p, _)| line.starts_with(p.as_str())) {
                return once.remove(i).1;
            }
        }
        self.rules
            .iter()
            .find(|(p, _)| line.starts_with(p.as_str()))
            .map(|(_, o)| o.clone())
            .unwrap_or_else(|| default_output(&line))
    }
}

/// Unscripted lookups answer as a stock host would: nginx runs as `nginx:nginx` (gid 991, as in
/// the seeded /etc/group), so `check_worker_group` passes unless a test scripts otherwise.
fn default_output(line: &str) -> crate::host::CmdOutput {
    let stdout = match line {
        "getent group nginx" => "nginx:x:991:\n",
        "id -g nginx" | "id -G nginx" => "991\n",
        _ => "",
    };
    crate::host::CmdOutput {
        status: 0,
        stdout: stdout.into(),
        stderr: Vec::new(),
    }
}

impl crate::host::Host for RecordingHost {
    fn run(&self, cmd: &crate::host::Cmd) -> anyhow::Result<crate::host::CmdOutput> {
        self.calls.borrow_mut().push(cmd.clone());
        self.check_spawn(cmd)?;
        Ok(self.lookup(cmd))
    }
    fn run_interactive(&self, cmd: &crate::host::Cmd) -> anyhow::Result<i32> {
        self.calls.borrow_mut().push(cmd.clone());
        self.check_spawn(cmd)?;
        Ok(self.lookup(cmd).status)
    }
    fn fchown(
        &self,
        _file: &std::fs::File,
        path: &std::path::Path,
        uid: u32,
        gid: u32,
    ) -> anyhow::Result<()> {
        self.chown(path, uid, gid)
    }
    fn run_streaming(
        &self,
        cmd: &crate::host::Cmd,
        stdin: Option<&mut (dyn std::io::Read + Send)>,
        stdout: &mut dyn std::io::Write,
    ) -> anyhow::Result<crate::host::CmdOutput> {
        let mut recorded = cmd.clone();
        if let Some(r) = stdin {
            let mut buf = Vec::new();
            r.read_to_end(&mut buf)?;
            recorded.stdin = Some(buf);
        }
        self.calls.borrow_mut().push(recorded);
        self.check_spawn(cmd)?;
        let mut out = self.lookup(cmd);
        stdout.write_all(&out.stdout)?;
        out.stdout.clear();
        Ok(out)
    }
    fn chown(&self, path: &std::path::Path, uid: u32, gid: u32) -> anyhow::Result<()> {
        if self.fail_chown {
            anyhow::bail!("chown {}: injected failure", path.display());
        }
        self.chowns
            .borrow_mut()
            .push((path.to_path_buf(), uid, gid));
        Ok(())
    }
    fn lchown(&self, path: &std::path::Path, uid: u32, gid: u32) -> anyhow::Result<()> {
        self.chown(path, uid, gid)
    }
    fn chown_tree_nofollow(
        &self,
        root: &std::path::Path,
        uid: u32,
        gid: u32,
    ) -> anyhow::Result<u64> {
        self.calls
            .borrow_mut()
            .push(crate::host::Cmd::new("chown_tree").args([
                root.display().to_string(),
                uid.to_string(),
                gid.to_string(),
            ]));
        Ok(0)
    }
    fn owner(&self, path: &std::path::Path) -> anyhow::Result<(u32, u32)> {
        use std::os::unix::fs::MetadataExt;
        if let Some((_, u, g)) = self
            .chowns
            .borrow()
            .iter()
            .rev()
            .find(|(p, _, _)| p == path)
        {
            return Ok((*u, *g));
        }
        let m = std::fs::metadata(path)?;
        Ok((m.uid(), m.gid()))
    }
    fn is_root(&self) -> bool {
        self.is_root
    }
    fn sysroot(&self) -> &std::path::Path {
        &self.root
    }
}

/// For tests that only hold for a non-root runner: prints a notice and returns true under root.
pub fn skip_if_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    let root = unsafe { libc::geteuid() } == 0;
    if root {
        eprintln!("skipped: assumes non-root runner");
    }
    root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{Cmd, Host};

    #[test]
    fn respond_once_is_consumed_then_falls_back() {
        let h = RecordingHost::new(true)
            .respond("nginx -t", 0, "", "")
            .respond_once("nginx -t", 1, "", "bad");
        assert_eq!(h.run(&Cmd::new("nginx").arg("-t")).unwrap().status, 1);
        assert_eq!(h.run(&Cmd::new("nginx").arg("-t")).unwrap().status, 0);
        assert_eq!(h.calls().len(), 2);
    }

    #[test]
    fn fail_spawn_errors_after_recording() {
        let h = RecordingHost::new(true).fail_spawn("podman run");
        let e = h.run(&Cmd::new("podman").args(["run", "x"])).unwrap_err();
        assert!(format!("{e}").contains("injected failure"));
        assert!(
            h.run_interactive(&Cmd::new("podman").args(["run", "y"]))
                .is_err()
        );
        assert_eq!(h.calls().len(), 2);
        assert!(h.run(&Cmd::new("podman").args(["ps"])).is_ok());
    }

    #[test]
    fn run_interactive_records_and_returns_status() {
        let h = RecordingHost::new(true).respond("podman run", 3, "", "");
        assert_eq!(
            h.run_interactive(&Cmd::new("podman").arg("run")).unwrap(),
            3
        );
        assert_eq!(h.calls()[0].to_string(), "podman run");
    }

    #[test]
    fn fchown_records_path_and_owner_sees_it() {
        let h = RecordingHost::new(true);
        let d = h.sysroot().join("d");
        std::fs::create_dir(&d).unwrap();
        let f = std::fs::File::open(&d).unwrap();
        h.fchown(&f, &d, 7, 8).unwrap();
        assert_eq!(h.chowns(), vec![(d.clone(), 7, 8)]);
        assert_eq!(h.owner(&d).unwrap(), (7, 8));
    }
}
