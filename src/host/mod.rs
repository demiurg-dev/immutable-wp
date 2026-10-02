//! The only gateway to host side effects: processes, ownership and system paths.

pub mod alert;
pub mod db;
pub mod egress;
pub mod fsx;
pub mod identity;
pub mod image;
pub mod install;
pub mod layout;
pub mod lock;
pub mod nginx;
pub mod secrets;
pub mod selinux;

use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};

#[derive(Clone, PartialEq, Eq)]
pub struct Cmd {
    pub program: String,
    pub args: Vec<String>,
    pub stdin: Option<Vec<u8>>,
    /// Upper bound on the run time (`run`/`run_streaming`); on expiry the child is terminated
    /// and the run fails with "<program> timed out after Ns".
    pub timeout: Option<Duration>,
}

impl Cmd {
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            stdin: None,
            timeout: None,
        }
    }
    pub fn arg(mut self, a: impl Into<String>) -> Self {
        self.args.push(a.into());
        self
    }
    pub fn args<I, S>(mut self, it: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(it.into_iter().map(Into::into));
        self
    }
    pub fn stdin(mut self, bytes: Vec<u8>) -> Self {
        self.stdin = Some(bytes);
        self
    }
    pub fn timeout(mut self, limit: Duration) -> Self {
        self.timeout = Some(limit);
        self
    }
}

impl fmt::Debug for Cmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let stdin = match &self.stdin {
            Some(b) => format!("<{} bytes>", b.len()),
            None => "None".to_string(),
        };
        write!(
            f,
            "Cmd {{ program: {:?}, args: {:?}, stdin: {stdin}",
            self.program, self.args
        )?;
        if let Some(t) = self.timeout {
            write!(f, ", timeout: {}s", t.as_secs())?;
        }
        write!(f, " }}")
    }
}

impl fmt::Display for Cmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.program)?;
        for a in &self.args {
            write!(f, " {a}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CmdOutput {
    pub status: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub trait Host {
    fn run(&self, cmd: &Cmd) -> Result<CmdOutput>;
    fn run_streaming(
        &self,
        cmd: &Cmd,
        stdin: Option<&mut (dyn Read + Send)>,
        stdout: &mut dyn Write,
    ) -> Result<CmdOutput>;
    /// Runs `cmd` with inherited stdin/stdout/stderr and returns its exit code
    /// (128 + signal number when it was killed by a signal). `cmd.stdin` must be `None`.
    fn run_interactive(&self, cmd: &Cmd) -> Result<i32>;
    fn chown(&self, path: &Path, uid: u32, gid: u32) -> Result<()>;
    /// Changes the owner of the open file/directory `file` (no path lookup, so no symlink can
    /// redirect it). `path` names it in errors and test recordings only.
    fn fchown(&self, file: &std::fs::File, path: &Path, uid: u32, gid: u32) -> Result<()>;
    /// Like `chown` but never follows a symlink at `path` (changes the link itself).
    fn lchown(&self, path: &Path, uid: u32, gid: u32) -> Result<()>;
    /// Recursively changes the owner of `root` (which must not be a symlink) and everything
    /// below it without ever following a symlink; returns the number of entries changed.
    fn chown_tree_nofollow(&self, root: &Path, uid: u32, gid: u32) -> Result<u64>;
    /// Current (uid, gid) of `path`, following symlinks.
    fn owner(&self, path: &Path) -> Result<(u32, u32)>;
    fn is_root(&self) -> bool;
    fn sysroot(&self) -> &Path;
}

pub fn sys(host: &dyn Host, abs: impl AsRef<Path>) -> PathBuf {
    let p = abs.as_ref();
    host.sysroot().join(p.strip_prefix("/").unwrap_or(p))
}

pub fn run_ok(host: &dyn Host, cmd: &Cmd) -> Result<String> {
    let out = host.run(cmd)?;
    if out.status != 0 {
        bail!(
            "{cmd}: exit {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn status_code(s: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    s.code()
        .unwrap_or_else(|| s.signal().map_or(-1, |n| 128 + n))
}

fn timed_out(cmd: &Cmd) -> anyhow::Error {
    timed_out_with(cmd, &[])
}

/// How much captured stderr a timeout error carries.
const STDERR_TAIL: usize = 2048;

fn timed_out_with(cmd: &Cmd, stderr: &[u8]) -> anyhow::Error {
    let secs = cmd.timeout.map_or(0.0, |t| t.as_secs_f64());
    let tail = &stderr[stderr.len().saturating_sub(STDERR_TAIL)..];
    let tail = String::from_utf8_lossy(tail);
    let tail = tail.trim();
    if tail.is_empty() {
        anyhow::anyhow!("{} timed out after {secs}s", cmd.program)
    } else {
        anyhow::anyhow!(
            "{} timed out after {secs}s; stderr tail: {tail}",
            cmd.program
        )
    }
}

/// Blocks until child `pid` has exited, without reaping it (so its pid stays reserved).
fn wait_exited(pid: libc::pid_t) {
    loop {
        // SAFETY: waitid only writes into the zeroed siginfo we pass; WNOWAIT leaves the child
        // waitable, so the later `Child::wait` still reaps it.
        let r = unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        if r == 0 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return;
        }
    }
}

/// Terminates a child that outlives its time limit: SIGTERM first (podman forwards it to the
/// container), SIGKILL after `grace`. It only signals while the child is unreaped: the owner
/// calls `disarm` after `wait_exited` and before reaping, so the pid cannot have been reused.
struct Watchdog {
    done: Arc<(Mutex<bool>, Condvar)>,
    fired: Arc<std::sync::atomic::AtomicBool>,
    thread: std::thread::JoinHandle<()>,
}

impl Watchdog {
    fn arm(pid: libc::pid_t, limit: Duration, grace: Duration) -> Self {
        use std::sync::atomic::Ordering;
        let done = Arc::new((Mutex::new(false), Condvar::new()));
        let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (d, f) = (done.clone(), fired.clone());
        let thread = std::thread::spawn(move || {
            let (m, cv) = &*d;
            let g = m.lock().unwrap_or_else(|e| e.into_inner());
            let (g, _) = cv
                .wait_timeout_while(g, limit, |done| !*done)
                .unwrap_or_else(|e| e.into_inner());
            if *g {
                return;
            }
            f.store(true, Ordering::SeqCst);
            // SAFETY: plain kill(2) on our own child, which is not reaped while we hold `m`
            // with `done == false`.
            unsafe { libc::kill(pid, libc::SIGTERM) };
            let (g, _) = cv
                .wait_timeout_while(g, grace, |done| !*done)
                .unwrap_or_else(|e| e.into_inner());
            if !*g {
                // SAFETY: as above.
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
        });
        Self {
            done,
            fired,
            thread,
        }
    }

    /// Stops the watchdog; true when it fired. Call after the child exited, before reaping it.
    fn disarm(self) -> bool {
        let (m, cv) = &*self.done;
        *m.lock().unwrap_or_else(|e| e.into_inner()) = true;
        cv.notify_all();
        let _ = self.thread.join();
        self.fired.load(std::sync::atomic::Ordering::SeqCst)
    }
}

pub struct SystemHost {
    root: PathBuf,
    /// Time between SIGTERM and SIGKILL when a command outlives its timeout.
    grace: Duration,
}

impl SystemHost {
    pub fn new() -> Self {
        Self {
            root: PathBuf::from("/"),
            grace: Duration::from_secs(10),
        }
    }
}

impl Default for SystemHost {
    fn default() -> Self {
        Self::new()
    }
}

impl Host for SystemHost {
    fn run_interactive(&self, cmd: &Cmd) -> Result<i32> {
        use std::os::unix::process::ExitStatusExt;
        anyhow::ensure!(
            cmd.stdin.is_none(),
            "run_interactive does not take stdin bytes"
        );
        let st = Command::new(&cmd.program)
            .args(&cmd.args)
            .status()
            .with_context(|| format!("spawn {}", cmd.program))?;
        Ok(st.code().unwrap_or_else(|| 128 + st.signal().unwrap_or(0)))
    }

    fn fchown(&self, file: &std::fs::File, path: &Path, uid: u32, gid: u32) -> Result<()> {
        std::os::unix::fs::fchown(file, Some(uid), Some(gid))
            .with_context(|| format!("chown {}", path.display()))
    }

    fn run(&self, cmd: &Cmd) -> Result<CmdOutput> {
        let mut child = Command::new(&cmd.program)
            .args(&cmd.args)
            .stdin(if cmd.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("starting {} (is it installed?)", cmd.program))?;
        let pid = child.id() as libc::pid_t;
        let watchdog = cmd.timeout.map(|t| Watchdog::arm(pid, t, self.grace));
        // Feed stdin from a thread so a large input can't deadlock against a full stdout pipe.
        let writer = cmd.stdin.clone().map(|input| {
            let mut si = child.stdin.take().expect("piped");
            std::thread::spawn(move || si.write_all(&input))
        });
        let drain = |mut r: Box<dyn Read + Send>, sink: Arc<Mutex<Vec<u8>>>| {
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                while let Ok(n) = r.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    sink.lock().unwrap().extend_from_slice(&buf[..n]);
                }
            })
        };
        let out_buf = Arc::new(Mutex::new(Vec::new()));
        let err_buf = Arc::new(Mutex::new(Vec::new()));
        let out_t = drain(
            Box::new(child.stdout.take().expect("piped")),
            out_buf.clone(),
        );
        let err_t = drain(
            Box::new(child.stderr.take().expect("piped")),
            err_buf.clone(),
        );
        wait_exited(pid);
        let fired = watchdog.is_some_and(Watchdog::disarm);
        let status = child.wait()?;
        if fired {
            // The pipe readers are left behind: a grandchild may still hold the pipes open.
            // Give the stderr reader a moment to drain what the killed child wrote.
            let until = std::time::Instant::now() + Duration::from_millis(500);
            while !err_t.is_finished() && std::time::Instant::now() < until {
                std::thread::sleep(Duration::from_millis(10));
            }
            let seen = err_buf.lock().unwrap().clone();
            return Err(timed_out_with(cmd, &seen));
        }
        if let Some(w) = writer {
            let _ = w.join();
        }
        Ok(CmdOutput {
            status: status_code(status),
            stdout: {
                let _ = out_t.join();
                std::mem::take(&mut *out_buf.lock().unwrap())
            },
            stderr: {
                let _ = err_t.join();
                std::mem::take(&mut *err_buf.lock().unwrap())
            },
        })
    }

    fn run_streaming(
        &self,
        cmd: &Cmd,
        stdin: Option<&mut (dyn Read + Send)>,
        stdout: &mut dyn Write,
    ) -> Result<CmdOutput> {
        let mut child = Command::new(&cmd.program)
            .args(&cmd.args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("starting {} (is it installed?)", cmd.program))?;
        let mut err_pipe = child.stderr.take().expect("piped");
        let err_thread = std::thread::spawn(move || {
            let mut e = Vec::new();
            let _ = err_pipe.read_to_end(&mut e);
            e
        });
        let mut out_pipe = child.stdout.take().expect("piped");
        let pid = child.id() as libc::pid_t;
        let watchdog = cmd.timeout.map(|t| Watchdog::arm(pid, t, self.grace));
        let mut copy_err: Option<anyhow::Error> = None;
        let mut in_err: Option<anyhow::Error> = None;
        std::thread::scope(|s| {
            let in_thread = stdin.map(|input| {
                let mut si = child.stdin.take().expect("piped");
                s.spawn(move || {
                    let r = std::io::copy(input, &mut si);
                    if let Err(e) = &r
                        && e.kind() != std::io::ErrorKind::BrokenPipe
                    {
                        // Kill the child BEFORE `si` drops (closing its stdin), so it cannot
                        // see EOF and commit a truncated stream. The child is not yet reaped,
                        // so the pid cannot have been reused.
                        // SAFETY: plain kill(2) on our own unreaped child.
                        unsafe { libc::kill(pid, libc::SIGKILL) };
                    }
                    r
                })
            });
            let res = std::io::copy(&mut out_pipe, stdout).and_then(|_| stdout.flush());
            if let Err(e) = res {
                copy_err = Some(anyhow::Error::new(e).context("streaming stdout"));
                drop(out_pipe);
                let _ = child.kill();
            }
            if let Some(t) = in_thread {
                match t.join() {
                    Ok(Err(e)) if e.kind() != std::io::ErrorKind::BrokenPipe => {
                        in_err = Some(anyhow::Error::new(e).context("reading stdin"));
                    }
                    _ => {}
                }
            }
        });
        wait_exited(pid);
        let fired = watchdog.is_some_and(Watchdog::disarm);
        let waited = child.wait();
        if fired {
            return Err(timed_out(cmd));
        }
        let stderr = err_thread.join().unwrap_or_default();
        if let Some(e) = copy_err.or(in_err) {
            return Err(e);
        }
        let status = waited?;
        Ok(CmdOutput {
            status: status_code(status),
            stdout: Vec::new(),
            stderr,
        })
    }

    fn chown(&self, path: &Path, uid: u32, gid: u32) -> Result<()> {
        std::os::unix::fs::chown(path, Some(uid), Some(gid))
            .with_context(|| format!("chown {}", path.display()))
    }

    fn lchown(&self, path: &Path, uid: u32, gid: u32) -> Result<()> {
        std::os::unix::fs::lchown(path, Some(uid), Some(gid))
            .with_context(|| format!("lchown {}", path.display()))
    }

    fn chown_tree_nofollow(&self, root: &Path, uid: u32, gid: u32) -> Result<u64> {
        fsx::chown_tree_real(root, uid, gid)
    }

    fn owner(&self, path: &Path) -> Result<(u32, u32)> {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
        Ok((m.uid(), m.gid()))
    }

    fn is_root(&self) -> bool {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }

    fn sysroot(&self) -> &Path {
        &self.root
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn cmd_debug_never_prints_stdin() {
        let d = format!("{:?}", Cmd::new("x").stdin(b"hunter2".to_vec()));
        assert!(!d.contains("hunter2"), "{d}");
        assert!(d.contains("7 bytes"), "{d}");
        assert!(format!("{:?}", Cmd::new("x")).contains("stdin: None"));
    }

    use super::*;
    use crate::testutil::RecordingHost;

    #[test]
    fn display_never_shows_stdin() {
        let c = Cmd::new("podman")
            .args(["secret", "create", "x", "-"])
            .stdin(b"s3cret".to_vec());
        assert_eq!(c.to_string(), "podman secret create x -");
    }

    #[test]
    fn run_ok_reports_status_and_stderr_without_stdin() {
        let h = RecordingHost::new(true).respond("mariadb", 1, "", "ERROR 1045 access denied");
        let err = run_ok(
            &h,
            &Cmd::new("mariadb")
                .arg("--batch")
                .stdin(b"PASSWORD 'hunter2'".to_vec()),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("mariadb --batch: exit 1: ERROR 1045"), "{msg}");
        assert!(!msg.contains("hunter2"));
    }

    #[test]
    fn sys_maps_under_sysroot() {
        let h = RecordingHost::new(true);
        assert_eq!(
            sys(&h, "/etc/nginx/iwp/x.conf"),
            h.sysroot().join("etc/nginx/iwp/x.conf")
        );
    }

    #[test]
    fn system_host_runs_and_streams() {
        let _spawn = crate::testutil::spawn_guard();
        let h = SystemHost::new();
        let out = h
            .run(
                &Cmd::new("sh")
                    .args(["-c", "cat; echo err >&2; exit 3"])
                    .stdin(b"in".to_vec()),
            )
            .unwrap();
        assert_eq!(
            (out.status, out.stdout.as_slice(), out.stderr.as_slice()),
            (3, &b"in"[..], &b"err\n"[..])
        );
        let mut sink = Vec::new();
        let mut input: &[u8] = b"stream";
        let out = h
            .run_streaming(&Cmd::new("cat"), Some(&mut input), &mut sink)
            .unwrap();
        assert_eq!((out.status, sink.as_slice()), (0, &b"stream"[..]));
    }

    #[test]
    fn run_kills_a_command_that_outlives_its_timeout() {
        let _spawn = crate::testutil::spawn_guard();
        let t0 = std::time::Instant::now();
        let e = SystemHost::new()
            .run(
                &Cmd::new("sleep")
                    .arg("30")
                    .timeout(Duration::from_millis(300)),
            )
            .unwrap_err();
        assert_eq!(format!("{e:#}"), "sleep timed out after 0.3s");
        assert!(t0.elapsed() < Duration::from_secs(10), "{:?}", t0.elapsed());
        // Within the limit nothing changes.
        let out = SystemHost::new()
            .run(
                &Cmd::new("sh")
                    .args(["-c", "cat; exit 4"])
                    .stdin(b"ok".to_vec())
                    .timeout(Duration::from_secs(30)),
            )
            .unwrap();
        assert_eq!((out.status, out.stdout.as_slice()), (4, &b"ok"[..]));
    }

    #[test]
    fn run_timeout_error_carries_the_stderr_tail() {
        let _spawn = crate::testutil::spawn_guard();
        let e = SystemHost::new()
            .run(
                &Cmd::new("sh")
                    .args(["-c", "echo partial >&2; sleep 5"])
                    .stdin(b"SECRET-STDIN".to_vec())
                    .timeout(Duration::from_secs(1)),
            )
            .unwrap_err();
        let m = format!("{e:#}");
        assert!(m.starts_with("sh timed out after 1s"), "{m}");
        assert!(m.contains("partial"), "{m}");
        assert!(!m.contains("SECRET-STDIN"), "{m}");
        // Only the last 2 KiB are kept.
        let e = SystemHost::new()
            .run(
                &Cmd::new("sh")
                    .args([
                        "-c",
                        "head -c 5000 /dev/zero | tr '\\0' a >&2; echo END >&2; sleep 5",
                    ])
                    .timeout(Duration::from_secs(1)),
            )
            .unwrap_err();
        let m = format!("{e:#}");
        assert!(m.contains("END") && m.len() < 2300, "{}", m.len());
    }

    #[test]
    fn run_streaming_kills_a_command_that_outlives_its_timeout() {
        let _spawn = crate::testutil::spawn_guard();
        let t0 = std::time::Instant::now();
        let mut sink = Vec::new();
        let mut input: &[u8] = b"x";
        let e = SystemHost::new()
            .run_streaming(
                &Cmd::new("sleep")
                    .arg("30")
                    .timeout(Duration::from_millis(300)),
                Some(&mut input),
                &mut sink,
            )
            .unwrap_err();
        assert_eq!(format!("{e:#}"), "sleep timed out after 0.3s");
        assert!(t0.elapsed() < Duration::from_secs(10), "{:?}", t0.elapsed());
        let mut input: &[u8] = b"stream";
        let out = SystemHost::new()
            .run_streaming(
                &Cmd::new("cat").timeout(Duration::from_secs(30)),
                Some(&mut input),
                &mut sink,
            )
            .unwrap();
        assert_eq!((out.status, sink.as_slice()), (0, &b"stream"[..]));
    }

    #[test]
    fn timeout_escalates_to_sigkill_when_sigterm_is_ignored() {
        let _spawn = crate::testutil::spawn_guard();
        let h = SystemHost {
            root: PathBuf::from("/"),
            grace: Duration::from_millis(200),
        };
        let t0 = std::time::Instant::now();
        let e = h
            .run(
                &Cmd::new("sh")
                    .args(["-c", "trap '' TERM; while :; do :; done"])
                    .timeout(Duration::from_millis(200)),
            )
            .unwrap_err();
        assert!(format!("{e:#}").contains("timed out"), "{e:#}");
        assert!(t0.elapsed() < Duration::from_secs(10), "{:?}", t0.elapsed());
    }

    #[test]
    fn timeout_shows_in_debug_but_not_display() {
        let c = Cmd::new("mariadb-dump").timeout(Duration::from_secs(7200));
        assert_eq!(c.to_string(), "mariadb-dump");
        assert!(format!("{c:?}").contains("timeout: 7200s"), "{c:?}");
    }

    struct FailAfter(usize);
    impl Write for FailAfter {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            if self.0 == 0 {
                return Err(std::io::Error::other("sink broke"));
            }
            let n = b.len().min(self.0);
            self.0 -= n;
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn writer_failure_does_not_hang() {
        let _spawn = crate::testutil::spawn_guard();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut input = std::io::Cursor::new(vec![b'x'; 1 << 20]);
            let mut sink = FailAfter(1000);
            let r = SystemHost::new().run_streaming(&Cmd::new("cat"), Some(&mut input), &mut sink);
            let _ = tx.send(r.map(|_| ()).map_err(|e| format!("{e:#}")));
        });
        let r = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("run_streaming hung");
        assert!(r.unwrap_err().contains("streaming stdout"));
    }

    #[test]
    fn run_interactive_returns_exit_code() {
        let _g = crate::testutil::spawn_guard();
        let h = SystemHost::new();
        assert_eq!(
            h.run_interactive(&Cmd::new("sh").args(["-c", "exit 7"]))
                .unwrap(),
            7
        );
        assert_eq!(
            h.run_interactive(&Cmd::new("sh").args(["-c", "kill -TERM $$"]))
                .unwrap(),
            128 + 15
        );
        assert!(
            h.run_interactive(&Cmd::new("/nonexistent/iwp-test"))
                .is_err()
        );
    }

    struct BadReader(bool);
    impl Read for BadReader {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            if self.0 {
                return Err(std::io::Error::other("decompressor exploded"));
            }
            self.0 = true;
            b[..3].copy_from_slice(b"abc");
            Ok(3)
        }
    }

    #[test]
    fn reader_failure_kills_child_before_stdin_closes() {
        let _spawn = crate::testutil::spawn_guard();
        let d = crate::testutil::tmp();
        let marker = d.path().join("committed");
        let script = format!("cat >/dev/null; touch {}", marker.display());
        for _ in 0..20 {
            let mut sink = Vec::new();
            let err = SystemHost::new()
                .run_streaming(
                    &Cmd::new("sh").args(["-c", script.as_str()]),
                    Some(&mut BadReader(false)),
                    &mut sink,
                )
                .unwrap_err();
            assert!(format!("{err:#}").contains("decompressor exploded"));
            std::thread::sleep(std::time::Duration::from_millis(20));
            assert!(!marker.exists(), "child committed a partial stream");
        }
    }

    #[test]
    fn reader_failure_is_an_error() {
        let _spawn = crate::testutil::spawn_guard();
        let mut sink = Vec::new();
        let err = SystemHost::new()
            .run_streaming(&Cmd::new("cat"), Some(&mut BadReader(false)), &mut sink)
            .unwrap_err();
        assert!(format!("{err:#}").contains("decompressor exploded"));
    }
}
