//! Minimal FastCGI responder client for deploy smoke tests (talks to the site's FPM socket).

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::config::Site;

const VERSION: u8 = 1;
const BEGIN_REQUEST: u8 = 1;
const END_REQUEST: u8 = 3;
const PARAMS: u8 = 4;
const STDIN: u8 = 5;
const STDOUT: u8 = 6;
const STDERR: u8 = 7;
const MAX: usize = 65_535;
/// Upper bound on a buffered response (headers + body); a smoke test never needs more.
const MAX_RESPONSE: usize = 32 << 20;

fn record(kind: u8, content: &[u8]) -> Vec<u8> {
    let pad = (8 - content.len() % 8) % 8;
    let mut out = Vec::with_capacity(8 + content.len() + pad);
    out.extend_from_slice(&[VERSION, kind, 0, 1]);
    out.extend_from_slice(&(content.len() as u16).to_be_bytes());
    out.extend_from_slice(&[pad as u8, 0]);
    out.extend_from_slice(content);
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

fn stream(kind: u8, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in data.chunks(MAX) {
        out.extend(record(kind, chunk));
    }
    out.extend(record(kind, b""));
    out
}

fn nv_len(n: usize, out: &mut Vec<u8>) {
    if n < 128 {
        out.push(n as u8);
    } else {
        out.extend_from_slice(&((n as u32) | 0x8000_0000).to_be_bytes());
    }
}

fn encode_params(params: &[(String, String)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (k, v) in params {
        nv_len(k.len(), &mut out);
        nv_len(v.len(), &mut out);
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(v.as_bytes());
    }
    out
}

#[cfg(test)]
fn decode_params(mut b: &[u8]) -> Vec<(String, String)> {
    fn len(b: &mut &[u8]) -> usize {
        if b[0] & 0x80 == 0 {
            let n = b[0] as usize;
            *b = &b[1..];
            n
        } else {
            let n = (u32::from_be_bytes([b[0], b[1], b[2], b[3]]) & 0x7fff_ffff) as usize;
            *b = &b[4..];
            n
        }
    }
    let mut out = Vec::new();
    while !b.is_empty() {
        let (k, v) = (len(&mut b), len(&mut b));
        out.push((
            String::from_utf8(b[..k].to_vec()).unwrap(),
            String::from_utf8(b[k..k + v].to_vec()).unwrap(),
        ));
        b = &b[k + v..];
    }
    out
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// The `Location` header, if any (case-insensitive name).
    pub fn location(&self) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Location"))
            .map(|(_, v)| v.as_str())
    }

    /// A 301/302 to `/wp-admin/install.php`: WordPress found no installation in its database.
    pub fn redirects_to_install(&self) -> bool {
        if !matches!(self.status, 301 | 302) {
            return false;
        }
        let Some(loc) = self.location() else {
            return false;
        };
        let path = match loc.split_once("://") {
            Some((_, rest)) => rest.find('/').map_or("", |i| &rest[i..]),
            None => loc,
        };
        let path = path.split(['?', '#']).next().unwrap_or("");
        path.ends_with("/wp-admin/install.php")
    }
}

/// Result of a smoke test: problems fail the check, warnings do not.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct SmokeOutcome {
    pub problems: Vec<String>,
    pub warnings: Vec<String>,
}

/// Sends one responder request over `socket` and reads the whole response.
pub fn request(
    socket: &Path,
    params: &[(String, String)],
    body: &[u8],
    timeout: Duration,
) -> Result<Response> {
    let mut s =
        UnixStream::connect(socket).with_context(|| format!("connecting {}", socket.display()))?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    let mut msg = record(BEGIN_REQUEST, &[0, 1, 0, 0, 0, 0, 0, 0]); // role responder, no keep-conn
    msg.extend(stream(PARAMS, &encode_params(params)));
    msg.extend(stream(STDIN, body));
    s.write_all(&msg).context("sending FastCGI request")?;
    let mut out = Vec::new();
    loop {
        let mut h = [0u8; 8];
        s.read_exact(&mut h).context("reading FastCGI response")?;
        let len = u16::from_be_bytes([h[4], h[5]]) as usize;
        let mut c = vec![0u8; len + h[6] as usize];
        s.read_exact(&mut c).context("reading FastCGI response")?;
        c.truncate(len);
        match h[1] {
            STDOUT => {
                if out.len() + c.len() > MAX_RESPONSE {
                    bail!("FastCGI response exceeds {MAX_RESPONSE} bytes");
                }
                out.extend(c)
            }
            STDERR => {}
            END_REQUEST => break,
            other => bail!("unexpected FastCGI record type {other}"),
        }
    }
    // Whichever terminator comes first ends the headers (the body may contain the other).
    let crlf = out
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| (i, 4));
    let lf = out.windows(2).position(|w| w == b"\n\n").map(|i| (i, 2));
    let split = match (crlf, lf) {
        (Some(a), Some(b)) => Some(if a.0 <= b.0 { a } else { b }),
        (a, b) => a.or(b),
    }
    .context("FastCGI response has no header terminator")?;
    let head = String::from_utf8_lossy(&out[..split.0]).into_owned();
    let body = out[split.0 + split.1..].to_vec();
    let mut status = 200;
    let mut headers = Vec::new();
    for line in head.lines() {
        if let Some((k, v)) = line.split_once(':') {
            let (k, v) = (k.trim().to_string(), v.trim().to_string());
            if k.eq_ignore_ascii_case("Status") {
                status = v
                    .split_whitespace()
                    .next()
                    .and_then(|c| c.parse().ok())
                    .unwrap_or(500);
            }
            headers.push((k, v));
        }
    }
    Ok(Response {
        status,
        headers,
        body,
    })
}

const FATAL_MARKERS: &[&str] = &[
    "There has been a critical error",
    "Fatal error</b>",
    "PHP Fatal error",
];

fn params(
    domain: &str,
    method: &str,
    script: &str,
    uri: &str,
    body_len: usize,
) -> Vec<(String, String)> {
    let mut p = vec![
        ("GATEWAY_INTERFACE", "CGI/1.1".to_string()),
        ("SERVER_PROTOCOL", "HTTP/1.1".into()),
        ("REQUEST_METHOD", method.into()),
        ("SCRIPT_FILENAME", format!("/var/www/html{script}")),
        ("SCRIPT_NAME", script.into()),
        ("DOCUMENT_ROOT", "/var/www/html".into()),
        ("REQUEST_URI", uri.into()),
        (
            "QUERY_STRING",
            uri.split_once('?').map(|x| x.1).unwrap_or("").into(),
        ),
        ("HTTP_HOST", domain.into()),
        ("SERVER_NAME", domain.into()),
        ("SERVER_PORT", "443".into()),
        ("HTTPS", "on".into()),
        ("REMOTE_ADDR", "127.0.0.1".into()),
        ("HTTP_USER_AGENT", "iwp-smoke".into()),
    ];
    if method == "POST" {
        p.push(("CONTENT_TYPE", "application/x-www-form-urlencoded".into()));
        p.push(("CONTENT_LENGTH", body_len.to_string()));
    }
    p.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

type Check = (
    &'static str,
    &'static str,
    &'static str,
    &'static [u8],
    &'static [u16],
);

/// `smoke` with an explicit per-request timeout and a cap on the number of requests.
/// `first_deploy`: the site had no release before this deploy, so a redirect to
/// `install.php` only means WordPress is not installed yet and is a warning. Anywhere else it
/// means a wrong database or table prefix and is a problem.
pub(crate) fn smoke_with(
    socket: &Path,
    site: &Site,
    timeout: Duration,
    max: usize,
    first_deploy: bool,
) -> SmokeOutcome {
    let checks: [Check; 3] = [
        ("GET", "/index.php", "/", b"", &[200, 301, 302]),
        (
            "GET",
            "/wp-login.php",
            "/wp-login.php",
            b"",
            &[200, 301, 302],
        ),
        (
            "POST",
            "/wp-admin/admin-ajax.php",
            "/wp-admin/admin-ajax.php",
            b"action=heartbeat",
            &[200, 400],
        ),
    ];
    let mut problems = Vec::new();
    let mut not_installed = false;
    let mut n = 0;
    'outer: for d in &site.domains {
        for (m, script, uri, body, ok) in checks {
            if n == max {
                break 'outer;
            }
            n += 1;
            match request(
                socket,
                &params(d, m, script, uri, body.len()),
                body,
                timeout,
            ) {
                Err(e) => problems.push(format!("{d} {m} {uri}: {e:#}")),
                Ok(r) => {
                    let text = String::from_utf8_lossy(&r.body);
                    if let Some(mark) = FATAL_MARKERS.iter().find(|k| text.contains(*k)) {
                        problems.push(format!(
                            "{d} {m} {uri}: page contains \"{mark}\" (status {})",
                            r.status
                        ));
                    } else if r.redirects_to_install() {
                        if first_deploy {
                            not_installed = true;
                        } else {
                            problems.push(format!(
                                "{d} {m} {uri}: status {} to {}: WordPress finds no installation (wrong database or table prefix?)",
                                r.status,
                                r.location().unwrap_or_default()
                            ));
                        }
                    } else if !ok.contains(&r.status) {
                        problems.push(format!("{d} {m} {uri}: status {}", r.status));
                    }
                }
            }
        }
    }
    let warnings = if not_installed {
        vec![format!(
            "WordPress is not installed yet: run iwp wp {} core install --url=… --title=… --admin_user=… --admin_email=…",
            site.name
        )]
    } else {
        vec![]
    };
    SmokeOutcome { problems, warnings }
}

/// Runs due WP-Cron events by requesting `/wp-cron.php` over the FPM socket as `domain`
/// (nginx answers 404 for that URL, so only this path reaches it). WordPress ends the
/// request before it runs the events, so this reports whether cron was started, not whether
/// each event succeeded; event errors are in the site's journal. `None` means it started.
pub fn cron(socket: &Path, domain: &str, timeout: Duration) -> Option<String> {
    let uri = "/wp-cron.php?doing_wp_cron";
    match request(
        socket,
        &params(domain, "GET", "/wp-cron.php", uri, 0),
        b"",
        timeout,
    ) {
        Err(e) => Some(format!("{domain} {uri}: {e:#}")),
        Ok(r) => {
            let text = String::from_utf8_lossy(&r.body);
            if let Some(mark) = FATAL_MARKERS.iter().find(|k| text.contains(*k)) {
                Some(format!(
                    "{domain} {uri}: page contains \"{mark}\" (status {})",
                    r.status
                ))
            } else if r.status != 200 {
                Some(format!("{domain} {uri}: status {}", r.status))
            } else {
                None
            }
        }
    }
}

/// Smoke-tests every domain of `site` through the FPM socket; no problems means it passed.
pub fn smoke(socket: &Path, site: &Site, first_deploy: bool) -> SmokeOutcome {
    smoke_with(
        socket,
        site,
        Duration::from_secs(30),
        usize::MAX,
        first_deploy,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn read_records(s: &mut UnixStream) -> Vec<(u8, Vec<u8>)> {
        let mut out = Vec::new();
        loop {
            let mut h = [0u8; 8];
            s.read_exact(&mut h).unwrap();
            let len = u16::from_be_bytes([h[4], h[5]]) as usize;
            let mut c = vec![0u8; len + h[6] as usize];
            s.read_exact(&mut c).unwrap();
            c.truncate(len);
            let done = h[1] == STDIN && len == 0;
            out.push((h[1], c));
            if done {
                return out;
            }
        }
    }

    type Server = (
        tempfile::TempDir,
        std::path::PathBuf,
        std::thread::JoinHandle<Vec<(u8, Vec<u8>)>>,
    );

    fn server(reply: &'static [u8]) -> Server {
        let t = crate::testutil::tmp();
        let p = t.path().join("php.sock");
        let l = UnixListener::bind(&p).unwrap();
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let recs = read_records(&mut s);
            s.write_all(&record(STDOUT, reply)).unwrap();
            s.write_all(&record(STDOUT, b"")).unwrap();
            s.write_all(&record(END_REQUEST, &[0; 8])).unwrap();
            recs
        });
        (t, p, h)
    }

    fn site() -> Site {
        crate::config::parse_site(
            "name = \"a\"\ndomains = [\"a.example\"]\nid = 1\n[core]\nwordpress = \"7.1.2\"\nphp = \"8.3\"\n",
        )
        .unwrap()
    }

    #[test]
    fn request_encodes_params_and_parses_status() {
        let (_t, p, h) = server(b"Status: 302 Found\r\nLocation: /x\r\n\r\nbody");
        let params = vec![
            ("SCRIPT_FILENAME".into(), "/var/www/html/index.php".into()),
            ("LONG".into(), "v".repeat(300)),
        ];
        let r = request(&p, &params, b"a=b", Duration::from_secs(5)).unwrap();
        assert_eq!(r.status, 302);
        assert_eq!(r.body, b"body");
        assert!(r.headers.iter().any(|(k, v)| k == "Location" && v == "/x"));
        let recs = h.join().unwrap();
        assert_eq!(recs[0].0, BEGIN_REQUEST);
        let params_bytes: Vec<u8> = recs
            .iter()
            .filter(|r| r.0 == PARAMS)
            .flat_map(|r| r.1.clone())
            .collect();
        assert_eq!(decode_params(&params_bytes), params);
        let stdin: Vec<u8> = recs
            .iter()
            .filter(|r| r.0 == STDIN)
            .flat_map(|r| r.1.clone())
            .collect();
        assert_eq!(stdin, b"a=b");
    }

    #[test]
    fn default_status_is_200_and_fatal_marker_detected() {
        let (_t, p, _h) = server(
            b"Content-Type: text/html\r\n\r\n<p>There has been a critical error on this website.</p>",
        );
        let mut site = site();
        site.domains.truncate(1);
        let problems = smoke_with(&p, &site, Duration::from_secs(5), 1, false).problems;
        assert!(
            problems.iter().any(|m| m.contains("critical error")),
            "{problems:?}"
        );
    }

    #[test]
    fn default_status_is_200() {
        let (_t, p, _h) = server(b"Content-Type: text/html\n\n<p>ok</p>");
        let r = request(&p, &[], b"", Duration::from_secs(5)).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"<p>ok</p>");
    }

    #[test]
    fn header_split_uses_the_first_terminator() {
        let (_t, p, _h) = server(b"Status: 404\nX-A: 1\n\nline\r\n\r\nmore");
        let r = request(&p, &[], b"", Duration::from_secs(5)).unwrap();
        assert_eq!(r.status, 404);
        assert_eq!(r.headers.len(), 2, "{:?}", r.headers);
        assert_eq!(r.body, b"line\r\n\r\nmore");
    }

    #[test]
    fn location_and_install_redirect_detection() {
        let r = |status, loc: &str| Response {
            status,
            headers: vec![("Location".into(), loc.into())],
            body: vec![],
        };
        assert_eq!(r(302, "/x").location(), Some("/x"));
        assert!(r(302, "https://a.example/wp-admin/install.php").redirects_to_install());
        assert!(r(301, "/wp-admin/install.php?step=1").redirects_to_install());
        assert!(!r(200, "/wp-admin/install.php").redirects_to_install());
        assert!(!r(302, "https://a.example/wp-login.php").redirects_to_install());
        assert!(!r(302, "/x/?r=/wp-admin/install.php").redirects_to_install());
    }

    const INSTALL_302: &[u8] =
        b"Status: 302 Found\r\nLocation: https://a.example/wp-admin/install.php\r\n\r\n";

    #[test]
    fn install_redirect_is_a_warning_on_a_first_deploy() {
        let (_t, p, _h) = server(INSTALL_302);
        let o = smoke_with(&p, &site(), Duration::from_secs(5), 1, true);
        assert!(o.problems.is_empty(), "{o:?}");
        assert_eq!(o.warnings.len(), 1, "{o:?}");
        assert!(
            o.warnings[0]
                .starts_with("WordPress is not installed yet: run iwp wp a core install --url="),
            "{o:?}"
        );
    }

    #[test]
    fn install_redirect_is_a_problem_otherwise() {
        let (_t, p, _h) = server(INSTALL_302);
        let o = smoke_with(&p, &site(), Duration::from_secs(5), 1, false);
        assert!(o.warnings.is_empty(), "{o:?}");
        assert_eq!(o.problems.len(), 1, "{o:?}");
        assert!(o.problems[0].contains("/wp-admin/install.php"), "{o:?}");
    }

    #[test]
    fn cron_requests_wp_cron_and_reports_bad_status() {
        let (_t, p, h) = server(b"Content-Type: text/html\r\n\r\n");
        assert_eq!(cron(&p, "a.example", Duration::from_secs(5)), None);
        let recs = h.join().unwrap();
        let bytes: Vec<u8> = recs
            .iter()
            .filter(|(k, _)| *k == PARAMS)
            .flat_map(|(_, c)| c.clone())
            .collect();
        let params = decode_params(&bytes);
        let get = |k: &str| params.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("SCRIPT_FILENAME"), Some("/var/www/html/wp-cron.php"));
        assert_eq!(get("REQUEST_URI"), Some("/wp-cron.php?doing_wp_cron"));
        assert_eq!(get("HTTP_HOST"), Some("a.example"));
        assert_eq!(get("REQUEST_METHOD"), Some("GET"));

        let (_t, p, _h) = server(b"Status: 500 Internal Server Error\r\n\r\n");
        let m = cron(&p, "a.example", Duration::from_secs(5)).unwrap();
        assert!(m.contains("status 500"), "{m}");
        let (_t, p, _h) =
            server(b"\r\n\r\n<p>There has been a critical error on this website.</p>");
        let m = cron(&p, "a.example", Duration::from_secs(5)).unwrap();
        assert!(m.contains("critical error"), "{m}");
        let gone = crate::testutil::tmp();
        let m = cron(
            &gone.path().join("php.sock"),
            "a.example",
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(m.contains("connecting"), "{m}");
    }

    #[test]
    fn unreachable_socket_is_a_problem_not_a_panic() {
        let t = crate::testutil::tmp();
        let p = smoke(&t.path().join("nope.sock"), &site(), false).problems;
        assert_eq!(p.len(), 3, "{p:?}");
    }
}
