//! Host MariaDB: per-site database/user, dumps and restores.

use std::io::Write;
use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::config::GlobalConfig;
use crate::host::{Cmd, Host, run_ok};

pub fn db_name(site: &str) -> String {
    format!("wp_{}", site.replace('-', "_"))
}

pub fn db_user(site: &str) -> String {
    format!("iwp_{}", site.replace('-', "_"))
}

/// The database and user a site's data lives under. Identifiers are validated wherever they
/// are used (`ensure_database`, `dump`, `restore`), so a hand-built value cannot inject SQL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbIdent {
    pub name: String,
    pub user: String,
}

impl DbIdent {
    /// The default wp_/iwp_ mapping for a site name.
    pub fn from_site(site: &crate::config::Site) -> Result<Self> {
        let d = Self::for_site(&site.name)?;
        let id = Self {
            name: site.database.name.clone().unwrap_or(d.name),
            user: site.database.user.clone().unwrap_or(d.user),
        };
        id.validate()?;
        Ok(id)
    }

    pub fn for_site(site: &str) -> Result<Self> {
        if !crate::config::validate::valid_site_name(site) {
            bail!("invalid site name {site:?}");
        }
        let id = Self {
            name: db_name(site),
            user: db_user(site),
        };
        id.validate()?;
        Ok(id)
    }

    pub fn validate(&self) -> Result<()> {
        for (what, v) in [("database name", &self.name), ("database user", &self.user)] {
            let ok = (1..=64).contains(&v.len())
                && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
            if !ok {
                bail!("invalid {what} {v:?}: must match ^[A-Za-z0-9_]{{1,64}}$");
            }
        }
        Ok(())
    }
}

pub fn sql_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("''"),
            '\0' => out.push_str("\\0"),
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PodmanNet {
    pub subnet: Ipv4Addr,
    pub prefix: u8,
    pub gateway: Ipv4Addr,
}

impl PodmanNet {
    pub fn host_pattern(&self) -> String {
        let mask = if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(self.prefix))
        };
        let net = Ipv4Addr::from(u32::from(self.subnet) & mask);
        format!("{net}/{}", Ipv4Addr::from(mask))
    }
}

pub fn podman_network(host: &dyn Host, name: &str) -> Result<PodmanNet> {
    let out = run_ok(
        host,
        &Cmd::new("podman").args([
            "network",
            "inspect",
            name,
            "--format",
            "{{range .Subnets}}{{.Subnet}} {{.Gateway}}{{\"\\n\"}}{{end}}",
        ]),
    )?;
    for line in out.lines() {
        let mut it = line.split_whitespace();
        let (Some(cidr), Some(gw)) = (it.next(), it.next()) else {
            continue;
        };
        let Some((addr, prefix)) = cidr.split_once('/') else {
            continue;
        };
        if let (Ok(subnet), Ok(prefix), Ok(gateway)) = (
            addr.parse::<Ipv4Addr>(),
            prefix.parse::<u8>(),
            gw.parse::<Ipv4Addr>(),
        ) && prefix <= 32
        {
            return Ok(PodmanNet {
                subnet,
                prefix,
                gateway,
            });
        }
    }
    bail!("podman network {name} has no IPv4 subnet with a gateway")
}

fn sock_arg(g: &GlobalConfig) -> String {
    format!("--socket={}", g.mariadb_socket.display())
}

pub fn ensure_database(
    host: &dyn Host,
    g: &GlobalConfig,
    id: &DbIdent,
    password: &str,
    net: &PodmanNet,
) -> Result<()> {
    id.validate()?;
    let (db, user) = (&id.name, &id.user);
    let who = format!("{}@{}", sql_str(user), sql_str(&net.host_pattern()));
    let pw = sql_str(password);
    let sql = format!(
        "CREATE DATABASE IF NOT EXISTS `{db}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n\
         CREATE USER IF NOT EXISTS {who} IDENTIFIED BY {pw};\n\
         ALTER USER {who} IDENTIFIED BY {pw};\n\
         GRANT ALL PRIVILEGES ON `{db}`.* TO {who};\n\
         FLUSH PRIVILEGES;\n"
    );
    // mariadb's stderr can echo SQL fragments, including the password, so it is not surfaced.
    let out = host.run(
        &Cmd::new("mariadb")
            .args([sock_arg(g), "--batch".into()])
            .stdin(sql.into_bytes()),
    )?;
    if out.status != 0 {
        bail!(
            "creating database {db} and user {user} failed (mariadb exit {}); see the MariaDB error log",
            out.status
        );
    }
    Ok(())
}

/// Upper bound on the account-existence query.
pub const USER_QUERY_TIMEOUT: Duration = Duration::from_secs(60);

/// Whether the MariaDB account `'<user>'@'<net's host pattern>'` exists (read-only query over
/// the admin socket; values quoted with `sql_str`). stderr is never surfaced.
pub fn user_exists(host: &dyn Host, g: &GlobalConfig, user: &str, net: &PodmanNet) -> Result<bool> {
    let sql = format!(
        "SELECT COUNT(*) FROM mysql.user WHERE User = {} AND Host = {};\n",
        sql_str(user),
        sql_str(&net.host_pattern())
    );
    let out = host.run(
        &Cmd::new("mariadb")
            .args([sock_arg(g), "--batch".into(), "--skip-column-names".into()])
            .stdin(sql.into_bytes())
            .timeout(USER_QUERY_TIMEOUT),
    )?;
    if out.status != 0 {
        bail!(
            "checking whether the MariaDB account {user}@{} exists failed (mariadb exit {})",
            net.host_pattern(),
            out.status
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let n: u64 = text.trim().parse().with_context(|| {
        format!(
            "checking whether the MariaDB account {user}@{} exists: unexpected answer {:?}",
            net.host_pattern(),
            text.trim()
        )
    })?;
    Ok(n > 0)
}

/// Upper bound on a `mariadb-dump` run.
pub const DUMP_TIMEOUT: Duration = Duration::from_secs(2 * 3600);
/// Upper bound on a restore (`mariadb` reading a dump).
pub const RESTORE_TIMEOUT: Duration = Duration::from_secs(4 * 3600);

/// Upper bound on the table-count query.
pub const COUNT_TIMEOUT: Duration = Duration::from_secs(60);

/// How many tables of database `id.name` start with `prefix` (a first deploy that
/// finds WordPress "not installed" only warns when the database holds none of the site's tables).
pub fn count_prefixed_tables(
    host: &dyn Host,
    g: &GlobalConfig,
    id: &DbIdent,
    prefix: &str,
) -> Result<u64> {
    id.validate()?;
    if prefix.is_empty()
        || !prefix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        bail!("invalid table prefix {prefix:?}: must match ^[A-Za-z0-9_]+$");
    }
    let mut pattern = String::new();
    for c in prefix.chars() {
        // `!` is the LIKE escape (ESCAPE '!'), so no backslash handling is involved and
        // NO_BACKSLASH_ESCAPES cannot change the meaning.
        if matches!(c, '!' | '_' | '%') {
            pattern.push('!');
        }
        pattern.push(c);
    }
    pattern.push('%');
    let sql = format!(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = {} AND table_name LIKE {} ESCAPE '!';\n",
        sql_str(&id.name),
        sql_str(&pattern)
    );
    let out = run_ok(
        host,
        &Cmd::new("mariadb")
            .args([sock_arg(g), "--batch".into(), "--skip-column-names".into()])
            .stdin(sql.into_bytes())
            .timeout(COUNT_TIMEOUT),
    )?;
    out.trim().parse::<u64>().with_context(|| {
        format!(
            "counting tables of {}: unexpected answer {:?}",
            id.name,
            out.trim()
        )
    })
}

/// The strings of a PHP-serialized flat array of strings (`a:2:{i:0;s:5:"alice";...}`), as
/// WordPress stores `site_admins`. Lengths are byte counts, so quotes in a value are fine.
pub fn php_serialized_strings(s: &str) -> Vec<String> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(p) = s[i..].find("s:") {
        let start = i + p + 2;
        let digits = b[start..].iter().take_while(|c| c.is_ascii_digit()).count();
        let after = start + digits;
        let len: Option<usize> = s[start..after].parse().ok();
        match len {
            Some(n) if b.get(after..after + 2) == Some(b":\"".as_slice()) => {
                let (from, to) = (after + 2, after + 2 + n);
                match (s.get(from..to), b.get(to)) {
                    (Some(v), Some(b'"')) => {
                        out.push(v.to_string());
                        i = to + 1;
                    }
                    _ => i = after,
                }
            }
            _ => i = start,
        }
    }
    out
}

/// Logins of every account with the administrator role in the site's WordPress tables (on a
/// network: on any of its sites, plus the super admins), sorted. `None`: the database has no
/// `<prefix>users`/`<prefix>usermeta` tables (WordPress is not installed). Read-only, over
/// the admin socket.
pub fn admin_logins(
    host: &dyn Host,
    g: &GlobalConfig,
    id: &DbIdent,
    prefix: &str,
    multisite: bool,
) -> Result<Option<Vec<String>>> {
    id.validate()?;
    if prefix.is_empty()
        || !prefix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        bail!("invalid table prefix {prefix:?}: must match ^[A-Za-z0-9_]+$");
    }
    let query = |sql: String| {
        run_ok(
            host,
            &Cmd::new("mariadb")
                .args([
                    sock_arg(g),
                    "--batch".into(),
                    "--raw".into(),
                    "--skip-column-names".into(),
                    id.name.clone(),
                ])
                .stdin(sql.into_bytes())
                .timeout(COUNT_TIMEOUT),
        )
    };
    let wanted = if multisite { 3 } else { 2 };
    let tables = query(format!(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = {} AND table_name IN ('{prefix}users', '{prefix}usermeta'{});\n",
        sql_str(&id.name),
        if multisite {
            format!(", '{prefix}sitemeta'")
        } else {
            String::new()
        }
    ))?;
    if tables.trim().parse::<u64>().ok() != Some(wanted) {
        return Ok(None);
    }
    // The role is a key of the serialized capabilities array: `s:13:"administrator";b:1;`.
    // Each site of a network has its own `<prefix><n>_capabilities` key.
    let mut logins: Vec<String> = query(format!(
        "SELECT DISTINCT u.user_login FROM `{prefix}users` u JOIN `{prefix}usermeta` m ON m.user_id = u.ID WHERE m.meta_key REGEXP '^{prefix}([0-9]+_)?capabilities$' AND m.meta_value LIKE '%\"administrator\";b:1%';\n"
    ))?
    .lines()
    .filter(|l| !l.is_empty())
    .map(str::to_string)
    .collect();
    if multisite {
        let meta = query(format!(
            "SELECT meta_value FROM `{prefix}sitemeta` WHERE meta_key = 'site_admins';\n"
        ))?;
        logins.extend(php_serialized_strings(&meta));
    }
    logins.sort();
    logins.dedup();
    Ok(Some(logins))
}

pub fn dump(host: &dyn Host, g: &GlobalConfig, id: &DbIdent, dest: &Path) -> Result<()> {
    id.validate()?;
    let dir = dest.parent().context("dump destination has no directory")?;
    let tmp = tempfile::NamedTempFile::new_in(dir)?;
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o600))?;
    let mut gz = flate2::write::GzEncoder::new(tmp.reopen()?, flate2::Compression::default());
    let cmd = Cmd::new("mariadb-dump")
        .args([
            sock_arg(g),
            "--single-transaction".into(),
            "--routines".into(),
            "--triggers".into(),
            "--hex-blob".into(),
            "--default-character-set=utf8mb4".into(),
            id.name.clone(),
        ])
        .timeout(DUMP_TIMEOUT);
    let out = host.run_streaming(&cmd, None, &mut gz)?;
    if out.status != 0 {
        bail!(
            "{cmd}: exit {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    gz.finish()?.sync_all()?;
    host.chown(tmp.path(), 0, 0)?;
    tmp.persist_noclobber(dest).map_err(|e| {
        if e.error.kind() == std::io::ErrorKind::AlreadyExists {
            anyhow::anyhow!("{} already exists; refusing to overwrite", dest.display())
        } else {
            anyhow::Error::new(e.error).context(format!("writing {}", dest.display()))
        }
    })?;
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

const DUMP_HAS_DB_STMT: &str = "dump contains USE/CREATE DATABASE (made with --databases?); re-dump the single database without --databases";

/// Fully decompresses `src` once (verifying the gzip CRC and length) while scanning for
/// statements that would make a restore leave the target database.
pub fn validate_dump_source(src: &Path) -> Result<()> {
    use crate::error::UsageError;
    use std::io::Read;
    let mut gz = flate2::read::MultiGzDecoder::new(
        std::fs::File::open(src).with_context(|| format!("opening {}", src.display()))?,
    );
    let mut buf = vec![0u8; 64 * 1024];
    let mut at_start = true;
    let mut prefix: Vec<u8> = Vec::new();
    let bad = |p: &[u8]| {
        let p = p.to_ascii_uppercase();
        let mut t = p
            .split(|c| c.is_ascii_whitespace())
            .filter(|t| !t.is_empty());
        match (t.next(), t.next()) {
            (Some(b"USE"), Some(_)) => true,
            (Some(first), _) if first.starts_with(b"USE`") => true,
            (Some(b"CREATE"), Some(b"DATABASE" | b"SCHEMA")) => true,
            _ => false,
        }
    };
    loop {
        let n = gz.read(&mut buf).map_err(|e| {
            UsageError(format!(
                "restore source {} is not a complete valid gzip file: {e}",
                src.display()
            ))
        })?;
        if n == 0 {
            break;
        }
        for &b in &buf[..n] {
            if b == b'\n' {
                if bad(&prefix) {
                    return Err(UsageError(DUMP_HAS_DB_STMT.into()).into());
                }
                prefix.clear();
                at_start = true;
            } else if at_start {
                if prefix.is_empty() && b.is_ascii_whitespace() {
                    continue;
                }
                prefix.push(b);
                if prefix.len() >= 32 {
                    if bad(&prefix) {
                        return Err(UsageError(DUMP_HAS_DB_STMT.into()).into());
                    }
                    prefix.clear();
                    at_start = false;
                }
            }
        }
    }
    if bad(&prefix) {
        return Err(UsageError(DUMP_HAS_DB_STMT.into()).into());
    }
    Ok(())
}

pub fn restore(host: &dyn Host, g: &GlobalConfig, id: &DbIdent, src: &Path) -> Result<()> {
    id.validate()?;
    validate_dump_source(src)?;
    let mut gz = flate2::read::MultiGzDecoder::new(
        std::fs::File::open(src).with_context(|| format!("opening {}", src.display()))?,
    );
    let cmd = Cmd::new("mariadb")
        .args([sock_arg(g), "--one-database".into(), id.name.clone()])
        .timeout(RESTORE_TIMEOUT);
    let mut sink = std::io::sink();
    let out = host.run_streaming(&cmd, Some(&mut gz), &mut sink)?;
    if out.status != 0 {
        bail!(
            "{cmd}: exit {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let _ = sink.flush();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GlobalConfig;
    use crate::testutil::{RecordingHost, tmp};
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn concatenated_gzip_members_are_fully_read() {
        use flate2::{Compression, write::GzEncoder};
        use std::io::Write;
        let t = crate::testutil::tmp();
        let p = t.path().join("d.sql.gz");
        let mut bytes = Vec::new();
        for part in ["INSERT INTO a VALUES (1);\n", "USE other;\n"] {
            let mut e = GzEncoder::new(Vec::new(), Compression::fast());
            e.write_all(part.as_bytes()).unwrap();
            bytes.extend(e.finish().unwrap());
        }
        std::fs::write(&p, bytes).unwrap();
        // The second member's USE must be seen.
        let e = validate_dump_source(&p).unwrap_err();
        assert!(format!("{e}").contains("USE/CREATE DATABASE"), "{e}");
    }

    #[test]
    fn ident_from_site_defaults_and_overrides() {
        let s = crate::config::parse_site(include_str!("../../examples/simple.toml")).unwrap();
        let d = DbIdent::from_site(&s).unwrap();
        assert_eq!(d, DbIdent::for_site(&s.name).unwrap());
        let mut s2 = s.clone();
        s2.database.name = Some("legacy_portal".into());
        s2.database.user = Some("iwp_legacy_info".into());
        let d2 = DbIdent::from_site(&s2).unwrap();
        assert_eq!(
            (d2.name.as_str(), d2.user.as_str()),
            ("legacy_portal", "iwp_legacy_info")
        );
    }

    fn id(site: &str) -> DbIdent {
        DbIdent::for_site(site).unwrap()
    }

    fn gz_file(dir: &Path, name: &str, body: &[u8]) -> std::path::PathBuf {
        let p = dir.join(name);
        let mut enc = flate2::write::GzEncoder::new(
            std::fs::File::create(&p).unwrap(),
            flate2::Compression::default(),
        );
        std::io::Write::write_all(&mut enc, body).unwrap();
        enc.finish().unwrap();
        p
    }

    #[test]
    fn names_and_quoting() {
        assert_eq!(db_name("acme-hr"), "wp_acme_hr");
        assert_eq!(db_user("acme-hr"), "iwp_acme_hr");
        assert_eq!(sql_str(r"a'b\c"), r"'a''b\\c'");
        assert_eq!(sql_str("x\0y"), r"'x\0y'");
    }

    #[test]
    fn podman_network_parsing() {
        let h = RecordingHost::new(true).respond(
            "podman network inspect podman",
            0,
            "fd00::/64 fd00::1\n10.88.0.0/16 10.88.0.1\n",
            "",
        );
        let n = podman_network(&h, "podman").unwrap();
        assert_eq!(
            (n.subnet.to_string(), n.prefix, n.gateway.to_string()),
            ("10.88.0.0".into(), 16, "10.88.0.1".into())
        );
        assert_eq!(n.host_pattern(), "10.88.0.0/255.255.0.0");
        let bad = RecordingHost::new(true).respond(
            "podman network inspect",
            0,
            "fd00::/64 fd00::1\n",
            "",
        );
        assert!(podman_network(&bad, "podman").is_err());
    }

    #[test]
    fn ensure_database_sql_via_stdin_only() {
        let h = RecordingHost::new(true);
        let net = PodmanNet {
            subnet: "10.88.0.0".parse().unwrap(),
            prefix: 16,
            gateway: "10.88.0.1".parse().unwrap(),
        };
        let pw = r"p'w\;`x";
        ensure_database(&h, &GlobalConfig::default(), &id("acme-hr"), pw, &net).unwrap();
        let c = &h.calls()[0];
        assert_eq!(
            c.to_string(),
            "mariadb --socket=/var/lib/mysql/mysql.sock --batch"
        );
        let sql = String::from_utf8(c.stdin.clone().unwrap()).unwrap();
        assert!(
            sql.contains("CREATE DATABASE IF NOT EXISTS `wp_acme_hr` CHARACTER SET utf8mb4"),
            "{sql}"
        );
        assert!(
            sql.contains("'iwp_acme_hr'@'10.88.0.0/255.255.0.0' IDENTIFIED BY 'p''w\\\\;`x'"),
            "{sql}"
        );
        assert!(
            sql.contains(
                "GRANT ALL PRIVILEGES ON `wp_acme_hr`.* TO 'iwp_acme_hr'@'10.88.0.0/255.255.0.0'"
            ),
            "{sql}"
        );
        assert!(!c.args.iter().any(|a| a.contains("p'w")));
    }

    #[test]
    fn dump_streams_gzip_to_private_file() {
        let h =
            RecordingHost::new(true).respond("mariadb-dump", 0, "CREATE TABLE t (x int);\n", "");
        let d = tmp();
        let dest = d.path().join("db-1.sql.gz");
        dump(&h, &GlobalConfig::default(), &id("acme"), &dest).unwrap();
        let mut s = String::new();
        flate2::read::MultiGzDecoder::new(std::fs::File::open(&dest).unwrap())
            .read_to_string(&mut s)
            .unwrap();
        assert_eq!(s, "CREATE TABLE t (x int);\n");
        assert_eq!(
            std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(
            h.calls()[0]
                .to_string()
                .ends_with("--hex-blob --default-character-set=utf8mb4 wp_acme")
        );
        assert_eq!(h.calls()[0].timeout, Some(DUMP_TIMEOUT));
        assert_eq!(DUMP_TIMEOUT, std::time::Duration::from_secs(2 * 3600));
        assert_eq!(
            std::fs::read_dir(d.path()).unwrap().count(),
            1,
            "no temp left"
        );
    }

    #[test]
    fn invalid_identifiers_rejected_before_any_command() {
        let h = RecordingHost::new(true);
        let g = GlobalConfig::default();
        let net = PodmanNet {
            subnet: "10.88.0.0".parse().unwrap(),
            prefix: 16,
            gateway: "10.88.0.1".parse().unwrap(),
        };
        let e = DbIdent::for_site("x`; DROP").unwrap_err();
        assert!(format!("{e:#}").contains("invalid site name"), "{e:#}");
        let d = tmp();
        let src = gz_file(d.path(), "i.gz", b"SELECT 1;");
        for bad in [
            DbIdent {
                name: "x`; DROP".into(),
                user: "u".into(),
            },
            DbIdent {
                name: "ok".into(),
                user: "u'; --".into(),
            },
            DbIdent {
                name: "a".repeat(65),
                user: "u".into(),
            },
            DbIdent {
                name: String::new(),
                user: "u".into(),
            },
        ] {
            let errs = [
                ensure_database(&h, &g, &bad, "pw", &net).unwrap_err(),
                dump(&h, &g, &bad, &d.path().join("o.gz")).unwrap_err(),
                restore(&h, &g, &bad, &src).unwrap_err(),
            ];
            for e in errs {
                assert!(format!("{e:#}").contains("invalid database"), "{e:#}");
            }
        }
        assert!(h.calls().is_empty());
        assert_eq!(id("acme-hr").name, "wp_acme_hr");
    }

    #[test]
    fn restore_rejects_truncated_gzip_before_any_command() {
        let h = RecordingHost::new(true);
        let d = tmp();
        let good = gz_file(d.path(), "g.gz", &vec![b'a'; 200_000]);
        let bytes = std::fs::read(&good).unwrap();
        let cut = d.path().join("cut.gz");
        std::fs::write(&cut, &bytes[..bytes.len() - 20]).unwrap();
        let e = restore(&h, &GlobalConfig::default(), &id("acme"), &cut).unwrap_err();
        assert!(
            e.downcast_ref::<crate::error::UsageError>().is_some(),
            "{e:#}"
        );
        assert!(h.calls().is_empty());
    }

    #[test]
    fn restore_rejects_use_and_create_database() {
        let d = tmp();
        for (i, body) in [
            "SELECT 1;
USE `other`;
",
            "  use other;
",
            "CREATE DATABASE /*!32312 IF NOT EXISTS*/ `x`;
",
            "x;
create   database y;",
            "USE x;",
        ]
        .iter()
        .enumerate()
        {
            let h = RecordingHost::new(true);
            let src = gz_file(d.path(), &format!("{i}.gz"), body.as_bytes());
            let e = restore(&h, &GlobalConfig::default(), &id("acme"), &src).unwrap_err();
            assert!(
                e.downcast_ref::<crate::error::UsageError>().is_some()
                    && format!("{e:#}").contains("without --databases"),
                "{body:?}: {e:#}"
            );
            assert!(h.calls().is_empty(), "{body:?}");
        }
        for body in [
            "/*!40101 SET x */;
INSERT INTO `used` VALUES ('USE x');
-- USE y
USER_VAR;
",
            "INSERT INTO t VALUES (1);
CREATE TABLE t2 (x int);
",
        ] {
            let h = RecordingHost::new(true);
            let src = gz_file(d.path(), "ok.gz", body.as_bytes());
            restore(&h, &GlobalConfig::default(), &id("acme"), &src).unwrap();
            assert_eq!(h.calls().len(), 1);
        }
    }

    #[test]
    fn dump_refuses_existing_destination() {
        let h = RecordingHost::new(true).respond("mariadb-dump", 0, "x", "");
        let d = tmp();
        let dest = d.path().join("db.sql.gz");
        std::fs::write(&dest, "precious").unwrap();
        let e = dump(&h, &GlobalConfig::default(), &id("acme"), &dest).unwrap_err();
        assert!(format!("{e:#}").contains("already exists"), "{e:#}");
        assert_eq!(std::fs::read(&dest).unwrap(), b"precious");
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 1, "no temp");
    }

    #[test]
    fn host_pattern_masks_the_subnet() {
        let n = PodmanNet {
            subnet: "10.88.3.7".parse().unwrap(),
            prefix: 16,
            gateway: "10.88.0.1".parse().unwrap(),
        };
        assert_eq!(n.host_pattern(), "10.88.0.0/255.255.0.0");
    }

    #[test]
    fn ensure_database_error_hides_stderr() {
        let h = RecordingHost::new(true).respond(
            "mariadb",
            1,
            "",
            "ERROR near IDENTIFIED BY 'sekrit-pw'",
        );
        let net = PodmanNet {
            subnet: "10.88.0.0".parse().unwrap(),
            prefix: 16,
            gateway: "10.88.0.1".parse().unwrap(),
        };
        let err = ensure_database(&h, &GlobalConfig::default(), &id("acme"), "sekrit-pw", &net)
            .unwrap_err();
        let t = format!("{err:#}");
        assert!(!t.contains("sekrit-pw"), "{t}");
        assert!(t.contains("exit 1"), "{t}");
    }

    #[test]
    fn dump_failure_leaves_no_file() {
        let h = RecordingHost::new(true).respond("mariadb-dump", 2, "partial", "Got error: 1049");
        let d = tmp();
        let dest = d.path().join("db.sql.gz");
        let err = dump(&h, &GlobalConfig::default(), &id("acme"), &dest).unwrap_err();
        assert!(format!("{err:#}").contains("1049"));
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
    }

    #[test]
    fn restore_streams_gunzipped_sql() {
        let d = tmp();
        let src = d.path().join("in.sql.gz");
        let mut enc = flate2::write::GzEncoder::new(
            std::fs::File::create(&src).unwrap(),
            flate2::Compression::default(),
        );
        std::io::Write::write_all(&mut enc, b"INSERT 1;").unwrap();
        enc.finish().unwrap();
        let h = RecordingHost::new(true);
        restore(&h, &GlobalConfig::default(), &id("acme"), &src).unwrap();
        let c = &h.calls()[0];
        assert_eq!(
            c.to_string(),
            "mariadb --socket=/var/lib/mysql/mysql.sock --one-database wp_acme"
        );
        assert_eq!(c.stdin.as_deref(), Some(&b"INSERT 1;"[..]));
        assert_eq!(c.timeout, Some(RESTORE_TIMEOUT));
        assert_eq!(RESTORE_TIMEOUT, std::time::Duration::from_secs(4 * 3600));
    }

    #[test]
    fn serialized_string_arrays() {
        assert_eq!(
            php_serialized_strings(r#"a:2:{i:0;s:5:"alice";i:1;s:5:"ma"ja";}"#),
            vec!["alice", "ma\"ja"]
        );
        assert_eq!(php_serialized_strings("a:0:{}"), Vec::<String>::new());
        // A length that does not fit the text is skipped, not a panic.
        assert_eq!(
            php_serialized_strings(r#"s:99:"x";s:1:"y";s:2:"č";"#),
            vec!["y", "č"]
        );
        assert_eq!(php_serialized_strings("s:"), Vec::<String>::new());
    }

    #[test]
    fn admin_logins_reads_roles_and_super_admins() {
        let g = GlobalConfig::default();
        let h = RecordingHost::new(true)
            .respond_once("mariadb", 0, "3\n", "")
            .respond_once("mariadb", 0, "zoe\nalice\n", "")
            .respond_once(
                "mariadb",
                0,
                "a:2:{i:0;s:5:\"alice\";i:1;s:4:\"root\";}\n",
                "",
            );
        let got = admin_logins(&h, &g, &id("acme"), "wp_", true).unwrap();
        assert_eq!(got, Some(vec!["alice".into(), "root".into(), "zoe".into()]));
        let calls = h.calls();
        assert_eq!(calls.len(), 3);
        for c in &calls {
            assert!(
                c.to_string().ends_with("--skip-column-names wp_acme"),
                "{c}"
            );
        }
        let sql = String::from_utf8(calls[1].stdin.clone().unwrap()).unwrap();
        assert!(
            sql.contains("REGEXP '^wp_([0-9]+_)?capabilities$'"),
            "{sql}"
        );
        assert!(sql.contains("LIKE '%\"administrator\";b:1%'"), "{sql}");
        // No WordPress tables: nothing to list, and no further query.
        let h = RecordingHost::new(true).respond("mariadb", 0, "0\n", "");
        assert_eq!(admin_logins(&h, &g, &id("a"), "wp_", false).unwrap(), None);
        assert_eq!(h.calls().len(), 1);
        let h = RecordingHost::new(true);
        assert!(admin_logins(&h, &g, &id("a"), "wp_`x", false).is_err());
        assert!(h.calls().is_empty());
    }

    #[test]
    fn count_prefixed_tables_escapes_the_like_pattern() {
        let h = RecordingHost::new(true).respond("mariadb", 0, "3\n", "");
        let id = DbIdent {
            name: "legacy_portal".into(),
            user: "iwp_k".into(),
        };
        let n = count_prefixed_tables(&h, &GlobalConfig::default(), &id, "wp_").unwrap();
        assert_eq!(n, 3);
        let c = &h.calls()[0];
        assert_eq!(
            c.to_string(),
            "mariadb --socket=/var/lib/mysql/mysql.sock --batch --skip-column-names"
        );
        assert_eq!(
            String::from_utf8(c.stdin.clone().unwrap()).unwrap(),
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'legacy_portal' AND table_name LIKE 'wp!_%' ESCAPE '!';\n"
        );
        assert_eq!(c.timeout, Some(Duration::from_secs(60)));
        // Prefixes are validated like the site file does; nothing runs for a bad one.
        let h = RecordingHost::new(true);
        assert!(count_prefixed_tables(&h, &GlobalConfig::default(), &id, "wp'").is_err());
        assert!(count_prefixed_tables(&h, &GlobalConfig::default(), &id, "").is_err());
        assert!(h.calls().is_empty());
        // A failing or unparsable answer is an error, not zero.
        let h = RecordingHost::new(true).respond("mariadb", 1, "", "denied");
        assert!(count_prefixed_tables(&h, &GlobalConfig::default(), &id, "wp_").is_err());
        let h = RecordingHost::new(true).respond("mariadb", 0, "x\n", "");
        assert!(count_prefixed_tables(&h, &GlobalConfig::default(), &id, "wp_").is_err());
    }
}
