//! Pure parser for an existing site's `wp-config.php` (DB settings, prefix, salts,
//! multisite, carried-over simple constants). Secrets never reach errors or `Debug`.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use anyhow::{Result, bail};
use regex::Regex;

use crate::config::validate::{RESERVED_CONSTANTS, valid_multisite_path};
use crate::config::{ConstValue, Multisite};
use crate::host::secrets::{SALT_KEYS, import_salts, strip_php_comments};

#[derive(Clone)]
pub struct OldConfig {
    pub db_name: String,
    pub db_user: String,
    pub db_password: String,
    pub db_host: String,
    pub table_prefix: String,
    pub db_charset: Option<String>,
    pub db_collate: Option<String>,
    pub salts: BTreeMap<String, String>,
    /// MULTISITE with its DOMAIN/PATH/SITE_ID/BLOG_ID_CURRENT_SITE.
    pub multisite: Option<Multisite>,
    pub constants: BTreeMap<String, ConstValue>,
    /// Names (never values) of defines that were skipped.
    pub not_carried: Vec<String>,
    /// Report warnings (never containing secrets).
    pub warnings: Vec<String>,
}

impl std::fmt::Debug for OldConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OldConfig")
            .field("db_name", &self.db_name)
            .field("db_user", &self.db_user)
            .field("db_password", &"<redacted>")
            .field("db_host", &self.db_host)
            .field("table_prefix", &self.table_prefix)
            .field("db_charset", &self.db_charset)
            .field("db_collate", &self.db_collate)
            .field("salts", &format_args!("<{} redacted>", self.salts.len()))
            .field("multisite", &self.multisite)
            .field("constants", &self.constants)
            .field("not_carried", &self.not_carried)
            .field("warnings", &self.warnings)
            .finish()
    }
}

static PREFIX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_]+$").unwrap());
static COLLATE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z0-9_]*$").unwrap());
static CONST_NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Z_][A-Z0-9_]*$").unwrap());
static DEFINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i:\bdefine)\s*\(\s*['"]([A-Za-z0-9_]+)['"]\s*,\s*"#).unwrap());
static CREDENTIAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(PASS|PASSWORD|SECRET|KEY|TOKEN|SALT|AUTH)").unwrap());
static INT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(0|-?[1-9][0-9]*)$").unwrap());
static TABLE_PREFIX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$table_prefix\s*=\s*").unwrap());

const MULTISITE_NAMES: &[&str] = &[
    "MULTISITE",
    "SUBDOMAIN_INSTALL",
    "DOMAIN_CURRENT_SITE",
    "PATH_CURRENT_SITE",
    "SITE_ID_CURRENT_SITE",
    "BLOG_ID_CURRENT_SITE",
    "WP_ALLOW_MULTISITE",
];
const PATH_NAMES: &[&str] = &[
    "ABSPATH",
    "WP_CONTENT_DIR",
    "WP_CONTENT_URL",
    "WP_PLUGIN_DIR",
    "WP_PLUGIN_URL",
    "UPLOADS",
];

#[derive(Debug, Clone, PartialEq)]
enum Val {
    /// A string whose PHP value is known (single-quoted, or plain double-quoted).
    Str(String),
    /// Double-quoted with `$` or `\`: its PHP value is not reproducible here.
    DqUnsafe,
    Bool(bool),
    Int(i64),
    /// Anything else (expression, call, variable, constant...).
    Other,
}

/// Parse a PHP value at the start of `s`, which must be followed by `)` (define) or `;`.
fn parse_value(s: &str, end: char) -> Val {
    let t = s.trim_start();
    let close = |rest: &str| rest.trim_start().starts_with(end);
    if let Some(body) = t.strip_prefix('\'') {
        let mut v = String::new();
        let mut it = body.char_indices();
        while let Some((i, c)) = it.next() {
            match c {
                '\\' => match it.next() {
                    Some((_, n @ ('\\' | '\''))) => v.push(n),
                    Some((_, n)) => {
                        v.push('\\');
                        v.push(n);
                    }
                    None => return Val::Other,
                },
                '\'' => {
                    return if close(&body[i + 1..]) {
                        Val::Str(v)
                    } else {
                        Val::Other
                    };
                }
                _ => v.push(c),
            }
        }
        return Val::Other;
    }
    if let Some(body) = t.strip_prefix('"') {
        let mut it = body.char_indices();
        let mut unsafe_ = false;
        while let Some((i, c)) = it.next() {
            match c {
                '\\' => {
                    unsafe_ = true;
                    it.next();
                }
                '$' => unsafe_ = true,
                '"' => {
                    if !close(&body[i + 1..]) {
                        return Val::Other;
                    }
                    return if unsafe_ {
                        Val::DqUnsafe
                    } else {
                        Val::Str(body[..i].to_string())
                    };
                }
                _ => {}
            }
        }
        return Val::Other;
    }
    let tok_end = t
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        .unwrap_or(t.len());
    let (tok, rest) = t.split_at(tok_end);
    if !close(rest) {
        return Val::Other;
    }
    match tok.to_ascii_lowercase().as_str() {
        "true" => Val::Bool(true),
        "false" => Val::Bool(false),
        _ => {
            if INT.is_match(tok)
                && let Ok(n) = tok.parse::<i64>()
            {
                Val::Int(n)
            } else {
                Val::Other
            }
        }
    }
}

/// Per byte: true when it lies inside a quoted string (quotes included).
fn string_mask(code: &str) -> Vec<bool> {
    let b = code.as_bytes();
    let mut m = vec![false; b.len()];
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\'' || b[i] == b'"' {
            let q = b[i];
            let start = i;
            i += 1;
            while i < b.len() && b[i] != q {
                i += if b[i] == b'\\' { 2 } else { 1 };
            }
            let end = (i + 1).min(b.len());
            m[start..end].iter_mut().for_each(|x| *x = true);
            i = end;
        } else {
            i += 1;
        }
    }
    m
}

/// Matches of `re` in `code` that start outside any string.
fn code_matches<'a>(
    re: &'a Regex,
    code: &'a str,
    mask: &'a [bool],
) -> impl Iterator<Item = regex::Captures<'a>> {
    let mut at = 0;
    std::iter::from_fn(move || {
        while at <= code.len() {
            let c = re.captures_at(code, at)?;
            let m = c.get(0).expect("match");
            if mask[m.start()] {
                at = m.start() + code[m.start()..].chars().next().map_or(1, char::len_utf8);
            } else {
                at = m.end();
                return Some(c);
            }
        }
        None
    })
}

/// `localhost`, `127.0.0.1` or `::1` (optionally with a `:port`), or a unix socket path.
fn points_at_this_host(v: &str) -> bool {
    let v = v.trim();
    let lower = v.to_ascii_lowercase();
    let host_is = |h: &str| {
        lower == h
            || lower
                .strip_prefix(h)
                .and_then(|r| r.strip_prefix(':'))
                .is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    };
    host_is("localhost")
        || host_is("127.0.0.1")
        || host_is("[::1]")
        || lower == "::1"
        || lower.starts_with("unix:")
        || (v.starts_with('/') && (lower.ends_with(".sock") || lower.ends_with(".socket")))
}

pub fn parse(php: &str) -> Result<OldConfig> {
    let code = strip_php_comments(php);
    // First define wins (PHP semantics).
    let mut defs: BTreeMap<String, Val> = BTreeMap::new();
    let mut order: Vec<String> = Vec::new();
    let mask = string_mask(&code);
    for c in code_matches(&DEFINE, &code, &mask) {
        let name = c[1].to_string();
        if defs.contains_key(&name) {
            continue;
        }
        let rest = &code[c.get(0).expect("match").end()..];
        defs.insert(name.clone(), parse_value(rest, ')'));
        order.push(name);
    }

    let secret_str = |k: &str| -> Result<String> {
        match defs.get(k) {
            Some(Val::Str(s)) => Ok(s.clone()),
            Some(Val::DqUnsafe) => bail!(
                "{k} is a double-quoted string with escapes or variables; convert it to single quotes"
            ),
            Some(_) => bail!("{k} is not a plain string literal"),
            None => bail!("{k} is missing from wp-config.php"),
        }
    };
    let db_name = secret_str("DB_NAME")?;
    let db_user = secret_str("DB_USER")?;
    let db_password = secret_str("DB_PASSWORD")?;
    let db_host = secret_str("DB_HOST")?;

    // PHP assignments: the last one wins.
    let table_prefix = match code_matches(&TABLE_PREFIX, &code, &mask)
        .last()
        .map(|c| parse_value(&code[c.get(0).expect("match").end()..], ';'))
    {
        Some(Val::Str(s)) => s,
        Some(_) => bail!("$table_prefix is not a plain string literal"),
        None => bail!("$table_prefix is missing from wp-config.php"),
    };
    if !PREFIX.is_match(&table_prefix) {
        bail!("$table_prefix must match ^[A-Za-z0-9_]+$");
    }

    let mut warnings = Vec::new();
    if !(db_host == "localhost" || db_host == "127.0.0.1" || db_host.starts_with('/')) {
        warnings.push(
            "DB_HOST is not localhost, 127.0.0.1 or a socket path; iwp always connects through the podman gateway"
                .to_string(),
        );
    }
    let mut optional = |k: &str, ok: &dyn Fn(&str) -> bool, rule: &str| -> Option<String> {
        match defs.get(k)? {
            Val::Str(s) if ok(s) => Some(s.clone()),
            _ => {
                warnings.push(format!("{k} omitted: it must be {rule}"));
                None
            }
        }
    };
    let db_charset = optional(
        "DB_CHARSET",
        &|s| ["utf8mb4", "utf8", "utf8mb3"].contains(&s),
        "utf8mb4, utf8 or utf8mb3",
    );
    let db_collate = optional("DB_COLLATE", &|s| COLLATE.is_match(s), "^[a-z0-9_]*$");

    let salts = import_salts(php)?;

    for k in ["MULTISITE", "SUBDOMAIN_INSTALL"] {
        if defs.get(k).is_some_and(|v| !matches!(v, Val::Bool(_))) {
            bail!("{k} must be true or false");
        }
    }
    let multisite = if defs.get("MULTISITE") == Some(&Val::Bool(true)) {
        let subdomain = defs.get("SUBDOMAIN_INSTALL") == Some(&Val::Bool(true));
        let domain = match defs.get("DOMAIN_CURRENT_SITE") {
            Some(Val::Str(d)) => d.clone(),
            _ => bail!("MULTISITE is enabled but DOMAIN_CURRENT_SITE is missing or not a string"),
        };
        let path = match defs.get("PATH_CURRENT_SITE") {
            None => "/".to_string(),
            Some(Val::Str(p)) if valid_multisite_path(p) => p.clone(),
            Some(_) => bail!(
                "PATH_CURRENT_SITE must be a string that starts and ends with / (segments of A-Za-z0-9._~-)"
            ),
        };
        let id = |k: &str| -> Result<u32> {
            match defs.get(k) {
                None => Ok(1),
                Some(Val::Int(n)) if *n > 0 && *n <= i64::from(u32::MAX) => Ok(*n as u32),
                Some(_) => bail!("{k} must be a positive integer"),
            }
        };
        Some(Multisite {
            subdomain,
            domain,
            path,
            site_id: id("SITE_ID_CURRENT_SITE")?,
            blog_id: id("BLOG_ID_CURRENT_SITE")?,
        })
    } else {
        None
    };

    let mut constants = BTreeMap::new();
    let mut not_carried = Vec::new();
    for name in order {
        if name.starts_with("DB_")
            || SALT_KEYS.contains(&name.as_str())
            || MULTISITE_NAMES.contains(&name.as_str())
        {
            continue;
        }
        if CREDENTIAL.is_match(&name) {
            not_carried.push(format!(
                "{name} (looks like a credential; not carried; v1 has no supported way to supply it \u{2014} move the setting into the plugin's options or wait for per-site extra secrets)"
            ));
            continue;
        }
        let carried = if PATH_NAMES.contains(&name.as_str())
            || RESERVED_CONSTANTS.contains(&name.as_str())
            || !CONST_NAME.is_match(&name)
        {
            None
        } else {
            match &defs[&name] {
                Val::Bool(b) => Some(ConstValue::Bool(*b)),
                Val::Int(n) => Some(ConstValue::Int(*n)),
                Val::Str(s) if !s.contains('$') && !s.chars().any(char::is_control) => {
                    Some(ConstValue::Str(s.clone()))
                }
                _ => None,
            }
        };
        match carried {
            Some(v) => {
                constants.insert(name, v);
            }
            None => not_carried.push(name),
        }
    }

    if defs.contains_key("UPLOADS") {
        warnings.push(
            "UPLOADS is defined in wp-config.php: the copied wp-content/uploads may not be the real uploads location; check where the old site stores its media"
                .into(),
        );
    }
    for (name, v) in &constants {
        if let ConstValue::Str(s) = v
            && points_at_this_host(s)
        {
            warnings.push(format!(
                "{name} points at this host (localhost, a loopback address or a unix socket): inside the container this points at the container itself; change it in [config.constants] if the service is on the host"
            ));
        }
    }

    Ok(OldConfig {
        db_name,
        db_user,
        db_password,
        db_host,
        table_prefix,
        db_charset,
        db_collate,
        salts,
        multisite,
        constants,
        not_carried,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn salts() -> String {
        SALT_KEYS
            .iter()
            .map(|k| format!("define( '{k}', 'SALTVAL-{k}' );\n"))
            .collect()
    }

    fn base(extra: &str) -> String {
        format!(
            "<?php\ndefine( 'DB_NAME', 'wpdb' );\ndefine( 'DB_USER', 'wpuser' );\n\
             define( 'DB_PASSWORD', 'pw' );\ndefine( 'DB_HOST', 'localhost' );\n\
             $table_prefix = 'wp_';\n{}{extra}",
            salts()
        )
    }

    #[test]
    fn db_values_quotes_and_escapes() {
        let php = format!(
            "<?php\ndefine('DB_NAME', \"dq\");\ndefine('DB_USER', 'u\\'x');\n\
             define('DB_PASSWORD', 'p$a\\\\b\\n\"q');\ndefine('DB_HOST', '127.0.0.1');\n\
             $table_prefix = 'wp7_';\n{}",
            salts()
        );
        let c = parse(&php).unwrap();
        assert_eq!(c.db_name, "dq");
        assert_eq!(c.db_user, "u'x");
        assert_eq!(c.db_password, "p$a\\b\\n\"q");
        assert_eq!(c.table_prefix, "wp7_");
        assert!(c.warnings.is_empty(), "{:?}", c.warnings);
        assert_eq!(c.salts.len(), 8);
    }

    #[test]
    fn dq_password_with_dollar_refused_without_leak() {
        let php = base("").replace("'pw'", "\"se$cret\"");
        let e = format!("{:#}", parse(&php).unwrap_err());
        assert!(e.contains("DB_PASSWORD") && !e.contains("se$cret"), "{e}");
    }

    #[test]
    fn comments_ignored_and_first_define_wins() {
        let php = format!(
            "<?php\n// define('DB_NAME','commented');\ndefine('DB_NAME','first');\n\
             define('DB_NAME','second');\n/* define('DB_USER','x'); */\ndefine('DB_USER','u');\n\
             define('DB_PASSWORD','p');define('DB_HOST','localhost');\n$table_prefix='wp_';\n{}",
            salts()
        );
        let c = parse(&php).unwrap();
        assert_eq!((c.db_name.as_str(), c.db_user.as_str()), ("first", "u"));
    }

    #[test]
    fn multisite_parsed_and_not_a_constant() {
        let c = parse(&base(
            "define('WP_ALLOW_MULTISITE', true);\ndefine('MULTISITE', true);\n\
             define('SUBDOMAIN_INSTALL', true);\ndefine('DOMAIN_CURRENT_SITE', 'example.com');\n\
             define('PATH_CURRENT_SITE','/');\ndefine('SITE_ID_CURRENT_SITE',1);\n",
        ))
        .unwrap();
        let ms = c.multisite.clone().unwrap();
        assert!(ms.subdomain && ms.domain == "example.com");
        assert_eq!((ms.path.as_str(), ms.site_id, ms.blog_id), ("/", 1, 1));
        assert!(c.constants.is_empty() && c.not_carried.is_empty(), "{c:?}");
        assert_eq!(parse(&base("")).unwrap().multisite, None);
    }

    #[test]
    fn multisite_path_and_ids_are_carried_and_validated() {
        let ms = |extra: &str| {
            parse(&base(&format!(
                "define('MULTISITE', true);define('SUBDOMAIN_INSTALL', true);\
                 define('DOMAIN_CURRENT_SITE', 'net.example');{extra}"
            )))
        };
        let c = ms("define('PATH_CURRENT_SITE','/net/');define('SITE_ID_CURRENT_SITE',2);define('BLOG_ID_CURRENT_SITE', 3);")
            .unwrap();
        let m = c.multisite.unwrap();
        assert_eq!((m.path.as_str(), m.site_id, m.blog_id), ("/net/", 2, 3));
        // Defaults when absent.
        let m = ms("").unwrap().multisite.unwrap();
        assert_eq!((m.path.as_str(), m.site_id, m.blog_id), ("/", 1, 1));
        for (bad, what) in [
            ("define('PATH_CURRENT_SITE','net/');", "PATH_CURRENT_SITE"),
            ("define('PATH_CURRENT_SITE','/net');", "PATH_CURRENT_SITE"),
            (
                "define('PATH_CURRENT_SITE', \"/x'y/\");",
                "PATH_CURRENT_SITE",
            ),
            ("define('PATH_CURRENT_SITE', $p);", "PATH_CURRENT_SITE"),
            ("define('SITE_ID_CURRENT_SITE', 0);", "SITE_ID_CURRENT_SITE"),
            (
                "define('SITE_ID_CURRENT_SITE', '2');",
                "SITE_ID_CURRENT_SITE",
            ),
            (
                "define('BLOG_ID_CURRENT_SITE', -1);",
                "BLOG_ID_CURRENT_SITE",
            ),
        ] {
            let e = format!("{:#}", ms(bad).unwrap_err());
            assert!(e.contains(what), "{bad}: {e}");
        }
    }

    #[test]
    fn constants_carried_and_skipped() {
        let c = parse(&base(
            "define('WP_DEBUG', false);\ndefine('WP_MEMORY_LIMIT','256M');\n\
             define('AUTOSAVE_INTERVAL', 120);\ndefine('FOO', $_SERVER['X']);\n\
             define('BAR', 'a$b');\ndefine('BAZ', dirname(__FILE__) . '/x');\n\
             define('ABSPATH', dirname(__FILE__) . '/');\ndefine('WP_CONTENT_DIR', '/x');\n\
             define('WP_CONTENT_URL', 'http://x');\n",
        ))
        .unwrap();
        assert_eq!(c.constants["WP_DEBUG"], ConstValue::Bool(false));
        assert_eq!(
            c.constants["WP_MEMORY_LIMIT"],
            ConstValue::Str("256M".into())
        );
        assert_eq!(c.constants["AUTOSAVE_INTERVAL"], ConstValue::Int(120));
        assert_eq!(c.constants.len(), 3);
        for n in [
            "FOO",
            "BAR",
            "BAZ",
            "ABSPATH",
            "WP_CONTENT_DIR",
            "WP_CONTENT_URL",
        ] {
            assert!(c.not_carried.contains(&n.to_string()), "{n}");
        }
        assert!(!c.not_carried.iter().any(|n| n.starts_with("DB_")));
    }

    #[test]
    fn missing_db_name_names_key_only() {
        let php = base("").replace("define( 'DB_NAME', 'wpdb' );", "");
        let e = format!("{:#}", parse(&php).unwrap_err());
        assert!(e.contains("DB_NAME") && !e.contains("wpdb"), "{e}");
    }

    #[test]
    fn prefix_validation_and_host_warning() {
        let e = parse(&base("").replace("'wp_'", "'wp-;'")).unwrap_err();
        assert!(format!("{e}").contains("table_prefix"));
        assert!(parse(&base("").replace("$table_prefix = 'wp_';", "")).is_err());
        let c = parse(&base("").replace("'localhost'", "'db.example.com'")).unwrap();
        assert_eq!(c.warnings.len(), 1);
        assert!(!c.warnings[0].contains("db.example.com"));
        let c = parse(&base("").replace("'localhost'", "'/var/run/mysqld/mysqld.sock'")).unwrap();
        assert!(c.warnings.is_empty());
    }

    #[test]
    fn charset_collate_validated() {
        let c = parse(&base(
            "define('DB_CHARSET','utf8mb4');define('DB_COLLATE','utf8mb4_unicode_ci');",
        ))
        .unwrap();
        assert_eq!(c.db_charset.as_deref(), Some("utf8mb4"));
        assert_eq!(c.db_collate.as_deref(), Some("utf8mb4_unicode_ci"));
        let c = parse(&base(
            "define('DB_CHARSET','latin1');define('DB_COLLATE','UTF8 bin');",
        ))
        .unwrap();
        assert!(c.db_charset.is_none() && c.db_collate.is_none());
        assert_eq!(c.warnings.len(), 2);
        let c = parse(&base(
            "define('DB_CHARSET','utf8');define('DB_COLLATE','');",
        ))
        .unwrap();
        assert_eq!(c.db_collate.as_deref(), Some(""));
    }

    #[test]
    fn octal_hex_binary_are_not_carried() {
        let c = parse(&base(
            "define('FS_CHMOD_FILE', 0644);define('A',0755);define('B',0x1F);define('C',0b11);\n\
             define('Z', 0);define('NEG', -1);define('POS', 42);define('T', TRUE);define('F', False);",
        ))
        .unwrap();
        for n in ["FS_CHMOD_FILE", "A", "B", "C"] {
            assert!(c.not_carried.contains(&n.to_string()), "{n}");
            assert!(!c.constants.contains_key(n), "{n}");
        }
        assert_eq!(c.constants["Z"], ConstValue::Int(0));
        assert_eq!(c.constants["NEG"], ConstValue::Int(-1));
        assert_eq!(c.constants["POS"], ConstValue::Int(42));
        assert_eq!(c.constants["T"], ConstValue::Bool(true));
        assert_eq!(c.constants["F"], ConstValue::Bool(false));
    }

    #[test]
    fn define_text_inside_strings_is_not_parsed() {
        let pw = r#"x');define("DB_HOST","evil");$table_prefix = 'bad_';define('Q', 1); é"#;
        let php = base("").replace(
            "'pw'",
            &format!("'{}'", pw.replace('\\', "\\\\").replace('\'', "\\'")),
        );
        let c = parse(&php).unwrap();
        assert_eq!(c.db_password, pw);
        assert_eq!(c.db_host, "localhost");
        assert_eq!(c.table_prefix, "wp_");
        assert!(!c.constants.contains_key("Q"));
    }

    #[test]
    fn paren_semicolon_inside_value_and_hash_comments() {
        let php = base("").replace("'pw'", "'a); b' # trailing define('DB_HOST','x');\n");
        let c = parse(&php).unwrap_or_else(|e| panic!("{e:#}"));
        assert_eq!(c.db_password, "a); b");
        assert_eq!(c.db_host, "localhost");
    }

    #[test]
    fn unicode_password_roundtrips() {
        let c = parse(&base("").replace("'pw'", "'lozinka-čšž-日本'")).unwrap();
        assert_eq!(c.db_password, "lozinka-čšž-日本");
    }

    #[test]
    fn multisite_flags_must_be_bool() {
        let e = parse(&base("define('MULTISITE', 'yes');")).unwrap_err();
        assert!(format!("{e}").contains("MULTISITE must be true or false"));
        let e = parse(&base(
            "define('MULTISITE', true);define('SUBDOMAIN_INSTALL', 1);define('DOMAIN_CURRENT_SITE','a.b');",
        ))
        .unwrap_err();
        assert!(format!("{e}").contains("SUBDOMAIN_INSTALL must be true or false"));
    }

    #[test]
    fn define_is_case_insensitive() {
        let php =
            base("DEFINE('WP_DEBUG', true);").replace("define( 'DB_USER'", "Define( 'DB_USER'");
        let c = parse(&php).unwrap();
        assert_eq!(c.constants["WP_DEBUG"], ConstValue::Bool(true));
        assert_eq!(c.db_user, "wpuser");
        let salts_upper = salts().replace("define(", "DEFINE (");
        assert_eq!(
            crate::host::secrets::import_salts(&salts_upper)
                .unwrap()
                .len(),
            8
        );
    }

    #[test]
    fn last_table_prefix_wins_ignoring_strings_and_comments() {
        let php = base(
            "// $table_prefix = 'c_';\n$table_prefix = 'second_';\n$x = '$table_prefix = \\'str_\\';';\n",
        );
        assert_eq!(parse(&php).unwrap().table_prefix, "second_");
    }

    #[test]
    fn credential_like_constants_are_never_carried() {
        let c = parse(&base(
            "define('MY_API_TOKEN','t0k');define('SMTP_PASSWORD','smtpsecret');define('WP_CACHE_KEY_SALT','k');\n\
             define('RECAPTCHA_SECRET','s');define('SOME_AUTH','a');define('WP_DEBUG', true);",
        ))
        .unwrap();
        assert_eq!(c.constants.len(), 1);
        let joined = c.not_carried.join("|");
        assert!(
            joined.contains("MY_API_TOKEN (looks like a credential; not carried; v1 has no supported way to supply it \u{2014} move the setting into the plugin's options or wait for per-site extra secrets)"),
            "{joined}"
        );
        for n in [
            "SMTP_PASSWORD",
            "WP_CACHE_KEY_SALT",
            "RECAPTCHA_SECRET",
            "SOME_AUTH",
        ] {
            assert!(
                joined.contains(&format!("{n} (looks like a credential")),
                "{n}"
            );
        }
        for v in ["t0k", "smtpsecret"] {
            assert!(!joined.contains(v));
        }
    }

    #[test]
    fn uploads_and_local_endpoints_warn_by_name_only() {
        let c = parse(&base(
            "define('UPLOADS', 'wp-content/media');\n\
             define('WP_REDIS_HOST', '127.0.0.1');define('WP_REDIS_PATH', '/var/run/redis/redis.sock');\n\
             define('MEMCACHE_SERVER', 'localhost:11211');define('V6', '::1');\n\
             define('SITE_LABEL', 'localhost-ish shop');define('OTHER_HOST', 'db.example');",
        ))
        .unwrap();
        let w = c.warnings.join("|");
        assert!(
            w.contains("UPLOADS is defined in wp-config.php: the copied wp-content/uploads may not be the real uploads location"),
            "{w}"
        );
        for n in ["WP_REDIS_HOST", "WP_REDIS_PATH", "MEMCACHE_SERVER", "V6"] {
            assert!(
                w.contains(&format!("{n} points at this host (localhost, a loopback address or a unix socket): inside the container this points at the container itself")),
                "{n}: {w}"
            );
        }
        assert!(
            !w.contains("SITE_LABEL") && !w.contains("OTHER_HOST"),
            "{w}"
        );
        assert!(!w.contains("redis.sock") && !w.contains("11211"), "{w}");
    }

    #[test]
    fn debug_redacts_secrets() {
        let c = parse(&base("").replace("'pw'", "'hunter2pw'")).unwrap();
        let d = format!("{c:?}");
        assert!(!d.contains("hunter2pw") && !d.contains("SALTVAL"), "{d}");
        assert!(d.contains("wpdb") && d.contains("redacted"));
    }
}
