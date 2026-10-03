use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use super::{ConstValue, GlobalConfig, LoadedSite, Package, Site, Source};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub field: String,
    pub message: String,
}

impl std::fmt::Display for Issue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

pub const RESERVED_CONSTANTS: &[&str] = &[
    "DB_NAME",
    "DB_USER",
    "DB_PASSWORD",
    "DB_HOST",
    "DB_CHARSET",
    "DB_COLLATE",
    "AUTH_KEY",
    "SECURE_AUTH_KEY",
    "LOGGED_IN_KEY",
    "NONCE_KEY",
    "AUTH_SALT",
    "SECURE_AUTH_SALT",
    "LOGGED_IN_SALT",
    "NONCE_SALT",
    "ABSPATH",
    "DISALLOW_FILE_MODS",
    "DISALLOW_FILE_EDIT",
    "AUTOMATIC_UPDATER_DISABLED",
    "WP_AUTO_UPDATE_CORE",
    "DISABLE_WP_CRON",
    "WP_TEMP_DIR",
    "FS_METHOD",
    "WP_ALLOW_MULTISITE",
    "MULTISITE",
    "SUBDOMAIN_INSTALL",
    "DOMAIN_CURRENT_SITE",
    "PATH_CURRENT_SITE",
    "SITE_ID_CURRENT_SITE",
    "BLOG_ID_CURRENT_SITE",
    "WP_CONTENT_DIR",
    "WP_CONTENT_URL",
    "WP_PLUGIN_DIR",
    "WP_PLUGIN_URL",
    "WPMU_PLUGIN_DIR",
    "WPMU_PLUGIN_URL",
    "WP_LANG_DIR",
    "UPLOADS",
];

pub const ALLOWED_DROPINS: &[&str] = &[
    "advanced-cache.php",
    "object-cache.php",
    "db.php",
    "db-error.php",
    "maintenance.php",
    "sunrise.php",
    "php-error.php",
    "fatal-error-handler.php",
    "install.php",
];

const PROTECTED_TOP: &[&str] = &[
    "plugins",
    "themes",
    "mu-plugins",
    "languages",
    "uploads",
    "upgrade",
];
/// PHP paths with an exact `location =` block in the nginx include.
const FIXED_PHP_LOCATIONS: &[&str] = &[
    "/xmlrpc.php",
    "/wp-config.php",
    "/wp-config-sample.php",
    "/wp-cron.php",
];
const PHP_VERSIONS: &[&str] = &["8.2", "8.3", "8.4", "8.5"];

macro_rules! re {
    ($name:ident, $pat:expr) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pat).unwrap());
    };
}
re!(NAME, r"^[a-z][a-z0-9-]{0,30}$");

/// Whether `s` is an acceptable site name (also the `<site>.toml` file stem).
pub fn valid_site_name(s: &str) -> bool {
    NAME.is_match(s)
}
re!(
    HOST,
    r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
);
re!(WP_VERSION, r"^[0-9]+\.[0-9]+(\.[0-9]+)?$");
re!(LANG, r"^[a-z]{2,3}(_[A-Z]{2})?(_[a-z]+)?$");
re!(CONST_NAME, r"^[A-Z_][A-Z0-9_]*$");
re!(IDENT, r"^[a-z_][a-z0-9_-]{0,31}$");
// One plain address: it is written into a mail header.
re!(
    EMAIL,
    r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$"
);
re!(SIZE, r"^[1-9][0-9]*[KMG]?$");
re!(FUNC, r"^[a-z_][a-z0-9_]*$");
re!(SLUG, r"^[a-z0-9][a-z0-9._-]{0,99}$");
re!(PKG_VERSION, r"^[0-9A-Za-z][0-9A-Za-z.+-]{0,39}$");
re!(SHA256, r"^[0-9a-f]{64}$");
re!(GIT_REV, r"^[0-9a-f]{40}$");
re!(COMPONENT, r"^[A-Za-z0-9][A-Za-z0-9._-]*$");
re!(
    URL,
    r"^https://[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._~%/+-]*$"
);
re!(
    GIT_URL,
    r"^(https://[A-Za-z0-9][A-Za-z0-9.-]*(:[0-9]+)?/|git@[A-Za-z0-9][A-Za-z0-9.-]*:)[A-Za-z0-9._~%/+-]+$"
);

/// Whether `s` is an acceptable package slug (the site-file rule).
pub fn valid_slug(s: &str) -> bool {
    SLUG.is_match(s) && !s.contains("..")
}

/// Whether `s` is an acceptable wordpress.org package version (the site-file rule).
pub fn valid_pkg_version(s: &str) -> bool {
    PKG_VERSION.is_match(s)
}

/// "wp-content/wflogs" → "wflogs" (path under <base>/shared/).
pub fn shared_rel(path: &str) -> &str {
    path.strip_prefix("wp-content/").unwrap_or(path)
}

#[derive(Default)]
struct Collector {
    issues: Vec<Issue>,
}

impl Collector {
    fn err(&mut self, field: impl Into<String>, message: impl Into<String>) {
        self.issues.push(Issue {
            field: field.into(),
            message: message.into(),
        });
    }
}

/// Absolute UTF-8 path, at least one component, each matching COMPONENT (allowlist).
fn is_clean_absolute(p: &Path) -> bool {
    let Some(s) = p.to_str() else { return false };
    s.strip_prefix('/')
        .is_some_and(|rest| rest.split('/').all(|c| COMPONENT.is_match(c)))
}

/// Bytes of a php size string like "256M" (K/M/G are 1024 multiples); None if malformed.
pub fn size_bytes(v: &str) -> Option<u64> {
    if !SIZE.is_match(v) {
        return None;
    }
    let (digits, mult) = match v.chars().last()? {
        'K' => (&v[..v.len() - 1], 1u64 << 10),
        'M' => (&v[..v.len() - 1], 1 << 20),
        'G' => (&v[..v.len() - 1], 1 << 30),
        _ => (v, 1),
    };
    digits.parse::<u64>().ok()?.checked_mul(mult)
}

/// Components of a "/"-separated relative path, if every component matches COMPONENT.
fn clean_components(p: &str) -> Option<Vec<&str>> {
    let parts: Vec<&str> = p.split('/').collect();
    parts
        .iter()
        .all(|c| COMPONENT.is_match(c) && *c != "." && *c != "..")
        .then_some(parts)
}

pub fn validate_site(site: &Site, file_stem: Option<&str>) -> Vec<Issue> {
    let mut c = Collector::default();
    check_identity(&mut c, site, file_stem);
    check_core(&mut c, site);
    check_config(&mut c, site);
    check_php(&mut c, site);
    check_packages(&mut c, "plugin", &site.plugins, true);
    check_packages(&mut c, "theme", &site.themes, false);
    let writable = check_writable(&mut c, site);
    check_dropins(&mut c, site);
    check_entrypoints(&mut c, site, &writable);
    check_database(&mut c, site);
    check_wpcli(&mut c, site);
    check_limits(&mut c, site);
    check_verify(&mut c, &writable, &site.verify.allow_php);
    for a in site.verify.admins.iter().flatten() {
        if a.is_empty() || a.len() > 60 || a.chars().any(char::is_control) {
            c.err(
                "verify.admins",
                format!(
                    "{a:?} is not a WordPress login (1 to 60 characters, no control characters)"
                ),
            );
        }
    }
    c.issues
}

re!(GLOB_SEGMENT, r"^[A-Za-z0-9._*?-]+$");

/// Regex for a `[verify] allow_php` glob over WP-root-relative paths: `*` and `?` match within
/// one path segment, everything else is literal. None unless the glob is a clean relative path
/// (segments of [A-Za-z0-9._*?-], no empty, `.` or `..` segment).
pub fn allow_php_regex(glob: &str) -> Option<Regex> {
    let ok = glob
        .split('/')
        .all(|seg| GLOB_SEGMENT.is_match(seg) && seg != "." && seg != "..");
    if !ok {
        return None;
    }
    let mut re = String::from("^");
    for ch in glob.chars() {
        match ch {
            '*' => re.push_str("[^/]*"),
            '?' => re.push_str("[^/]"),
            c => re.push_str(&regex::escape(&c.to_string())),
        }
    }
    re.push('$');
    Regex::new(&re).ok()
}

fn check_verify(c: &mut Collector, writable: &[String], allow_php: &[String]) {
    for g in allow_php {
        let under = |dir: &str| g.starts_with(&format!("{dir}/"));
        if allow_php_regex(g).is_none() {
            c.err(
                "verify.allow_php",
                format!("{g:?} must be a relative path without '..', '.', '//' or a trailing '/', using only [A-Za-z0-9._-] and the wildcards * and ?"),
            );
        } else if g == "wp-content/uploads" || under("wp-content/uploads") {
            c.err(
                "verify.allow_php",
                format!("{g:?}: PHP in wp-content/uploads can never be allowed"),
            );
        } else if !writable.iter().any(|w| under(w)) {
            c.err(
                "verify.allow_php",
                format!("{g:?} must lie under a declared writable path"),
            );
        }
    }
}

static DB_IDENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_]{1,64}$").unwrap());
static DB_PREFIX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_]+$").unwrap());
static DB_COLLATE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z0-9_]*$").unwrap());

const FORBIDDEN_MOUNTS: &[&str] = &[
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/boot",
    "/dev",
    "/proc",
    "/sys",
    "/run",
    "/var/lib",
    "/var/run",
    "/root",
    "/var/www/html",
    "/tmp",
];

fn check_database(c: &mut Collector, site: &Site) {
    let d = &site.database;
    for (k, v) in [("name", &d.name), ("user", &d.user)] {
        if let Some(v) = v
            && !DB_IDENT.is_match(v)
        {
            c.err(
                format!("database.{k}"),
                format!("{v:?} must match ^[A-Za-z0-9_]{{1,64}}$"),
            );
        }
    }
    if let Some(v) = &d.prefix
        && !DB_PREFIX.is_match(v)
    {
        c.err(
            "database.prefix",
            format!("{v:?} must match ^[A-Za-z0-9_]+$"),
        );
    }
    if let Some(v) = &d.charset
        && !["utf8mb4", "utf8", "utf8mb3"].contains(&v.as_str())
    {
        c.err(
            "database.charset",
            format!("{v:?} must be utf8mb4, utf8 or utf8mb3"),
        );
    }
    if let Some(v) = &d.collate
        && !DB_COLLATE.is_match(v)
    {
        c.err("database.collate", format!("{v:?} must match ^[a-z0-9_]*$"));
    }
}

fn check_limits(c: &mut Collector, site: &Site) {
    let tmp_size = site.tmp_size();
    let Some(tmp) = size_bytes(&tmp_size) else {
        c.err(
            "limits.tmp_size",
            format!("{tmp_size:?} must be a size like 1G"),
        );
        return;
    };
    if size_bytes(&site.php.post_max_size).is_some_and(|post| tmp < post) {
        c.err(
            "limits.tmp_size",
            format!(
                "{tmp_size:?} must be >= php.post_max_size {:?} (request bodies are buffered in /tmp)",
                site.php.post_max_size
            ),
        );
    }
    if let Some(m) = &site.limits.memory {
        match size_bytes(m) {
            None => c.err("limits.memory", format!("{m:?} must be a size like 4G")),
            Some(b) => {
                let floor = tmp.saturating_add(size_bytes(&site.php.memory_limit).unwrap_or(0));
                if b < floor {
                    c.err(
                        "limits.memory",
                        format!(
                            "{m:?} must cover at least tmp_size plus one worker's php.memory_limit"
                        ),
                    );
                }
            }
        }
    }
}

fn check_wpcli(c: &mut Collector, site: &Site) {
    for m in &site.wpcli.mounts {
        let field = "wpcli.mounts";
        let Some(s) = m.to_str() else {
            c.err(field, format!("{} is not valid UTF-8", m.display()));
            continue;
        };
        let normalised = s.starts_with('/')
            && s != "/"
            && !s.ends_with('/')
            && s.split('/')
                .skip(1)
                .all(|p| !p.is_empty() && p != "." && p != "..");
        if !normalised {
            c.err(field, format!("{s:?} must be an absolute normalised path (no ., .. or trailing /) other than /"));
            continue;
        }
        if let Some(f) = FORBIDDEN_MOUNTS
            .iter()
            .find(|f| s == **f || s.starts_with(&format!("{f}/")))
        {
            c.err(field, format!("{s:?} must not be or be under {f}"));
        }
    }
}

fn check_identity(c: &mut Collector, site: &Site, file_stem: Option<&str>) {
    if !NAME.is_match(&site.name) {
        c.err(
            "name",
            format!("{:?} must match ^[a-z][a-z0-9-]{{0,30}}$", site.name),
        );
    }
    if site.name.ends_with("-cron") || site.name.ends_with("-verify") {
        c.err(
            "name",
            format!(
                "{:?} must not end in -cron or -verify (collides with the generated iwp-<name>-cron/-verify systemd units of another site)",
                site.name
            ),
        );
    }
    if let Some(stem) = file_stem
        && stem != site.name
    {
        c.err(
            "name",
            format!("{:?} must equal the file name ({stem}.toml)", site.name),
        );
    }
    if !(1..=511).contains(&site.id) {
        c.err("id", format!("{} must be in 1..=511", site.id));
    }
    if let Some(base) = &site.base
        && !is_clean_absolute(base)
    {
        c.err(
            "base",
            format!(
                "{} must be an absolute path whose components match [A-Za-z0-9][A-Za-z0-9._-]*",
                base.display()
            ),
        );
    }
    if site.domains.is_empty() {
        c.err("domains", "at least one domain is required");
    }
    let mut seen = BTreeSet::new();
    for d in &site.domains {
        if d.len() > 253 || !HOST.is_match(d) {
            c.err(
                "domains",
                format!("{d:?} is not a valid lowercase hostname"),
            );
        } else if !seen.insert(d.as_str()) {
            c.err("domains", format!("{d:?} is listed twice"));
        }
    }
}

/// Shared WordPress/PHP version rules (site files and `iwp image build` arguments).
pub fn validate_core_versions(wp: &str, php: &str) -> Vec<Issue> {
    let mut c = Collector::default();
    if !WP_VERSION.is_match(wp) {
        c.err(
            "core.wordpress",
            format!("{wp:?} must be a version like 7.1.2"),
        );
    }
    if !PHP_VERSIONS.contains(&php) {
        c.err(
            "core.php",
            format!("{php:?} must be one of {PHP_VERSIONS:?}"),
        );
    }
    c.issues
}

fn check_core(c: &mut Collector, site: &Site) {
    c.issues
        .extend(validate_core_versions(&site.core.wordpress, &site.core.php));
    for l in &site.core.languages {
        if !LANG.is_match(l) {
            c.err(
                "core.languages",
                format!("{l:?} is not a WordPress locale (e.g. hr, de_DE, de_DE_formal)"),
            );
        }
    }
}

static MULTISITE_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/([A-Za-z0-9_~-][A-Za-z0-9._~-]*/)*$").unwrap());

/// PATH_CURRENT_SITE as iwp accepts it (it is rendered into a single-quoted PHP string).
pub fn valid_multisite_path(p: &str) -> bool {
    MULTISITE_PATH.is_match(p)
}

fn check_config(c: &mut Collector, site: &Site) {
    if let Some(ms) = &site.config.multisite {
        if !ms.subdomain {
            c.err(
                "config.multisite.subdomain",
                "only subdomain multisite is supported in v1",
            );
        }
        if !site.domains.contains(&ms.domain) {
            c.err(
                "config.multisite.domain",
                format!("{:?} must be one of `domains`", ms.domain),
            );
        }
        if !valid_multisite_path(&ms.path) {
            c.err(
                "config.multisite.path",
                format!(
                    "{:?} must start and end with / (segments of A-Za-z0-9._~- not starting with .)",
                    ms.path
                ),
            );
        }
        for (f, v) in [("site_id", ms.site_id), ("blog_id", ms.blog_id)] {
            if v == 0 {
                c.err(
                    format!("config.multisite.{f}"),
                    "must be a positive integer",
                );
            }
        }
    }
    for (name, value) in &site.config.constants {
        let field = format!("config.constants.{name}");
        if !CONST_NAME.is_match(name) {
            c.err(&field, "constant names must match ^[A-Z_][A-Z0-9_]*$");
        } else if RESERVED_CONSTANTS.contains(&name.as_str()) {
            c.err(
                &field,
                "is managed by iwp and cannot be set in the site file",
            );
        }
        if let ConstValue::Str(s) = value
            && s.chars().any(char::is_control)
        {
            c.err(&field, "string values must not contain control characters");
        }
    }
}

fn check_php(c: &mut Collector, site: &Site) {
    let php = &site.php;
    for (field, v) in [
        ("php.memory_limit", &php.memory_limit),
        ("php.upload_max_filesize", &php.upload_max_filesize),
        ("php.post_max_size", &php.post_max_size),
    ] {
        if !SIZE.is_match(v) {
            c.err(field, format!("{v:?} must be a size like 256M"));
        }
    }
    if let (Some(up), Some(post)) = (
        size_bytes(&php.upload_max_filesize),
        size_bytes(&php.post_max_size),
    ) && post < up
    {
        c.err(
            "php.post_max_size",
            format!(
                "{:?} must be >= upload_max_filesize {:?}",
                php.post_max_size, php.upload_max_filesize
            ),
        );
    }
    if !(1..=3600).contains(&php.max_execution_time) {
        c.err("php.max_execution_time", "must be in 1..=3600");
    }
    for f in &php.disable_functions {
        if !FUNC.is_match(f) {
            c.err(
                "php.disable_functions",
                format!("{f:?} is not a PHP function name"),
            );
        }
    }
    let fpm = &php.fpm;
    let ordered = fpm.min_spare <= fpm.start_servers
        && fpm.start_servers <= fpm.max_spare
        && fpm.max_spare <= fpm.max_children;
    if fpm.max_children == 0 || fpm.min_spare == 0 || !ordered {
        c.err(
            "php.fpm",
            "need 1 <= min_spare <= start_servers <= max_spare <= max_children",
        );
    }
}

/// Checks writable/cache dirs across all packages; returns the declared writable paths.
fn check_writable(c: &mut Collector, site: &Site) -> Vec<String> {
    let owners: Vec<(String, &str)> = site
        .plugins
        .iter()
        .map(|p| ("plugin", p))
        .chain(site.themes.iter().map(|p| ("theme", p)))
        .flat_map(|(k, p)| {
            p.writable
                .iter()
                .map(move |w| (format!("{k}[{}].writable", p.slug), w.as_str()))
        })
        .collect();
    for (i, (field, a)) in owners.iter().enumerate() {
        for (_, b) in owners.iter().take(i) {
            if a == b || a.starts_with(&format!("{b}/")) || b.starts_with(&format!("{a}/")) {
                c.err(
                    field.clone(),
                    format!("{a:?} duplicates or nests with {b:?}"),
                );
            }
        }
    }
    let writable: Vec<String> = owners.iter().map(|(_, w)| (*w).to_string()).collect();
    for (kind, list) in [("plugin", &site.plugins), ("theme", &site.themes)] {
        for p in list {
            for cache in &p.cache {
                if !writable
                    .iter()
                    .any(|w| cache == w || cache.starts_with(&format!("{w}/")))
                {
                    c.err(
                        format!("{kind}[{}].cache", p.slug),
                        format!("{cache:?} must be inside a declared writable dir"),
                    );
                }
            }
        }
    }
    writable
}

fn check_dropins(c: &mut Collector, site: &Site) {
    let plugin_slugs: BTreeSet<&str> = site.plugins.iter().map(|p| p.slug.as_str()).collect();
    for (name, d) in &site.dropins {
        let field = format!("dropins.{name}");
        if !ALLOWED_DROPINS.contains(&name.as_str()) {
            c.err(
                &field,
                format!("not a WordPress drop-in; allowed: {ALLOWED_DROPINS:?}"),
            );
        }
        if !plugin_slugs.contains(d.plugin.as_str()) {
            c.err(&field, format!("plugin {:?} is not declared", d.plugin));
        }
        if clean_components(&d.file).is_none() || !d.file.ends_with(".php") {
            c.err(
                &field,
                format!(
                    "file {:?} must be a relative .php path inside the plugin",
                    d.file
                ),
            );
        }
    }
}

fn check_entrypoints(c: &mut Collector, site: &Site, writable: &[String]) {
    let mut seen = BTreeSet::new();
    for ep in &site.nginx.php_entrypoints {
        if !seen.insert(ep.as_str()) {
            c.err("nginx.php_entrypoints", format!("{ep:?} is listed twice"));
            continue;
        }
        if FIXED_PHP_LOCATIONS.contains(&ep.as_str()) {
            c.err(
                "nginx.php_entrypoints",
                format!("{ep:?} already has a fixed location in the generated nginx include"),
            );
            continue;
        }
        let ok = ep.strip_prefix('/').and_then(clean_components).is_some() && ep.ends_with(".php");
        if !ok {
            c.err("nginx.php_entrypoints", format!("{ep:?} must be an absolute URL path ending in .php without '..', '//' or special characters"));
            continue;
        }
        let rel = &ep[1..];
        let under = |dir: &str| rel.starts_with(&format!("{dir}/"));
        if under("wp-content/uploads") || writable.iter().any(|w| under(w)) {
            c.err(
                "nginx.php_entrypoints",
                format!("{ep:?} is inside a writable directory"),
            );
        }
    }
}

fn check_source(c: &mut Collector, f: &str, p: &Package, src: &Source) {
    match &p.sha256 {
        None => c.err(
            format!("{f}.sha256"),
            format!("required with `source`; run `iwp pin <site> {}`", p.slug),
        ),
        Some(h) if !SHA256.is_match(h) => {
            c.err(format!("{f}.sha256"), "must be 64 lowercase hex characters")
        }
        _ => {}
    }
    if let Some(msg) = source_issue(src) {
        c.err(format!("{f}.source"), msg);
    }
}

/// What is wrong with a `source` (the site-file rule), if anything.
pub fn source_issue(src: &Source) -> Option<&'static str> {
    match src {
        Source::Path { path } => (!is_clean_absolute(path))
            .then_some("path must be absolute with components matching [A-Za-z0-9][A-Za-z0-9._-]*"),
        Source::Git { git, rev } => (!GIT_URL.is_match(git) || !GIT_REV.is_match(rev))
            .then_some("git must be https:// or git@ URL and rev a full 40-hex commit"),
        Source::Url { url } => (!URL.is_match(url))
            .then_some("url must be https:// without query or special characters"),
    }
}

fn check_packages(c: &mut Collector, kind: &str, list: &[Package], allow_mu: bool) {
    let mut seen = BTreeSet::new();
    for p in list {
        let f = format!("{kind}[{}]", p.slug);
        if !SLUG.is_match(&p.slug) || p.slug.contains("..") {
            c.err(
                format!("{f}.slug"),
                "must match ^[a-z0-9][a-z0-9._-]{0,99}$ and not contain '..'",
            );
        }
        if !seen.insert(p.slug.as_str()) {
            c.err(&f, "declared twice");
        }
        match (&p.version, &p.source) {
            (Some(_), Some(_)) => c.err(
                &f,
                "set either `version` (wordpress.org) or `source`, not both",
            ),
            (None, None) => c.err(&f, "set `version` (wordpress.org) or `source`"),
            (Some(v), None) => {
                if !PKG_VERSION.is_match(v) {
                    c.err(
                        format!("{f}.version"),
                        format!("{v:?} is not a valid version"),
                    );
                }
                if p.sha256.is_some() {
                    c.err(
                        format!("{f}.sha256"),
                        "not used with wordpress.org packages (per-file checksums are fetched)",
                    );
                }
            }
            (None, Some(src)) => check_source(c, &f, p, src),
        }
        if p.mu && !allow_mu {
            c.err(format!("{f}.mu"), "only plugins can be mu-plugins");
        }
        if p.mu && allow_mu {
            if p.slug == "iwp" {
                c.err(format!("{f}.slug"), "the mu-plugin name `iwp` is reserved");
            }
            let single_php = matches!(&p.source, Some(Source::Path { path }) if path.extension().is_some_and(|e| e == "php"));
            if !single_php {
                c.err(
                    format!("{f}.mu"),
                    "mu-plugins must be a single .php file from a `path` source in v1",
                );
            }
        }
        for w in &p.writable {
            let ok = clean_components(w).is_some_and(|parts| {
                parts.len() >= 2 && parts[0] == "wp-content" && !PROTECTED_TOP.contains(&parts[1])
            });
            let dropin = clean_components(w).is_some_and(|parts| {
                parts.len() == 2 && parts[0] == "wp-content" && ALLOWED_DROPINS.contains(&parts[1])
            });
            if dropin {
                c.err(
                    format!("{f}.writable"),
                    format!("{w:?} is a drop-in destination and cannot be writable"),
                );
            }
            if !ok {
                c.err(format!("{f}.writable"), format!("{w:?} must be wp-content/<dir>… (not plugins/themes/mu-plugins/languages/uploads/upgrade), relative, no '..' or trailing '/'"));
            }
        }
        for cache in &p.cache {
            if clean_components(cache)
                .is_none_or(|parts| parts.len() < 2 || parts[0] != "wp-content")
            {
                c.err(
                    format!("{f}.cache"),
                    format!("{cache:?} must be a clean wp-content/… path"),
                );
            }
        }
    }
}

/// Values of iwp.toml that end up in generated files or UID arithmetic.
pub fn validate_global(g: &GlobalConfig) -> Vec<Issue> {
    let mut c = Collector::default();
    for (field, p) in [
        ("sites_dir", &g.sites_dir),
        ("cache_dir", &g.cache_dir),
        ("base_root", &g.base_root),
        ("mariadb_socket", &g.mariadb_socket),
    ] {
        if !is_clean_absolute(p) {
            c.err(
                field,
                format!(
                    "{} must be an absolute path whose components match [A-Za-z0-9][A-Za-z0-9._-]*",
                    p.display()
                ),
            );
        }
    }
    for (field, v) in [
        ("podman_network", &g.podman_network),
        ("nginx_group", &g.nginx_group),
    ] {
        if !IDENT.is_match(v) {
            c.err(
                field,
                format!("{v:?} must match ^[a-z_][a-z0-9_-]{{0,31}}$"),
            );
        }
    }
    if g.id_offset < 65_536 || u64::from(g.id_offset) + 512 * 65_536 > u64::from(u32::MAX) {
        c.err(
            "id_offset",
            "must be >= 65536 and leave room for 512 slots of 65536 IDs within 32 bits",
        );
    }
    if g.keep_releases < 2 {
        c.err("keep_releases", "must be >= 2");
    }
    if g.keep_db_dumps < 1 {
        c.err("keep_db_dumps", "must be >= 1");
    }
    if let Some(a) = &g.alert_email
        && !EMAIL.is_match(a)
    {
        c.err("alert_email", format!("{a:?} is not a mail address"));
    }
    for a in &g.egress.allow {
        if crate::host::egress::parse_allow(a).is_none() {
            c.err(
                "egress.allow",
                format!("{a:?} must be \"<ipv4>[/<prefix>]:<tcp port>\""),
            );
        }
    }
    if g.egress.db_port == 0 || g.egress.ports.contains(&0) {
        c.err("egress.ports", "port 0 is not a port");
    }
    c.issues
}

pub fn validate_all(sites: &[LoadedSite], g: &GlobalConfig) -> Vec<Issue> {
    let mut out = Vec::new();
    let file = |l: &LoadedSite| {
        l.path
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_default()
    };
    for l in sites {
        let stem = l.path.file_stem().map(|s| s.to_string_lossy().into_owned());
        for i in validate_site(&l.site, stem.as_deref()) {
            out.push(Issue {
                field: format!("{}: {}", file(l), i.field),
                message: i.message,
            });
        }
    }
    let mut by_name: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let mut by_id: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    let mut by_domain: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    // Effective DB identity (explicit, or the wp_/iwp_ defaults): two sites must never share
    // a database or a MariaDB account.
    let mut by_db_user: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut by_db_name: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for l in sites {
        by_name.entry(&l.site.name).or_default().push(file(l));
        by_id.entry(l.site.id).or_default().push(file(l));
        let d = &l.site.database;
        by_db_user
            .entry(
                d.user
                    .clone()
                    .unwrap_or_else(|| crate::host::db::db_user(&l.site.name)),
            )
            .or_default()
            .push(file(l));
        by_db_name
            .entry(
                d.name
                    .clone()
                    .unwrap_or_else(|| crate::host::db::db_name(&l.site.name)),
            )
            .or_default()
            .push(file(l));
        for d in &l.site.domains {
            by_domain.entry(d).or_default().push(file(l));
        }
    }
    for (i, a) in sites.iter().enumerate() {
        let pa = a.site.base_dir(g);
        for b in &sites[i + 1..] {
            let pb = b.site.base_dir(g);
            if pa.starts_with(&pb) || pb.starts_with(&pa) {
                out.push(Issue {
                    field: "sites".into(),
                    message: format!(
                        "base {} of {} overlaps {} of {}",
                        pa.display(),
                        file(a),
                        pb.display(),
                        file(b)
                    ),
                });
            }
        }
    }
    for l in sites {
        for m in &l.site.wpcli.mounts {
            for o in sites {
                let ob = o.site.base_dir(g);
                if m.starts_with(&ob) {
                    out.push(Issue {
                        field: format!("{}: wpcli.mounts", file(l)),
                        message: format!(
                            "{} is inside the base {} of {}",
                            m.display(),
                            ob.display(),
                            file(o)
                        ),
                    });
                }
            }
        }
    }
    for (k, files) in by_name.iter().filter(|(_, v)| v.len() > 1) {
        out.push(Issue {
            field: "sites".into(),
            message: format!("name {k:?} used by {}", files.join(", ")),
        });
    }
    for (k, files) in by_id.iter().filter(|(_, v)| v.len() > 1) {
        out.push(Issue {
            field: "sites".into(),
            message: format!("id {k} used by {}", files.join(", ")),
        });
    }
    for (k, files) in by_domain.iter().filter(|(_, v)| v.len() > 1) {
        out.push(Issue {
            field: "sites".into(),
            message: format!("domain {k} used by {}", files.join(", ")),
        });
    }
    for (what, map) in [("user", &by_db_user), ("name", &by_db_name)] {
        for (k, files) in map.iter().filter(|(_, v)| v.len() > 1) {
            out.push(Issue {
                field: "sites".into(),
                message: format!(
                    "database {what} {k:?} used by {} (sites must not share a database or a MariaDB account)",
                    files.join(", ")
                ),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ConstValue, LoadedSite, Package, Source, parse_site};

    fn base() -> Site {
        parse_site(include_str!("../../examples/acme.toml")).unwrap()
    }
    fn fields(site: &Site) -> Vec<String> {
        validate_site(site, Some(&site.name))
            .into_iter()
            .map(|i| i.field)
            .collect()
    }
    fn has(site: &Site, field_prefix: &str) -> bool {
        let f = fields(site);
        f.iter().any(|x| x.starts_with(field_prefix))
            || panic!("no issue for {field_prefix}; got {f:?}")
    }
    fn pkg(slug: &str) -> Package {
        Package {
            slug: slug.into(),
            version: Some("1.0".into()),
            source: None,
            sha256: None,
            writable: vec![],
            cache: vec![],
            mu: false,
            hold: false,
        }
    }

    #[test]
    fn examples_are_valid() {
        assert_eq!(fields(&base()), Vec::<String>::new());
        let s = parse_site(include_str!("../../examples/simple.toml")).unwrap();
        assert_eq!(fields(&s), Vec::<String>::new());
    }

    #[test]
    fn name_and_file_stem() {
        let mut s = base();
        assert!(
            validate_site(&s, Some("other"))
                .iter()
                .any(|i| i.field == "name")
        );
        s.name = "Bad_Name".into();
        assert!(has(&s, "name"));
    }

    #[test]
    fn limits() {
        let mut s = base(); // post_max_size 256M, memory_limit 256M
        s.limits.tmp_size = Some("1G".into());
        s.limits.memory = Some("2G".into());
        assert_eq!(fields(&s), Vec::<String>::new());
        // The default /tmp grows with post_max_size, so big-upload sites stay valid.
        s.php.upload_max_filesize = "2G".into();
        s.php.post_max_size = "2G".into();
        s.limits = Default::default();
        assert_eq!(fields(&s), Vec::<String>::new());
        assert_eq!(s.tmp_size(), "2G");
        s.php.cron = crate::config::CronMode::Cli;
        assert_eq!(fields(&s), Vec::<String>::new());
        s.php.upload_max_filesize = "256M".into();
        s.php.post_max_size = "256M".into();
        s.limits.tmp_size = Some("128M".into()); // an upload would not fit
        assert!(has(&s, "limits.tmp_size"));
        s.limits.tmp_size = Some("lots".into());
        assert!(has(&s, "limits.tmp_size"));
        s.limits.tmp_size = None;
        s.limits.memory = Some("1G".into()); // below the default 1G /tmp + one 256M worker
        assert!(has(&s, "limits.memory"));
        s.limits.memory = Some("2 G".into());
        assert!(has(&s, "limits.memory"));
    }

    #[test]
    fn id_range() {
        let mut s = base();
        s.id = 0;
        assert!(has(&s, "id"));
        s.id = 512;
        assert!(has(&s, "id"));
        s.id = 511;
        assert!(!fields(&s).contains(&"id".to_string()));
    }

    #[test]
    fn rejects_injection_in_domains() {
        for bad in [
            "evil.com;",
            "a.b\nlocation",
            "UPPER.hr",
            "no-tld",
            "x.hr ",
            "",
            "*.example.org",
        ] {
            let mut s = base();
            s.domains.push(bad.into());
            assert!(has(&s, "domains"), "{bad:?}");
        }
        let mut s = base();
        s.domains.push("www.example.org".into());
        assert!(has(&s, "domains"), "duplicate");
        s.domains.clear();
        assert!(has(&s, "domains"), "empty");
    }

    #[test]
    fn base_must_be_clean_absolute() {
        let mut s = base();
        s.base = Some("relative/x".into());
        assert!(has(&s, "base"));
        s.base = Some("/var/www/../etc".into());
        assert!(has(&s, "base"));
        for bad in [
            "/srv/a:/etc",
            "/srv/%h/x",
            "/srv/x\\",
            "/srv/a b",
            "/srv/\u{e4}",
            "/",
            "/srv//x/",
            "/srv/#x",
            "/srv/a*",
        ] {
            let mut s = base();
            s.base = Some(bad.into());
            assert!(has(&s, "base"), "{bad:?}");
        }
        let mut s = base();
        s.base = Some("/var/www/vhosts/example.org/iwp".into());
        assert!(!fields(&s).contains(&"base".to_string()));
    }

    #[test]
    fn source_path_is_allowlisted() {
        let mut s = base();
        let mut p = pkg("x");
        p.version = None;
        p.sha256 = Some("a".repeat(64));
        p.source = Some(Source::Path {
            path: "/srv/a:b".into(),
        });
        s.plugins.push(p);
        assert!(has(&s, "plugin[x].source"));
    }

    #[test]
    fn core_versions() {
        let mut s = base();
        s.core.php = "7.4".into();
        assert!(has(&s, "core.php"));
        let mut s = base();
        s.core.wordpress = "latest".into();
        assert!(has(&s, "core.wordpress"));
        let mut s = base();
        s.core.languages.push("hr;x".into());
        assert!(has(&s, "core.languages"));
    }

    #[test]
    fn multisite_path_and_ids_are_validated() {
        for (path, site_id, blog_id, bad) in [
            ("/", 1, 1, None),
            ("/net/", 2, 3, None),
            ("/a/b-c_d.e/", 1, 1, None),
            ("net/", 1, 1, Some("config.multisite.path")),
            ("/net", 1, 1, Some("config.multisite.path")),
            ("/n'et/", 1, 1, Some("config.multisite.path")),
            ("//", 1, 1, Some("config.multisite.path")),
            ("/", 0, 1, Some("config.multisite.site_id")),
            ("/", 1, 0, Some("config.multisite.blog_id")),
        ] {
            let mut s = base();
            let ms = s.config.multisite.as_mut().unwrap();
            ms.path = path.into();
            ms.site_id = site_id;
            ms.blog_id = blog_id;
            match bad {
                None => assert!(fields(&s).is_empty(), "{path}: {:?}", fields(&s)),
                Some(f) => assert!(has(&s, f), "{path}"),
            }
        }
    }

    #[test]
    fn multisite_rules() {
        let mut s = base();
        s.config.multisite.as_mut().unwrap().domain = "other.hr".into();
        assert!(has(&s, "config.multisite.domain"));
        let mut s = base();
        s.config.multisite.as_mut().unwrap().subdomain = false;
        assert!(has(&s, "config.multisite.subdomain"));
    }

    #[test]
    fn rejects_reserved_constants() {
        for name in [
            "DISALLOW_FILE_MODS",
            "DB_PASSWORD",
            "ABSPATH",
            "WP_CONTENT_DIR",
            "AUTH_KEY",
            "MULTISITE",
        ] {
            let mut s = base();
            s.config
                .constants
                .insert(name.into(), ConstValue::Bool(true));
            assert!(has(&s, &format!("config.constants.{name}")), "{name}");
        }
    }

    #[test]
    fn rejects_injection_in_constants() {
        let mut s = base();
        s.config
            .constants
            .insert("lower".into(), ConstValue::Int(1));
        assert!(has(&s, "config.constants.lower"));
        let mut s = base();
        s.config
            .constants
            .insert("X".into(), ConstValue::Str("a\n?><?php evil();".into()));
        assert!(has(&s, "config.constants.X"));
        let mut s = base();
        s.config
            .constants
            .insert("Y".into(), ConstValue::Str("it's fine".into()));
        assert!(
            !fields(&s)
                .iter()
                .any(|f| f.starts_with("config.constants.Y"))
        );
    }

    #[test]
    fn rejects_injection_in_php_settings() {
        let mut s = base();
        s.php.memory_limit = "256M\nauto_prepend_file=/x".into();
        assert!(has(&s, "php.memory_limit"));
        let mut s = base();
        s.php.upload_max_filesize = "0".into();
        assert!(has(&s, "php.upload_max_filesize"));
        let mut s = base();
        s.php.post_max_size = "1T".into();
        assert!(has(&s, "php.post_max_size"));
        let mut s = base();
        s.php.disable_functions.push("exec;".into());
        assert!(has(&s, "php.disable_functions"));
        let mut s = base();
        s.php.max_execution_time = 0;
        assert!(has(&s, "php.max_execution_time"));
        let mut s = base();
        s.php.fpm.max_children = 0;
        assert!(has(&s, "php.fpm"));
        let mut s = base();
        s.php.fpm.start_servers = 30;
        assert!(has(&s, "php.fpm"));
    }

    #[test]
    fn package_source_rules() {
        let h = "a".repeat(64);
        let mut s = base();
        let mut p = pkg("x");
        p.source = Some(Source::Url {
            url: "https://e/x.zip".into(),
        });
        p.sha256 = Some(h.clone());
        s.plugins.push(p);
        assert!(has(&s, "plugin[x]"), "both version and source");
        let mut s = base();
        let mut p = pkg("x");
        p.version = None;
        s.plugins.push(p);
        assert!(has(&s, "plugin[x]"), "neither");
        let mut s = base();
        let mut p = pkg("x");
        p.version = None;
        p.source = Some(Source::Path {
            path: "/srv/x".into(),
        });
        s.plugins.push(p);
        assert!(has(&s, "plugin[x].sha256"), "source without sha");
        let mut s = base();
        let mut p = pkg("x");
        p.sha256 = Some(h.clone());
        s.plugins.push(p);
        assert!(has(&s, "plugin[x].sha256"), "version with sha");
        let mut s = base();
        let mut p = pkg("x");
        p.version = None;
        p.sha256 = Some(h.clone());
        p.source = Some(Source::Git {
            git: "https://g/x.git".into(),
            rev: "abc".into(),
        });
        s.plugins.push(p);
        assert!(has(&s, "plugin[x].source"), "short rev");
        let mut s = base();
        let mut p = pkg("x");
        p.version = None;
        p.sha256 = Some(h.clone());
        p.source = Some(Source::Url {
            url: "http://e/x.zip".into(),
        });
        s.plugins.push(p);
        assert!(has(&s, "plugin[x].source"), "http url");
        let mut s = base();
        let mut p = pkg("x");
        p.version = None;
        p.sha256 = Some(h);
        p.source = Some(Source::Path {
            path: "rel/x".into(),
        });
        s.plugins.push(p);
        assert!(has(&s, "plugin[x].source"), "relative path");
    }

    #[test]
    fn package_slug_and_version_rules() {
        let mut s = base();
        s.plugins.push(pkg("../x"));
        assert!(has(&s, "plugin[../x].slug"));
        let mut s = base();
        s.plugins.push(pkg("gutena-tabs"));
        assert!(has(&s, "plugin[gutena-tabs]"), "duplicate");
        let mut s = base();
        let mut p = pkg("x");
        p.version = Some("1.0 ; rm".into());
        s.plugins.push(p);
        assert!(has(&s, "plugin[x].version"));
        let mut s = base();
        let mut t = pkg("t");
        t.mu = true;
        s.themes.push(t);
        assert!(has(&s, "theme[t].mu"));
    }

    #[test]
    fn verify_admins_are_logins() {
        let mut s = base();
        s.verify.admins = Some(vec!["alice".into(), "mara@example.org".into()]);
        assert!(fields(&s).is_empty());
        // An empty list: no administrator is expected.
        s.verify.admins = Some(vec![]);
        assert!(fields(&s).is_empty());
        for bad in ["", "a\nb", &"x".repeat(61)] {
            s.verify.admins = Some(vec![bad.to_string()]);
            assert!(has(&s, "verify.admins"), "{bad:?}");
        }
    }

    #[test]
    fn verify_allow_php_globs() {
        // acme declares wp-content/wflogs writable (Wordfence).
        let mut s = base();
        s.verify.allow_php = vec![
            "wp-content/wflogs/*.php".into(),
            "wp-content/wflogs/config?.php".into(),
            "wp-content/wflogs/sub/*/x.php".into(),
        ];
        assert_eq!(fields(&s), Vec::<String>::new());
        for bad in [
            "wp-content/other/*.php", // outside writable
            "wp-content/wflogs",      // the writable dir itself, not a path under it
            "wp-content/uploads/*.php",
            "wp-content/uploads/x/y.php",
            "/wp-content/wflogs/*.php",
            "wp-content/wflogs/../wflogs/x.php",
            "wp-content/wflogs/./x.php",
            "wp-content/wflogs//x.php",
            "wp-content/wflogs/",
            "wp-content/wflogs/[ab].php",
            "wp-content/wflogs/a b.php",
            "",
        ] {
            let mut s = base();
            s.verify.allow_php = vec![bad.into()];
            assert!(has(&s, "verify.allow_php"), "{bad:?}");
        }
    }

    #[test]
    fn allow_php_glob_matches_within_segments() {
        let re = allow_php_regex("wp-content/wflogs/*.php").unwrap();
        assert!(re.is_match("wp-content/wflogs/config.php"));
        assert!(re.is_match("wp-content/wflogs/.php"));
        assert!(!re.is_match("wp-content/wflogs/sub/config.php"));
        assert!(!re.is_match("wp-content/wflogs/config.php.bak"));
        assert!(!re.is_match("xwp-content/wflogs/config.php"));
        let re = allow_php_regex("wp-content/wflogs/a?.php").unwrap();
        assert!(re.is_match("wp-content/wflogs/ab.php"));
        assert!(!re.is_match("wp-content/wflogs/a/.php"));
        // `.` is literal.
        let re = allow_php_regex("wp-content/w/a.php").unwrap();
        assert!(!re.is_match("wp-content/w/aXphp"));
        assert!(allow_php_regex("wp-content/w/../x").is_none());
    }

    #[test]
    fn writable_and_cache_paths() {
        for bad in [
            "../etc",
            "/abs",
            "wp-content",
            "wp-content/plugins/x",
            "wp-content/uploads/x",
            "wp-content/wflogs/",
            "wp-content/a b",
            "wp-content/./x",
            "wp-content/x/../y",
        ] {
            let mut s = base();
            let mut p = pkg("x");
            p.writable = vec![bad.into()];
            s.plugins.push(p);
            assert!(has(&s, "plugin[x].writable"), "{bad:?}");
        }
        let mut s = base();
        let mut p = pkg("x");
        p.writable = vec!["wp-content/wflogs/sub".into()];
        s.plugins.push(p);
        assert!(
            has(&s, "plugin[x].writable"),
            "nested under wordfence's wp-content/wflogs"
        );
        let mut s = base();
        let mut p = pkg("x");
        p.writable = vec!["wp-content/cache".into()];
        p.cache = vec!["wp-content/other".into()];
        s.plugins.push(p);
        assert!(has(&s, "plugin[x].cache"), "cache outside writable");
        let mut s = base();
        let mut p = pkg("x");
        p.writable = vec!["wp-content/cache".into()];
        p.cache = vec!["wp-content/cache/pages".into()];
        s.plugins.push(p);
        assert!(!fields(&s).iter().any(|f| f.starts_with("plugin[x]")));
    }

    #[test]
    fn dropins() {
        let mut s = base();
        s.dropins.insert(
            "evil.php".into(),
            crate::config::Dropin {
                plugin: "wordfence".into(),
                file: "x.php".into(),
            },
        );
        assert!(has(&s, "dropins.evil.php"));
        let mut s = base();
        s.dropins.insert(
            "object-cache.php".into(),
            crate::config::Dropin {
                plugin: "missing".into(),
                file: "x.php".into(),
            },
        );
        assert!(has(&s, "dropins.object-cache.php"));
        let mut s = base();
        s.dropins.insert(
            "object-cache.php".into(),
            crate::config::Dropin {
                plugin: "wordfence".into(),
                file: "../x.php".into(),
            },
        );
        assert!(has(&s, "dropins.object-cache.php"));
    }

    #[test]
    fn entrypoints() {
        for bad in [
            "/wp-content/uploads/x.php",
            "/wp-content/wflogs/x.php",
            "/a/../b.php",
            "relative.php",
            "/x.php;",
            "/x.phtml",
            "/a//b.php",
        ] {
            let mut s = base();
            s.nginx.php_entrypoints = vec![bad.into()];
            assert!(has(&s, "nginx.php_entrypoints"), "{bad:?}");
        }
        let mut s = base();
        s.nginx.php_entrypoints = vec!["/wp-content/plugins/p/ajax.php".into()];
        assert!(!fields(&s).iter().any(|f| f.starts_with("nginx")));
    }

    #[test]
    fn validate_all_detects_collisions() {
        let a = base();
        let mut b = parse_site(include_str!("../../examples/simple.toml")).unwrap();
        b.id = a.id;
        b.domains = vec!["www.example.org".into()];
        let sites = vec![
            LoadedSite {
                path: "/etc/iwp/sites/acme.toml".into(),
                site: a,
            },
            LoadedSite {
                path: "/etc/iwp/sites/simple.toml".into(),
                site: b,
            },
        ];
        let issues = validate_all(&sites, &GlobalConfig::default());
        let text: Vec<String> = issues.iter().map(|i| i.to_string()).collect();
        assert!(
            text.iter().any(|t| t.contains("id 3")
                && t.contains("acme.toml")
                && t.contains("simple.toml")),
            "{text:?}"
        );
        assert!(
            text.iter()
                .any(|t| t.contains("www.example.org") && t.contains("simple.toml")),
            "{text:?}"
        );
    }

    #[test]
    fn validate_all_checks_file_stem() {
        let sites = vec![LoadedSite {
            path: "/etc/iwp/sites/wrong.toml".into(),
            site: base(),
        }];
        assert!(
            validate_all(&sites, &GlobalConfig::default())
                .iter()
                .any(|i| i.to_string().starts_with("wrong.toml: name"))
        );
    }

    #[test]
    fn entrypoints_reject_duplicates_and_fixed_locations() {
        let mut s = base();
        s.nginx.php_entrypoints = vec!["/a/x.php".into(), "/a/x.php".into()];
        assert!(has(&s, "nginx.php_entrypoints"), "duplicate");
        for fixed in [
            "/xmlrpc.php",
            "/wp-config.php",
            "/wp-config-sample.php",
            "/wp-cron.php",
        ] {
            let mut s = base();
            s.nginx.php_entrypoints = vec![fixed.into()];
            assert!(has(&s, "nginx.php_entrypoints"), "{fixed}");
        }
    }

    #[test]
    fn rejects_names_colliding_with_unit_suffixes() {
        for bad in ["foo-cron", "foo-verify"] {
            let mut s = base();
            s.name = bad.into();
            assert!(
                validate_site(&s, Some(bad))
                    .iter()
                    .any(|i| i.field == "name"),
                "{bad}"
            );
        }
        let mut s = base();
        s.name = "cronjobs".into();
        assert!(
            !validate_site(&s, Some("cronjobs"))
                .iter()
                .any(|i| i.field == "name")
        );
    }

    fn loaded(name: &str, id: u32, domain: &str, base: Option<&str>) -> LoadedSite {
        let mut s = parse_site(include_str!("../../examples/simple.toml")).unwrap();
        s.name = name.into();
        s.id = id;
        s.domains = vec![domain.into()];
        s.base = base.map(Into::into);
        LoadedSite {
            path: format!("/etc/iwp/sites/{name}.toml").into(),
            site: s,
        }
    }
    #[test]
    fn duplicate_effective_database_user_or_name_is_rejected() {
        let issues = |sites: &[LoadedSite]| -> Vec<String> {
            validate_all(sites, &GlobalConfig::default())
                .iter()
                .map(|i| i.to_string())
                .filter(|t| t.contains("database"))
                .collect()
        };
        let a = loaded("a", 1, "a.example.org", Some("/srv/a"));
        let mut b = loaded("b", 2, "b.example.org", Some("/srv/b"));
        assert!(issues(&[a.clone(), b.clone()]).is_empty());
        // b names a's default user explicitly.
        b.site.database.user = Some("iwp_a".into());
        let t = issues(&[a.clone(), b.clone()]);
        assert!(
            t.iter().any(|x| x.starts_with("sites: ")
                && x.contains("database user \"iwp_a\" used by a.toml, b.toml")),
            "{t:?}"
        );
        // Same for the database name.
        b.site.database.user = None;
        b.site.database.name = Some("wp_a".into());
        let t = issues(&[a.clone(), b.clone()]);
        assert!(
            t.iter()
                .any(|x| x.contains("database name \"wp_a\" used by a.toml, b.toml")),
            "{t:?}"
        );
        // Two explicit identical users.
        let mut a2 = a.clone();
        a2.site.database.user = Some("shared".into());
        b.site.database.name = None;
        b.site.database.user = Some("shared".into());
        assert_eq!(issues(&[a2, b]).len(), 1);
    }

    fn overlap_issues(sites: &[LoadedSite]) -> Vec<String> {
        validate_all(sites, &GlobalConfig::default())
            .iter()
            .map(|i| i.to_string())
            .filter(|t| t.contains("overlaps"))
            .collect()
    }

    const MINIMAL: &str = "name = \"simple\"\ndomains = [\"www.example.org\"]\nid = 1\n[core]\nwordpress = \"7.1.2\"\nphp = \"8.3\"\n";

    #[test]
    fn database_table_rules() {
        let ok = parse_site(&format!("{}\n[database]\nname = \"legacy_portal\"\nuser = \"iwp_legacy_info\"\nprefix = \"wp_\"\ncharset = \"utf8\"\ncollate = \"\"\n", MINIMAL)).unwrap();
        assert!(validate_site(&ok, None).is_empty());
        for (k, bad) in [
            ("name", "a-b"),
            ("user", "x;y"),
            ("prefix", "wp-"),
            ("charset", "latin1"),
            ("collate", "UTF8 bin"),
            ("name", ""),
        ] {
            let s = parse_site(&format!("{MINIMAL}\n[database]\n{k} = {bad:?}\n")).unwrap();
            let f: Vec<String> = validate_site(&s, None)
                .iter()
                .map(|i| i.field.clone())
                .collect();
            assert!(f.contains(&format!("database.{k}")), "{k}={bad}: {f:?}");
        }
    }

    #[test]
    fn wpcli_mounts_rules() {
        let ok = parse_site(&format!(
            "{MINIMAL}\n[wpcli]\nmounts = [\"/srv/iwp/migration\"]\n"
        ))
        .unwrap();
        assert!(validate_site(&ok, None).is_empty());
        for bad in [
            "relative/x",
            "/",
            "/etc",
            "/etc/iwp",
            "/usr/lib",
            "/run/x",
            "/proc",
            "/var/www/html",
            "/srv/../etc",
            "/srv/x/",
        ] {
            let s = parse_site(&format!("{MINIMAL}\n[wpcli]\nmounts = [{bad:?}]\n")).unwrap();
            assert!(!validate_site(&s, None).is_empty(), "{bad}");
        }
    }

    #[test]
    fn wpcli_mount_inside_site_base_rejected() {
        let mut a = loaded("a", 1, "a.example.org", Some("/srv/a"));
        let b = loaded("b", 2, "b.example.org", Some("/srv/b"));
        a.site.wpcli.mounts = vec!["/srv/b/shared".into()];
        let t: Vec<String> = validate_all(&[a, b], &GlobalConfig::default())
            .iter()
            .map(|i| i.to_string())
            .collect();
        assert!(
            t.iter().any(|x| x.starts_with("a.toml: wpcli.mounts")),
            "{t:?}"
        );
    }

    #[test]
    fn validate_all_rejects_equal_and_nested_bases() {
        let eq = [
            loaded("a", 1, "a.example.org", Some("/srv/x")),
            loaded("b", 2, "b.example.org", Some("/srv/x")),
        ];
        let t = overlap_issues(&eq);
        assert_eq!(t.len(), 1, "{t:?}");
        assert!(t[0].starts_with("sites: base /srv/x of a.toml overlaps /srv/x of b.toml"));
        let dflt = [
            loaded("a", 1, "a.example.org", Some("/var/www/vhosts/b")),
            loaded("b", 2, "b.example.org", None),
        ];
        assert_eq!(overlap_issues(&dflt).len(), 1);
        let nested = [
            loaded("a", 1, "a.example.org", Some("/srv/x")),
            loaded("b", 2, "b.example.org", Some("/srv/x/y")),
        ];
        assert_eq!(overlap_issues(&nested).len(), 1);
        let ok = [
            loaded("a", 1, "a.example.org", Some("/srv/x")),
            loaded("b", 2, "b.example.org", Some("/srv/xy")),
        ];
        assert!(overlap_issues(&ok).is_empty());
    }

    fn gwith(f: impl FnOnce(&mut GlobalConfig)) -> GlobalConfig {
        let mut g = GlobalConfig::default();
        f(&mut g);
        g
    }
    fn gfields(g: &GlobalConfig) -> Vec<String> {
        validate_global(g).into_iter().map(|i| i.field).collect()
    }

    #[test]
    fn validate_global_defaults_ok_and_rules() {
        assert!(gfields(&GlobalConfig::default()).is_empty());
        for bad in ["relative", "/a b", "/a/../b", "/a:b", "/"] {
            for field in ["base_root", "sites_dir", "cache_dir", "mariadb_socket"] {
                let g = gwith(|g| match field {
                    "base_root" => g.base_root = bad.into(),
                    "sites_dir" => g.sites_dir = bad.into(),
                    "cache_dir" => g.cache_dir = bad.into(),
                    _ => g.mariadb_socket = bad.into(),
                });
                assert!(gfields(&g).contains(&field.to_string()), "{field} {bad}");
            }
        }
        for bad in ["x;y", "", "Podman", "1net", "a b", &"a".repeat(33)] {
            let g = gwith(|g| g.podman_network = bad.into());
            assert!(gfields(&g).contains(&"podman_network".to_string()), "{bad}");
            let g = gwith(|g| g.nginx_group = bad.into());
            assert!(gfields(&g).contains(&"nginx_group".to_string()), "{bad}");
        }
        for bad in [0, 65_535, u32::MAX, u32::MAX - 512 * 65_536 + 1] {
            let g = gwith(|g| g.id_offset = bad);
            assert!(gfields(&g).contains(&"id_offset".to_string()), "{bad}");
        }
        for ok in [65_536, u32::MAX - 512 * 65_536] {
            let g = gwith(|g| g.id_offset = ok);
            assert!(gfields(&g).is_empty(), "{ok}");
        }
        let g = gwith(|g| g.keep_releases = 1);
        assert!(gfields(&g).contains(&"keep_releases".to_string()));
        let g = gwith(|g| g.keep_db_dumps = 0);
        assert!(gfields(&g).contains(&"keep_db_dumps".to_string()));
        let g = gwith(|g| g.alert_email = Some("ops+iwp@example.org".into()));
        assert!(gfields(&g).is_empty());
        for bad in ["ops", "a@b", "a@b.c\nBcc: x@y.z", "a b@c.d", "a@b.c, d@e.f"] {
            let g = gwith(|g| g.alert_email = Some(bad.into()));
            assert!(gfields(&g).contains(&"alert_email".to_string()), "{bad:?}");
        }
        let g = gwith(|g| g.egress.allow = vec!["10.1.2.3:389".into()]);
        assert!(gfields(&g).is_empty());
        let g = gwith(|g| g.egress.allow = vec!["ldap.example:389".into()]);
        assert!(gfields(&g).contains(&"egress.allow".to_string()));
        let g = gwith(|g| g.egress.ports = vec![443, 0]);
        assert!(gfields(&g).contains(&"egress.ports".to_string()));
    }

    #[test]
    fn post_max_size_at_least_upload_max_filesize() {
        let mut s = base();
        s.php.upload_max_filesize = "256M".into();
        s.php.post_max_size = "128M".into();
        assert!(has(&s, "php.post_max_size"));
        s.php.post_max_size = "1G".into();
        assert!(!fields(&s).iter().any(|f| f.starts_with("php.")));
        s.php.post_max_size = "262144K".into();
        assert!(!fields(&s).iter().any(|f| f.starts_with("php.")));
    }

    #[test]
    fn writable_must_not_collide_with_dropin_mount() {
        let mut s = base();
        let mut p = pkg("x");
        p.writable = vec!["wp-content/object-cache.php".into()];
        s.plugins.push(p);
        assert!(has(&s, "plugin[x].writable"));
    }

    #[test]
    fn shared_rel_strips_prefix() {
        assert_eq!(shared_rel("wp-content/wflogs"), "wflogs");
        assert_eq!(shared_rel("wp-content/cache/wp-rocket"), "cache/wp-rocket");
    }

    #[test]
    fn mu_requires_single_php_path_source() {
        let h = "a".repeat(64);
        let mk = |src: Source| Package {
            slug: "m".into(),
            version: None,
            source: Some(src),
            sha256: Some(h.clone()),
            writable: vec![],
            cache: vec![],
            mu: true,
            hold: false,
        };
        let mut s = base();
        s.plugins.push(mk(Source::Path {
            path: "/srv/iwp/src/m".into(),
        }));
        assert!(has(&s, "plugin[m].mu"));
        let mut s = base();
        s.plugins.push(mk(Source::Url {
            url: "https://e/m.php".into(),
        }));
        assert!(has(&s, "plugin[m].mu"));
        for bad in ["/srv/x.PHP", "/srv/.php"] {
            let mut s = base();
            s.plugins.push(mk(Source::Path { path: bad.into() }));
            assert!(has(&s, "plugin[m].mu"), "{bad}");
        }
        let mut s = base();
        s.plugins.push(mk(Source::Path {
            path: "/srv/iwp/src/m.php".into(),
        }));
        assert!(!fields(&s).iter().any(|f| f.starts_with("plugin[m]")));
        let mut s = base();
        let mut p = pkg("m");
        p.mu = true;
        s.plugins.push(p);
        assert!(
            has(&s, "plugin[m].mu"),
            "wordpress.org mu not supported in v1"
        );
    }

    #[test]
    fn mu_plugin_named_iwp_is_reserved() {
        let mut s = base();
        s.plugins.push(Package {
            slug: "iwp".into(),
            version: None,
            source: Some(Source::Path {
                path: "/srv/iwp/src/iwp.php".into(),
            }),
            sha256: Some("a".repeat(64)),
            writable: vec![],
            cache: vec![],
            mu: true,
            hold: false,
        });
        let issues = validate_site(&s, None);
        let i = issues
            .iter()
            .find(|i| i.field == "plugin[iwp].slug")
            .expect("reserved slug issue");
        assert!(i.message.contains("the mu-plugin name `iwp` is reserved"));
        // a regular (non-mu) plugin called iwp stays legal
        let mut s = base();
        s.plugins.push(pkg("iwp"));
        assert!(!fields(&s).iter().any(|f| f.starts_with("plugin[iwp]")));
    }

    #[test]
    fn git_host_must_start_alphanumeric() {
        let check = |git: &str| {
            let mut s = base();
            let mut p = pkg("g");
            p.version = None;
            p.sha256 = Some("a".repeat(64));
            p.source = Some(Source::Git {
                git: git.into(),
                rev: "b".repeat(40),
            });
            s.plugins.push(p);
            fields(&s).iter().any(|f| f.starts_with("plugin[g].source"))
        };
        for bad in [
            "git@-evil.example.org:repo",
            "https://-evil.example.org/repo",
            "git@.evil:repo",
        ] {
            assert!(check(bad), "{bad} must be rejected");
        }
        for good in [
            "git@github.com:org/repo.git",
            "https://github.com/org/repo.git",
            "https://git.example.org:8443/x/y",
        ] {
            assert!(!check(good), "{good} must be accepted");
        }
    }
}
