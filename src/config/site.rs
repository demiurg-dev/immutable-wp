use std::collections::BTreeMap;
use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::GlobalConfig;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Site {
    /// Site name: ^[a-z][a-z0-9-]{0,30}$; must equal the file stem.
    pub name: String,
    /// Base directory; default <base_root>/<name>.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<PathBuf>,
    /// Domains served by this site (used for the nginx include comment and smoke tests).
    pub domains: Vec<String>,
    /// Host-unique slot 1..=511; determines UID/GID range and SELinux categories.
    pub id: u32,
    pub core: Core,
    #[serde(default)]
    pub config: WpConfig,
    #[serde(default)]
    pub php: PhpSettings,
    #[serde(default, rename = "plugin", skip_serializing_if = "Vec::is_empty")]
    pub plugins: Vec<Package>,
    #[serde(default, rename = "theme", skip_serializing_if = "Vec::is_empty")]
    pub themes: Vec<Package>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dropins: BTreeMap<String, Dropin>,
    #[serde(default)]
    pub nginx: NginxSettings,
    #[serde(default, skip_serializing_if = "is_default")]
    pub database: DatabaseSettings,
    #[serde(default, skip_serializing_if = "is_default")]
    pub wpcli: WpcliSettings,
    #[serde(default, skip_serializing_if = "is_default")]
    pub limits: LimitSettings,
    #[serde(default, skip_serializing_if = "is_default")]
    pub update: UpdateSettings,
    #[serde(default, skip_serializing_if = "is_default")]
    pub verify: VerifySettings,
}

fn is_default<T: Default + PartialEq>(t: &T) -> bool {
    *t == T::default()
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Core {
    pub wordpress: String,
    pub php: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub languages: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WpConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multisite: Option<Multisite>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub constants: BTreeMap<String, ConstValue>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Multisite {
    /// Only subdomain installs are supported in v1.
    pub subdomain: bool,
    /// DOMAIN_CURRENT_SITE; must be one of `domains`.
    pub domain: String,
    /// PATH_CURRENT_SITE; default "/". Starts and ends with `/`; segments of
    /// `A-Za-z0-9._~-` not starting with `.`.
    #[serde(
        default = "default_multisite_path",
        skip_serializing_if = "is_default_multisite_path"
    )]
    pub path: String,
    /// SITE_ID_CURRENT_SITE; default 1 (a positive integer).
    #[serde(default = "one", skip_serializing_if = "is_one")]
    pub site_id: u32,
    /// BLOG_ID_CURRENT_SITE; default 1 (a positive integer).
    #[serde(default = "one", skip_serializing_if = "is_one")]
    pub blog_id: u32,
}

fn default_multisite_path() -> String {
    "/".into()
}
fn is_default_multisite_path(p: &str) -> bool {
    p == "/"
}
fn one() -> u32 {
    1
}
fn is_one(n: &u32) -> bool {
    *n == 1
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(untagged)]
pub enum ConstValue {
    Bool(bool),
    Int(i64),
    Str(String),
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct PhpSettings {
    pub memory_limit: String,
    pub upload_max_filesize: String,
    pub post_max_size: String,
    pub max_execution_time: u32,
    pub disable_functions: Vec<String>,
    pub fpm: FpmSettings,
    /// How the cron timer runs WP-Cron: "fpm" (default; a request to wp-cron.php over the FPM
    /// socket, bounded by max_execution_time like any request) or "cli" (wp-cli in its own
    /// container, no time limit; for sites with long-running events). Networks always use cli.
    pub cron: CronMode,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CronMode {
    #[default]
    Fpm,
    Cli,
}

impl Default for PhpSettings {
    fn default() -> Self {
        Self {
            memory_limit: "256M".into(),
            upload_max_filesize: "64M".into(),
            post_max_size: "64M".into(),
            max_execution_time: 120,
            disable_functions: [
                "exec",
                "shell_exec",
                "system",
                "passthru",
                "proc_open",
                "popen",
            ]
            .map(String::from)
            .to_vec(),
            fpm: FpmSettings::default(),
            cron: CronMode::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct FpmSettings {
    pub max_children: u32,
    pub start_servers: u32,
    pub min_spare: u32,
    pub max_spare: u32,
}

impl Default for FpmSettings {
    fn default() -> Self {
        Self {
            max_children: 10,
            start_servers: 2,
            min_spare: 1,
            max_spare: 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub slug: String,
    /// wordpress.org version (mutually exclusive with `source`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    /// Required with `source`: archive SHA-256 (url) or tree hash (path/git).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Extra writable dirs under wp-content/ (moved to shared/, PHP denied by nginx).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub writable: Vec<String>,
    /// Cache dirs (must be inside a writable dir); emptied on deploy.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cache: Vec<String>,
    /// Install into mu-plugins/ (plugins only).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub mu: bool,
    /// Keep this version: `iwp update` leaves the package alone and never reports it as
    /// overdue (wordpress.org packages) or due for review (`source` packages).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub hold: bool,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(untagged, deny_unknown_fields)]
pub enum Source {
    Path { path: PathBuf },
    Git { git: String, rev: String },
    Url { url: String },
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Dropin {
    pub plugin: String,
    pub file: String,
}

#[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NginxSettings {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub php_entrypoints: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DatabaseSettings {
    /// Existing or new database name; default wp_<site with - → _>. ^[A-Za-z0-9_]{1,64}$
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// MariaDB user iwp creates/updates at the podman subnet; default iwp_<site>. Never an
    /// account another application uses. ^[A-Za-z0-9_]{1,64}$
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// $table_prefix; default "wp_". ^[A-Za-z0-9_]+$
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// DB_CHARSET: utf8mb4 (default), utf8 or utf8mb3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub charset: Option<String>,
    /// DB_COLLATE; default "". ^[a-z0-9_]*$
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collate: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WpcliSettings {
    /// Host directories mounted read-only at the same path for `iwp wp`/`iwp shell` only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<PathBuf>,
}

/// What `iwp update` may change in this site file.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct UpdateSettings {
    /// Include this site in `iwp update --all` (the update timer); default true.
    pub auto: bool,
    /// Core updates: "minor" (default; patch releases of the current x.y branch), "major"
    /// (the latest release) or "none".
    pub core: CorePolicy,
    /// Plugin and theme updates: "minor" (default; only versions with the same first number,
    /// e.g. 4.2 -> 4.9 but not 4.9 -> 5.0; versions that are not plain dotted numbers count as
    /// major), "major" (the latest release) or "none". Plugin database migrations run on the
    /// first request after a deploy and are not undone by a code rollback.
    pub plugins: PackagePolicy,
    /// Days an update that `iwp update` does not take on its own (a major one, or one that
    /// needs a newer PHP or WordPress) may stay available before the run fails because of it;
    /// default 30, 0: never. `hold = true` on the package accepts its version.
    pub overdue_days: u32,
    /// Days a `source` package (path, git, url: iwp cannot look for its updates) may keep the
    /// same pin before the run fails and asks for a review; default 90, 0: never.
    /// `hold = true` on the package accepts it as it is.
    pub source_review_days: u32,
}

impl Default for UpdateSettings {
    fn default() -> Self {
        Self {
            auto: true,
            core: CorePolicy::Minor,
            plugins: PackagePolicy::Minor,
            overdue_days: 30,
            source_review_days: 90,
        }
    }
}

/// What `iwp verify` accepts.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VerifySettings {
    /// PHP-like files (`*.php`, `.htaccess`, ...) that may exist in shared data, as globs relative
    /// to the WordPress root (`*` and `?` match within one path segment), e.g.
    /// "wp-content/wflogs/*.php" for Wordfence. Each must lie under a declared writable path;
    /// wp-content/uploads can never be allowlisted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_php: Vec<String>,
    /// Logins of the accounts that may be administrators (on a network: of any site, and the
    /// super admins). When set, `iwp verify` reports every other administrator as a finding;
    /// unset, it only lists them. Read from the site file, not the deployed snapshot, so a
    /// change needs no deploy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admins: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum PackagePolicy {
    None,
    #[default]
    Minor,
    Major,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CorePolicy {
    None,
    #[default]
    Minor,
    Major,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LimitSettings {
    /// Size of the container's /tmp (a tmpfs, so it counts against `memory`); default "1G", or
    /// php.post_max_size when that is larger. Must hold a request body: >= php.post_max_size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tmp_size: Option<String>,
    /// Memory ceiling of the site's container (systemd MemoryMax); default
    /// php.fpm.max_children x php.memory_limit + tmp_size + 384M.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
}

pub const DEFAULT_TMP_SIZE: &str = "1G";
/// Opcache, the FPM master and page cache headroom on top of the workers and /tmp.
const MEMORY_OVERHEAD: u64 = 384 << 20;

impl Site {
    /// `limits.tmp_size`, or by default 1G, or php.post_max_size when that is larger (request
    /// bodies are buffered in /tmp).
    pub fn tmp_size(&self) -> String {
        use super::validate::size_bytes;
        if let Some(t) = &self.limits.tmp_size {
            return t.clone();
        }
        let post = &self.php.post_max_size;
        if size_bytes(post) > size_bytes(DEFAULT_TMP_SIZE) {
            post.clone()
        } else {
            DEFAULT_TMP_SIZE.to_string()
        }
    }
    /// `MemoryMax` in MiB (rounded up). The site must be validated.
    pub fn memory_max_mib(&self) -> u64 {
        use super::validate::size_bytes;
        let bytes = match self.limits.memory.as_deref().and_then(size_bytes) {
            Some(b) => b,
            None => u64::from(self.php.fpm.max_children)
                .saturating_mul(size_bytes(&self.php.memory_limit).unwrap_or(0))
                .saturating_add(size_bytes(&self.tmp_size()).unwrap_or(0))
                .saturating_add(MEMORY_OVERHEAD),
        };
        bytes.div_ceil(1 << 20)
    }
    pub fn db_prefix(&self) -> &str {
        self.database.prefix.as_deref().unwrap_or("wp_")
    }
    pub fn base_dir(&self, g: &GlobalConfig) -> PathBuf {
        self.base
            .clone()
            .unwrap_or_else(|| g.base_root.join(&self.name))
    }
    pub fn fpm_image(&self) -> String {
        format!(
            "localhost/iwp-fpm:{}-php{}",
            self.core.wordpress, self.core.php
        )
    }
    pub fn cli_image(&self) -> String {
        format!(
            "localhost/iwp-cli:{}-php{}",
            self.core.wordpress, self.core.php
        )
    }
    /// All declared writable paths, in plugin order then declaration order.
    pub fn writable_paths(&self) -> Vec<&str> {
        self.plugins
            .iter()
            .chain(self.themes.iter())
            .flat_map(|p| p.writable.iter().map(String::as_str))
            .collect()
    }
}
