use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct GlobalConfig {
    pub sites_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub base_root: PathBuf,
    pub keep_releases: u32,
    pub keep_db_dumps: u32,
    pub podman_network: String,
    pub mariadb_socket: PathBuf,
    pub nginx_group: String,
    pub id_offset: u32,
    /// Where failed `iwp-update` and `iwp-<site>-verify` runs are mailed (through the host's
    /// `sendmail`); unset: no mail, the units only fail.
    pub alert_email: Option<String>,
    pub egress: EgressConfig,
}

/// What the site containers may connect to (`iwp egress apply`).
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct EgressConfig {
    /// Filter connections leaving `podman_network`'s subnet: the host only on the MariaDB
    /// port and DNS, private and link-local networks not at all, the internet on `ports`.
    pub restrict: bool,
    /// TCP ports allowed towards public addresses.
    pub ports: Vec<u16>,
    /// The port MariaDB listens on at the network's gateway.
    pub db_port: u16,
    /// Extra destinations, exempt from the rules above: "<ipv4>[/<prefix>]:<tcp port>", e.g.
    /// an internal LDAP or SMTP server.
    pub allow: Vec<String>,
}

impl Default for EgressConfig {
    fn default() -> Self {
        Self {
            restrict: false,
            ports: vec![80, 443, 465, 587],
            db_port: 3306,
            allow: Vec::new(),
        }
    }
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            sites_dir: "/etc/iwp/sites".into(),
            cache_dir: "/var/cache/iwp".into(),
            base_root: "/var/www/vhosts".into(),
            keep_releases: 5,
            keep_db_dumps: 10,
            podman_network: "podman".into(),
            mariadb_socket: "/var/lib/mysql/mysql.sock".into(),
            nginx_group: "nginx".into(),
            id_offset: 100_000,
            alert_email: None,
            egress: EgressConfig::default(),
        }
    }
}

pub const DEFAULT_GLOBAL_PATH: &str = "/etc/iwp/iwp.toml";

/// Explicit path must exist. With `None`, reads DEFAULT_GLOBAL_PATH if present, else defaults.
pub fn load_global(path: Option<&Path>) -> Result<GlobalConfig> {
    let (path, required) = match path {
        Some(p) => (p.to_path_buf(), true),
        None => (PathBuf::from(DEFAULT_GLOBAL_PATH), false),
    };
    if !required && !path.exists() {
        return Ok(GlobalConfig::default());
    }
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}
