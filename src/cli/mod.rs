use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};

use crate::config::edit::{PackageKind, edit_site_file, parse_spec};
use crate::config::{
    GlobalConfig, LoadedSite, Site, load_global, load_sites_dir, validate_all,
    validate_core_versions, validate_global,
};
use crate::host::image::{PodmanImages, cli_tag, fpm_tag};
use crate::host::{Host, SystemHost};
use crate::render::{RenderEnv, render_site};

pub use crate::error::UsageError;

mod assets;
mod build;
mod host;
mod image;
mod import;
mod lifecycle;
mod sitefile;
mod status;
mod verify;
mod wp;

#[derive(Debug, Parser)]
#[command(name = "iwp", version, about = "Immutable WordPress hosting tool")]
pub struct Cli {
    /// Global config file (default: /etc/iwp/iwp.toml if it exists, else built-in defaults)
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Edit plugin entries in a site file
    Plugin(PackageArgs),
    /// Edit theme entries in a site file
    Theme(PackageArgs),
    /// Validate site files (all, or the named ones; uniqueness is always checked across all)
    Validate { sites: Vec<String> },
    /// Render all generated files for a site into a directory (no host changes)
    Render {
        site: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "10.88.0.1")]
        db_host_ip: std::net::Ipv4Addr,
    },
    /// Print the JSON Schema for site files
    Schema,
    /// Build a verified release directory for a site (does not activate it)
    Build { site: String },
    /// Record sha256 pins for `source` packages (all, or one slug)
    Pin { site: String, slug: Option<String> },
    /// Show available updates for core, plugins and themes (read-only)
    Outdated {
        site: String,
        #[arg(long)]
        json: bool,
    },
    /// Move sites to newer wordpress.org core, plugin and theme versions and deploy them
    /// (smoke test and automatic rollback as with `deploy`; the site file is only rewritten once
    /// the new versions are live)
    Update {
        site: Option<String>,
        /// Every site that has not opted out with `[update] auto = false`
        #[arg(long)]
        all: bool,
        /// Show what would change without touching anything
        #[arg(long)]
        dry_run: bool,
        /// Rebuild the images on a freshly pulled PHP base first; sites whose image changed are redeployed
        #[arg(long)]
        refresh_base: bool,
    },
    /// Build, list or prune container images
    Image {
        #[command(subcommand)]
        action: ImageAction,
    },
    /// Install and test the nginx include for a site, or check server blocks use it
    Nginx {
        #[command(subcommand)]
        action: NginxAction,
    },
    /// Dump or restore a site's database
    Db {
        #[command(subcommand)]
        action: DbAction,
    },
    /// Outbound filter for the site containers ([egress] in iwp.toml)
    Egress {
        #[command(subcommand)]
        action: EgressAction,
    },
    /// Mail the journal of a failed iwp unit to `alert_email` (run by iwp-alert@.service)
    Alert { unit: String },
    /// SELinux policy module management
    Selinux {
        #[command(subcommand)]
        action: SelinuxAction,
    },
    /// Create a new site file (next free id) and provision the host for it
    New {
        site: String,
        #[arg(long = "domain", required = true)]
        domains: Vec<String>,
        #[arg(long)]
        base: Option<PathBuf>,
        /// WordPress version (default: latest from wordpress.org)
        #[arg(long)]
        wordpress: Option<String>,
        #[arg(long, default_value = "8.3")]
        php: String,
        /// Import the 8 keys/salts from an existing wp-config.php
        #[arg(long)]
        salts_from: Option<PathBuf>,
    },
    /// Adopt an existing classic WordPress webroot: write a site file, pin copies of custom
    /// code, provision the database user and secrets and copy the uploads (never deploys and
    /// never writes under --from)
    Import {
        site: String,
        /// The old WordPress root (the directory holding wp-includes/)
        #[arg(long)]
        from: PathBuf,
        /// Domains (default: DOMAIN_CURRENT_SITE of a multisite)
        #[arg(long = "domain")]
        domains: Vec<String>,
        #[arg(long)]
        base: Option<PathBuf>,
        #[arg(long, default_value = "8.3")]
        php: String,
        /// Create iwp_<site> with a generated password instead of reusing the old DB user name
        #[arg(long)]
        new_db_user: bool,
        /// Site id (1..=511) instead of the next free one; its UID range must not overlap
        /// /etc/subuid or /etc/subgid
        #[arg(long)]
        id: Option<u32>,
        /// Print the import report as JSON
        #[arg(long)]
        json: bool,
    },
    /// Provision (or re-provision) the host for an existing site file; idempotent
    Setup {
        site: String,
        #[arg(long)]
        salts_from: Option<PathBuf>,
    },
    /// Build, back up, activate and smoke-test a new release (auto-rollback on failure)
    Deploy {
        site: String,
        #[arg(long)]
        dry_run: bool,
    },
    /// Re-activate an earlier release (default: the previous one)
    Rollback {
        site: String,
        release: Option<String>,
        /// Also restore the database snapshot taken when the current release was deployed (needs --yes)
        #[arg(long)]
        with_db: bool,
        #[arg(long)]
        yes: bool,
    },
    /// Run wp-cli in the site's cli container (code-changing commands are refused).
    /// For wp-cli's own help use `iwp wp <site> help <command>`; `--help` shows iwp's.
    Wp {
        site: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        args: Vec<String>,
    },
    /// Open a shell in the site's cli container
    Shell { site: String },
    /// Run due wp-cron events (every subsite on multisite)
    Cron { site: String },
    /// Show state, releases and image of sites (read-only)
    Status {
        site: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Check the live site against its release manifest and wordpress.org core checksums
    /// (read-only; exit 0 clean, 3 findings, 1 check failed)
    Verify {
        site: String,
        #[arg(long)]
        json: bool,
    },
    /// List a site's releases (read-only)
    Releases { site: String },
    /// Remove old releases and database dumps beyond the configured retention
    Gc { site: String },
    /// Work with the files compiled into iwp (Containerfile, templates, mu-plugin, SELinux policy)
    Assets {
        #[command(subcommand)]
        action: AssetsAction,
    },
}

#[derive(Debug, Subcommand)]
pub enum AssetsAction {
    /// Write the embedded share/ trees under <dir> (absent or empty; needs no root)
    Export { dir: PathBuf },
}

#[derive(Debug, Subcommand)]
pub enum NginxAction {
    /// Render and install the nginx include, reloading nginx if it changed
    Apply { site: String },
    /// Check that every server block for the site's domains uses the include (read-only)
    Check { site: String },
}

#[derive(Debug, Subcommand)]
pub enum DbAction {
    /// Dump the site database to a gzipped SQL file
    Dump {
        site: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Restore the site database from a dump (overwrites it)
    Restore {
        site: String,
        file: PathBuf,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum EgressAction {
    /// Load the nftables filter described by [egress], or remove it when restrict = false
    Apply,
    /// Print the ruleset `apply` would load (needs podman to read the network)
    Show,
}

#[derive(Debug, Subcommand)]
pub enum SelinuxAction {
    /// Install or update the iwp SELinux policy module
    Install,
}

#[derive(Debug, Subcommand)]
pub enum ImageAction {
    /// Build the fpm and cli images for a WordPress/PHP version
    Build {
        wordpress: String,
        php: String,
        /// Pull the PHP base image even if present
        #[arg(long)]
        refresh_base: bool,
    },
    /// List iwp images and which sites use them
    List,
    /// Remove iwp images no site file references
    Prune,
}

#[derive(Debug, Args)]
pub struct PackageArgs {
    #[command(subcommand)]
    pub action: PackageAction,
}

#[derive(Debug, Subcommand)]
pub enum PackageAction {
    /// Add a wordpress.org package: <site> <slug>@<version>
    Add { site: String, spec: String },
    /// Change the pinned version: <site> <slug>@<version>
    Set { site: String, spec: String },
    /// Remove a package: <site> <slug>
    Rm { site: String, slug: String },
}

pub fn run(args: Vec<OsString>) -> ExitCode {
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(e) => {
            let _ = e.print();
            return if e.use_stderr() {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            };
        }
    };
    match dispatch(cli) {
        Ok(code) => code,
        Err(e) => {
            if let Some(UsageError(msg)) = e.downcast_ref::<UsageError>() {
                if msg.contains('\n') {
                    eprintln!("error: invalid site files:");
                    for line in msg.lines() {
                        eprintln!("  {line}");
                    }
                } else {
                    eprintln!("error: {msg}");
                }
                ExitCode::from(2)
            } else {
                eprintln!("error: {e:#}");
                ExitCode::from(1)
            }
        }
    }
}

fn dispatch(cli: Cli) -> Result<ExitCode> {
    // Needs neither the global config nor root.
    if let Command::Assets { action } = cli.command {
        return assets::assets_cmd(action);
    }
    let global = load_global(cli.config.as_deref())?;
    match cli.command {
        Command::Plugin(a) => sitefile::package(&global.sites_dir, PackageKind::Plugin, a.action),
        Command::Theme(a) => sitefile::package(&global.sites_dir, PackageKind::Theme, a.action),
        Command::Validate { sites } => sitefile::validate_cmd(&global, &sites),
        Command::Render {
            site,
            out,
            db_host_ip,
        } => sitefile::render_cmd(&global, &site, &out, db_host_ip),
        Command::Image { action } => image::image_cmd(&global, action),
        Command::Update {
            site,
            all,
            dry_run,
            refresh_base,
        } => lifecycle::update_cmd(&global, site.as_deref(), all, dry_run, refresh_base),
        Command::Nginx { action } => host::nginx_cmd(&global, action),
        Command::Db { action } => host::db_cmd(&global, action),
        Command::Selinux { action } => host::selinux_cmd(action),
        Command::Egress { action } => host::egress_cmd(&global, action),
        Command::Alert { unit } => host::alert_cmd(&global, &unit),
        Command::Build { site } => build::build_cmd(&global, &site),
        Command::Pin { site, slug } => sitefile::pin_cmd(&global, &site, slug.as_deref()),
        Command::Outdated { site, json } => build::outdated_cmd(&global, &site, json),
        Command::New {
            site,
            domains,
            base,
            wordpress,
            php,
            salts_from,
        } => lifecycle::new_cmd(
            &global,
            &site,
            &domains,
            base.as_deref(),
            wordpress,
            &php,
            salts_from.as_deref(),
        ),
        Command::Import {
            site,
            from,
            domains,
            base,
            php,
            new_db_user,
            id,
            json,
        } => import::import_cmd(
            &global,
            import::Opts {
                site,
                from,
                domains,
                base,
                php,
                new_db_user,
                id,
                json,
            },
        ),
        Command::Setup { site, salts_from } => {
            lifecycle::setup_cmd(&global, &site, salts_from.as_deref())
        }
        Command::Deploy { site, dry_run } => lifecycle::deploy_cmd(&global, &site, dry_run),
        Command::Rollback {
            site,
            release,
            with_db,
            yes,
        } => lifecycle::rollback_cmd(&global, &site, release.as_deref(), with_db, yes),
        Command::Wp { site, args } => wp::wp_cmd(&global, &site, Some(&args)),
        Command::Shell { site } => wp::wp_cmd(&global, &site, None),
        Command::Cron { site } => wp::cron_cmd(&global, &site),
        Command::Status { site, json } => status::status_cmd(&global, site.as_deref(), json),
        Command::Verify { site, json } => verify::verify_cmd(&global, &site, json),
        Command::Releases { site } => status::releases_cmd(&global, &site),
        Command::Gc { site } => lifecycle::gc_cmd(&global, &site),
        Command::Assets { .. } => unreachable!("dispatched above"),
        Command::Schema => {
            let schema = schemars::schema_for!(crate::config::Site);
            println!("{}", serde_json::to_string_pretty(&schema)?);
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// Rejects anything that is not a valid site name before it can reach a path.
pub fn site_arg(s: &str) -> Result<&str> {
    if crate::config::validate::valid_site_name(s) {
        Ok(s)
    } else {
        Err(UsageError(format!(
            "invalid site name {s:?} (must match ^[a-z][a-z0-9-]{{0,30}}$)"
        ))
        .into())
    }
}

fn site_path(sites_dir: &std::path::Path, site: &str) -> Result<PathBuf> {
    let site = site_arg(site)?;
    let p = sites_dir.join(format!("{site}.toml"));
    if !p.is_file() {
        return Err(UsageError(format!("no site file {}", p.display())).into());
    }
    Ok(p)
}

/// Loads all sites and fails with UsageError listing every issue relevant to `only` (all if empty).
fn load_valid_sites(global: &GlobalConfig, only: &[String]) -> Result<Vec<LoadedSite>> {
    for name in only {
        site_arg(name)?;
    }
    let global_issues: Vec<String> = validate_global(global)
        .into_iter()
        .map(|i| format!("iwp.toml: {i}"))
        .collect();
    if !global_issues.is_empty() {
        return Err(UsageError(global_issues.join("\n")).into());
    }
    let sites = load_sites_dir(&global.sites_dir).map_err(|e| UsageError(format!("{e:#}")))?;
    for name in only {
        if !sites
            .iter()
            .any(|l| l.path.file_stem().is_some_and(|s| s == name.as_str()))
        {
            return Err(UsageError(format!(
                "no site file {}/{name}.toml",
                global.sites_dir.display()
            ))
            .into());
        }
    }
    let issues: Vec<String> = validate_all(&sites, global)
        .into_iter()
        .map(|i| i.to_string())
        .filter(|t| {
            only.is_empty()
                || t.starts_with("sites:")
                || only.iter().any(|n| t.starts_with(&format!("{n}.toml:")))
        })
        .collect();
    if !issues.is_empty() {
        return Err(UsageError(issues.join("\n")).into());
    }
    Ok(sites)
}

fn require_root(host: &dyn Host, what: &str) -> Result<()> {
    if host.is_root() {
        Ok(())
    } else {
        Err(UsageError(format!("iwp {what} must be run as root")).into())
    }
}

fn loaded_site<'a>(sites: &'a [LoadedSite], name: &str) -> &'a Site {
    &sites
        .iter()
        .find(|l| l.site.name == name)
        .expect("validated")
        .site
}

fn timestamp() -> String {
    jiff::Timestamp::now().strftime("%Y%m%d-%H%M%S").to_string()
}

fn backups_dir(global: &GlobalConfig, site: &Site) -> Result<PathBuf> {
    let dir = site.base_dir(global).join("backups");
    if !dir.is_dir() {
        anyhow::bail!(
            "{} does not exist; the site is not set up yet (`iwp new` creates it)",
            dir.display()
        );
    }
    Ok(dir)
}

fn absolute(p: PathBuf) -> Result<PathBuf> {
    if p.is_absolute() {
        Ok(p)
    } else {
        Ok(std::env::current_dir()?.join(p))
    }
}

fn print_warnings(warnings: &[String]) {
    for w in warnings {
        eprintln!("warning: {w}");
    }
}
