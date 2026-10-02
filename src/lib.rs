pub mod build;
pub mod cli;
pub mod config;
pub mod error;
pub mod fetch;
pub mod hash;
pub mod host;
pub mod lifecycle;
pub mod render;
#[cfg(test)]
pub mod testutil;

/// Where the generated systemd units find iwp. Packages that install it elsewhere set
/// `IWP_BIN_PATH` at build time (the RPM: /usr/bin/iwp).
pub const BIN_PATH: &str = match option_env!("IWP_BIN_PATH") {
    Some(p) => p,
    None => "/usr/local/bin/iwp",
};
