//! What happens to a site over time: setup, deploy and rollback, updates, wp-cli and cron.

pub mod deploy;
pub mod fcgi;
pub mod import;
pub mod outdated;
pub mod releases;
pub mod setup;
pub mod update;
pub mod verify;
pub mod wpcli;
