//! `iwp import`.

use super::*;
use crate::lifecycle::import::{DEFAULT_SRC_ROOT, ImportArgs, ImportCtx, ImportError};

pub(super) struct Opts {
    pub site: String,
    pub from: PathBuf,
    pub domains: Vec<String>,
    pub base: Option<PathBuf>,
    pub php: String,
    pub new_db_user: bool,
    pub id: Option<u32>,
    pub json: bool,
}

pub(super) fn import_cmd(global: &GlobalConfig, o: Opts) -> Result<ExitCode> {
    let host = SystemHost::new();
    let name = site_arg(&o.site)?.to_string();
    let fetcher = crate::fetch::net::HttpFetcher::new();
    let cache = crate::fetch::cache::Cache::new(&global.cache_dir);
    let ctx = ImportCtx {
        wporg: crate::fetch::wporg::WpOrg {
            fetcher: &fetcher,
            cache: &cache,
        },
    };
    let args = ImportArgs {
        site: name,
        from: absolute(o.from)?,
        domains: o.domains,
        base: o.base.map(absolute).transpose()?,
        php: o.php,
        new_db_user: o.new_db_user,
        id: o.id,
        src_root: PathBuf::from(DEFAULT_SRC_ROOT),
    };
    let print = |r: &crate::lifecycle::import::ImportReport| -> Result<()> {
        if o.json {
            println!("{}", serde_json::to_string_pretty(r)?);
        } else {
            println!("{}", r.summary());
        }
        Ok(())
    };
    match crate::lifecycle::import::run(&host, global, &ctx, args) {
        Ok(report) => {
            print(&report)?;
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            // A failure after the site file was written still prints the report (with the
            // error and the commands that finish the import by hand).
            if let Some(ie) = e.downcast_ref::<ImportError>() {
                print(&ie.report)?;
            }
            Err(e)
        }
    }
}
