//! `iwp build` and `iwp outdated`.

use super::*;

pub(super) fn build_cmd(global: &GlobalConfig, name: &str) -> Result<ExitCode> {
    let name = site_arg(name)?;
    let sites = load_valid_sites(global, &[name.to_string()])?;
    let site = &sites
        .iter()
        .find(|l| l.path.file_stem().is_some_and(|s| s == name))
        .expect("validated")
        .site;
    let fetcher = crate::fetch::net::HttpFetcher::new();
    let cache = crate::fetch::cache::Cache::new(&global.cache_dir);
    let images = PodmanImages {
        wporg: crate::fetch::wporg::WpOrg {
            fetcher: &fetcher,
            cache: &cache,
        },
        refresh_base: false,
    };
    let r = crate::build::build_release(
        &crate::build::BuildEnv {
            global,
            fetcher: &fetcher,
            images: &images,
            now: jiff::Timestamp::now(),
            quiet: false,
        },
        site,
    )?;
    for w in unlisted_warnings(&r.manifest) {
        eprintln!("{w}");
    }
    println!(
        "built {} ({} packages, {} language packs) at {}",
        r.name,
        r.manifest.packages.len(),
        r.manifest.languages.len(),
        r.path.display()
    );
    Ok(ExitCode::SUCCESS)
}

/// One warning per package that shipped files wordpress.org's checksums do not list.
fn unlisted_warnings(m: &crate::build::ReleaseManifest) -> Vec<String> {
    m.packages
        .iter()
        .filter(|p| !p.unlisted_files.is_empty())
        .map(|p| {
            format!(
                "warning: {}[{}]: {} file(s) not in wordpress.org checksums: {}",
                p.kind,
                p.slug,
                p.unlisted_files.len(),
                p.unlisted_files
                    .iter()
                    .take(5)
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
        .collect()
}

pub(super) fn outdated_cmd(global: &GlobalConfig, name: &str, json: bool) -> Result<ExitCode> {
    let name = site_arg(name)?;
    use crate::lifecycle::outdated::{Status, outdated};
    let sites = load_valid_sites(global, &[name.to_string()])?;
    let site = &sites
        .iter()
        .find(|l| l.path.file_stem().is_some_and(|s| s == name))
        .expect("validated")
        .site;
    let fetcher = crate::fetch::net::HttpFetcher::new();
    let cache = crate::fetch::cache::Cache::new(&global.cache_dir);
    let rows = outdated(
        &crate::fetch::wporg::WpOrg {
            fetcher: &fetcher,
            cache: &cache,
        },
        site,
    );
    if json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
    } else {
        let w = rows.iter().map(|r| r.slug.len()).max().unwrap_or(0);
        for r in &rows {
            let head = format!("{:<6} {:<w$}", r.kind, r.slug);
            match &r.status {
                Status::Outdated => {
                    let tested = r
                        .tested
                        .as_deref()
                        .map(|t| format!(" (tested up to {t})"))
                        .unwrap_or_default();
                    println!(
                        "{head} {} -> {}{tested}",
                        r.current,
                        r.latest.as_deref().unwrap_or("?")
                    );
                }
                Status::UpToDate => println!("{head} {} up to date", r.current),
                Status::Pinned => println!("{head} pinned source"),
                Status::Error(m) => println!("{head} error: {m}"),
            }
        }
    }
    let failed = rows.iter().any(|r| matches!(r.status, Status::Error(_)));
    Ok(if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build::sources::Origin;
    use crate::build::{PackageRecord, ReleaseManifest};

    fn rec(slug: &str, unlisted: &[&str]) -> PackageRecord {
        PackageRecord {
            kind: "plugin".into(),
            slug: slug.into(),
            mu: false,
            origin: Origin::Wporg {
                version: "1.0".into(),
            },
            sha256: "0".repeat(64),
            files_verified: 1,
            unlisted_files: unlisted.iter().map(|s| s.to_string()).collect(),
            tree_sha256: "0".repeat(64),
        }
    }

    #[test]
    fn warns_once_per_package_with_first_five_files() {
        let m = ReleaseManifest {
            iwp_version: "0".into(),
            site: "s".into(),
            release: "r".into(),
            built_at: "t".into(),
            wordpress: "7.1.2".into(),
            php: "8.3".into(),
            image: "i".into(),
            image_digest: "d".into(),
            core_files_verified: 0,
            packages: vec![
                rec("clean", &[]),
                rec(
                    "gt",
                    &["a.png", "b.png", "c.png", "d.png", "e.png", "f.png"],
                ),
            ],
            languages: vec![],
            dropins: vec![],
            files: Default::default(),
        };
        assert_eq!(
            unlisted_warnings(&m),
            vec![
                "warning: plugin[gt]: 6 file(s) not in wordpress.org checksums: a.png, b.png, c.png, d.png, e.png"
            ]
        );
    }
}
