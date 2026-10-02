//! `iwp image build|list|prune`.

use super::*;

pub(super) fn image_cmd(global: &GlobalConfig, action: ImageAction) -> Result<ExitCode> {
    let fetcher = crate::fetch::net::HttpFetcher::new();
    let cache = crate::fetch::cache::Cache::new(&global.cache_dir);
    let refresh_base = matches!(
        action,
        ImageAction::Build {
            refresh_base: true,
            ..
        }
    );
    let images = PodmanImages {
        wporg: crate::fetch::wporg::WpOrg {
            fetcher: &fetcher,
            cache: &cache,
        },
        refresh_base,
    };
    match action {
        ImageAction::Build { wordpress, php, .. } => {
            let issues = validate_core_versions(&wordpress, &php);
            if !issues.is_empty() {
                let msg: Vec<String> = issues.iter().map(|i| i.to_string()).collect();
                return Err(UsageError(msg.join("; ")).into());
            }
            images.build(&wordpress, &php)?;
            println!(
                "built {} and {}",
                fpm_tag(&wordpress, &php),
                cli_tag(&wordpress, &php)
            );
        }
        ImageAction::List => {
            let users = image_users(global)?;
            for tag in images.list()? {
                match users.get(&tag) {
                    Some(names) => println!("{tag}  used by: {}", names.join(", ")),
                    None => println!("{tag}  unused"),
                }
            }
        }
        ImageAction::Prune => {
            let users = image_users(global)?;
            let release_ids = release_image_ids(global)?;
            let tags = images.list()?;
            let site_tags: BTreeSet<String> = users.keys().cloned().collect();
            let remove = prune_candidates(&tags, &site_tags, &release_ids, |t| images.image_id(t));
            for tag in remove {
                match images.remove(&tag) {
                    Ok(()) => println!("removed {tag}"),
                    Err(e) => println!("warning: could not remove {tag}: {e:#}"),
                }
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Tags `image prune` removes: everything not kept by `image_keep_set`. A tag whose ID
/// cannot be resolved is warned about and kept (with its cli pair).
fn prune_candidates(
    tags: &[String],
    site_tags: &BTreeSet<String>,
    release_ids: &BTreeSet<String>,
    mut image_id: impl FnMut(&str) -> Result<String>,
) -> Vec<String> {
    let mut ids = BTreeMap::new();
    let mut unknown = BTreeSet::new();
    for tag in tags {
        match image_id(tag) {
            Ok(id) => {
                ids.insert(tag.clone(), id);
            }
            Err(e) => {
                eprintln!("warning: cannot resolve image ID of {tag}, keeping it: {e:#}");
                unknown.insert(tag.clone());
            }
        }
    }
    let keep = image_keep_set(&ids, site_tags, release_ids, &unknown);
    tags.iter()
        .filter(|t| !keep.contains(*t))
        .cloned()
        .collect()
}

/// Image IDs recorded in the manifests of every release of one site. A failing listing is an
/// error naming the site; an unreadable manifest is skipped with a warning.
fn site_release_ids(base: &std::path::Path, site: &str) -> Result<BTreeSet<String>> {
    let names = (|| {
        let names = crate::lifecycle::releases::list(base)?;
        crate::lifecycle::releases::current(base)?;
        crate::lifecycle::releases::previous(base)?;
        Ok::<_, anyhow::Error>(names)
    })()
    .map_err(|e| e.context(format!("site {site}: cannot list releases; nothing pruned")))?;
    let mut out = BTreeSet::new();
    for r in names {
        match crate::lifecycle::releases::read_manifest(base, &r) {
            Ok(m) => {
                out.insert(m.image_digest);
            }
            Err(e) => eprintln!("warning: {site}: release {r}: {e:#}"),
        }
    }
    Ok(out)
}

fn release_image_ids(global: &GlobalConfig) -> Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    if !global.sites_dir.is_dir() {
        return Ok(out);
    }
    let host = SystemHost::new();
    let sites = load_sites_dir(&global.sites_dir).map_err(|e| UsageError(format!("{e:#}")))?;
    for l in sites {
        let base = crate::host::sys(&host, l.site.base_dir(global));
        out.extend(site_release_ids(&base, &l.site.name)?);
    }
    Ok(out)
}

/// Tags to keep when pruning: site-file tags, every fpm tag whose image ID a release
/// references, and the cli tag paired with each kept fpm tag (same `<wp>-php<php>` suffix).
pub fn image_keep_set(
    ids: &BTreeMap<String, String>,
    site_tags: &BTreeSet<String>,
    release_ids: &BTreeSet<String>,
    unknown: &BTreeSet<String>,
) -> BTreeSet<String> {
    const FPM: &str = "localhost/iwp-fpm:";
    const CLI: &str = "localhost/iwp-cli:";
    let mut keep: BTreeSet<String> = site_tags.union(unknown).cloned().collect();
    for tag in unknown {
        if let Some(suffix) = tag.strip_prefix(FPM) {
            keep.insert(format!("{CLI}{suffix}"));
        }
    }
    for (tag, id) in ids {
        if release_ids.contains(id)
            && let Some(suffix) = tag.strip_prefix(FPM)
        {
            keep.insert(tag.clone());
            keep.insert(format!("{CLI}{suffix}"));
        }
    }
    keep
}

/// image tag -> names of the sites referencing it (a missing sites dir means no sites).
fn image_users(global: &GlobalConfig) -> Result<BTreeMap<String, Vec<String>>> {
    let mut users: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if !global.sites_dir.is_dir() {
        return Ok(users);
    }
    let sites = load_sites_dir(&global.sites_dir).map_err(|e| UsageError(format!("{e:#}")))?;
    for l in sites {
        for tag in [l.site.fpm_image(), l.site.cli_image()] {
            let v = users.entry(tag).or_default();
            if !v.contains(&l.site.name) {
                v.push(l.site.name.clone());
            }
        }
    }
    Ok(users)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_keep_set_includes_release_images_and_cli_pairs() {
        let ids = BTreeMap::from([
            (fpm_tag("7.1.2", "8.3"), "id712".to_string()),
            (cli_tag("7.1.2", "8.3"), "cid712".to_string()),
            (fpm_tag("7.0", "8.3"), "id70".to_string()),
            (cli_tag("7.0", "8.3"), "cid70".to_string()),
            (fpm_tag("6.9", "8.3"), "id69".to_string()),
            (cli_tag("6.9", "8.3"), "cid69".to_string()),
        ]);
        let site_tags = BTreeSet::from([fpm_tag("7.1.2", "8.3"), cli_tag("7.1.2", "8.3")]);
        let release_ids = BTreeSet::from(["id70".to_string()]);
        let keep = image_keep_set(&ids, &site_tags, &release_ids, &BTreeSet::new());
        assert!(keep.contains(&fpm_tag("7.0", "8.3")) && keep.contains(&cli_tag("7.0", "8.3")));
        assert!(keep.contains(&fpm_tag("7.1.2", "8.3")));
        assert!(!keep.contains(&fpm_tag("6.9", "8.3")) && !keep.contains(&cli_tag("6.9", "8.3")));
    }

    #[test]
    fn image_keep_set_keeps_unresolved_tags_and_their_cli_pair() {
        let ids = BTreeMap::new();
        let unknown = BTreeSet::from([fpm_tag("6.9", "8.3")]);
        let keep = image_keep_set(&ids, &BTreeSet::new(), &BTreeSet::new(), &unknown);
        assert!(keep.contains(&fpm_tag("6.9", "8.3")) && keep.contains(&cli_tag("6.9", "8.3")));
        let unknown = BTreeSet::from([cli_tag("6.8", "8.3")]);
        let keep = image_keep_set(&ids, &BTreeSet::new(), &BTreeSet::new(), &unknown);
        assert!(keep.contains(&cli_tag("6.8", "8.3")));
    }

    #[test]
    fn site_release_ids_errors_naming_site_on_listing_failure() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("releases")).unwrap();
        std::os::unix::fs::symlink("elsewhere", d.path().join("current")).unwrap();
        let e = site_release_ids(d.path(), "acme").unwrap_err().to_string();
        assert!(e.contains("acme"), "{e}");
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("releases"), "x").unwrap();
        assert!(site_release_ids(d.path(), "acme").is_err());
        let d = tempfile::tempdir().unwrap();
        assert!(site_release_ids(d.path(), "acme").unwrap().is_empty());
    }

    #[test]
    fn prune_candidates_never_removes_tags_with_unresolvable_ids() {
        let tags = vec![
            cli_tag("6.9", "8.3"),
            fpm_tag("6.9", "8.3"),
            cli_tag("6.8", "8.3"),
            fpm_tag("6.8", "8.3"),
        ];
        let id_of = |t: &str| -> Result<String> {
            if t == fpm_tag("6.9", "8.3") {
                anyhow::bail!("inspect failed")
            }
            Ok(format!("id-{t}"))
        };
        let remove = prune_candidates(&tags, &BTreeSet::new(), &BTreeSet::new(), id_of);
        assert_eq!(remove, vec![cli_tag("6.8", "8.3"), fpm_tag("6.8", "8.3")]);
    }
}
