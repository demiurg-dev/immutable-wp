//! Commands that read or edit site files: plugin/theme, validate, render, pin.

use super::*;

pub(super) fn package(
    global: &GlobalConfig,
    kind: PackageKind,
    action: PackageAction,
) -> Result<ExitCode> {
    let sites_dir = &global.sites_dir;
    let usage = |e: anyhow::Error| anyhow::Error::new(UsageError(format!("{e:#}")));
    match action {
        PackageAction::Add {
            site,
            spec,
            url,
            path: dir,
        } => {
            let path = site_path(sites_dir, &site)?;
            let (slug, version) = parse_spec(&spec).map_err(usage)?;
            let source = match (url, dir) {
                (Some(url), _) => Some(crate::config::Source::Url { url }),
                (None, Some(path)) => Some(crate::config::Source::Path { path }),
                (None, None) => None,
            };
            match (source, version) {
                (Some(_), Some(_)) => {
                    return Err(UsageError(format!(
                        "{} add with --url or --path needs <slug> without a version",
                        kind.table()
                    ))
                    .into());
                }
                (Some(source), None) => {
                    let fetcher = crate::fetch::net::HttpFetcher::new();
                    let cache = crate::fetch::cache::Cache::new(&global.cache_dir);
                    let ctx = source_ctx(global, &fetcher, &cache)?;
                    let sha = crate::build::pin::add_source(&ctx, &path, kind, &slug, source)?;
                    println!("pinned {}[{slug}] {sha}", kind.table());
                }
                (None, Some(version)) => {
                    edit_site_file(&path, |d| d.add(kind, &slug, &version)).map_err(usage)?;
                }
                (None, None) => {
                    return Err(UsageError(format!(
                        "{} add needs <slug>@<version>, or <slug> with --url or --path",
                        kind.table()
                    ))
                    .into());
                }
            }
        }
        PackageAction::Set { site, spec } => {
            let path = site_path(sites_dir, &site)?;
            let (slug, version) = parse_spec(&spec).map_err(usage)?;
            let version = version.ok_or_else(|| {
                UsageError(format!("{} set needs <slug>@<version>", kind.table()))
            })?;
            edit_site_file(&path, |d| d.set_version(kind, &slug, &version)).map_err(usage)?;
        }
        PackageAction::Rm { site, slug } => {
            let path = site_path(sites_dir, &site)?;
            edit_site_file(&path, |d| d.remove(kind, &slug)).map_err(usage)?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

pub(super) fn validate_cmd(global: &GlobalConfig, only: &[String]) -> Result<ExitCode> {
    let sites = load_valid_sites(global, only)?;
    let n = if only.is_empty() {
        sites.len()
    } else {
        only.len()
    };
    println!("ok: {n} site(s)");
    Ok(ExitCode::SUCCESS)
}

pub(super) fn render_cmd(
    global: &GlobalConfig,
    name: &str,
    out: &std::path::Path,
    db_host_ip: std::net::Ipv4Addr,
) -> Result<ExitCode> {
    let name = site_arg(name)?;
    let sites = load_valid_sites(global, &[name.to_string()])?;
    let site = &sites
        .iter()
        .find(|l| l.site.name == name)
        .expect("validated")
        .site;
    if out.exists() && std::fs::read_dir(out)?.next().is_some() {
        return Err(UsageError(format!("{} is not empty", out.display())).into());
    }
    let env = RenderEnv {
        db_host_ip,
        ..RenderEnv::default()
    };
    for (rel, body) in render_site(global, site, &env)? {
        let p = out.join(rel);
        std::fs::create_dir_all(p.parent().expect("relative path has parent"))?;
        std::fs::write(&p, body)?;
    }
    println!("rendered {name} into {}", out.display());
    Ok(ExitCode::SUCCESS)
}

fn source_ctx<'a>(
    global: &GlobalConfig,
    fetcher: &'a crate::fetch::net::HttpFetcher,
    cache: &'a crate::fetch::cache::Cache,
) -> Result<crate::build::sources::SourceCtx<'a>> {
    Ok(crate::build::sources::SourceCtx {
        fetcher,
        cache,
        tofu: std::cell::RefCell::new(crate::build::tofu::Tofu::load(
            &global.cache_dir.join("tofu.json"),
        )?),
    })
}

pub(super) fn pin_cmd(global: &GlobalConfig, name: &str, slug: Option<&str>) -> Result<ExitCode> {
    let name = site_arg(name)?;
    // pin validates the site itself (a missing sha256 is the one issue it tolerates).
    let path = site_path(&global.sites_dir, name)?;
    let fetcher = crate::fetch::net::HttpFetcher::new();
    let cache = crate::fetch::cache::Cache::new(&global.cache_dir);
    let ctx = source_ctx(global, &fetcher, &cache)?;
    for (kind, slug, sha) in crate::build::pin::pin(&ctx, &path, slug)? {
        println!("pinned {kind}[{slug}] {sha}");
    }
    Ok(ExitCode::SUCCESS)
}
