//! `iwp pin`: record the current hash of `source` packages in the site file.

use std::path::Path;

use anyhow::{Context, Result};

use crate::build::sources::{SourceCtx, source_hash};
use crate::cli::UsageError;
use crate::config::edit::{PackageKind, edit_site_file};
use crate::config::validate::{source_issue, valid_slug};
use crate::config::{Package, Source, parse_site, validate_site};

pub fn pin(
    ctx: &SourceCtx,
    site_path: &Path,
    only: Option<&str>,
) -> Result<Vec<(String, String, String)>> {
    let text = std::fs::read_to_string(site_path)
        .with_context(|| format!("reading {}", site_path.display()))?;
    let site = parse_site(&text).map_err(|e| UsageError(format!("{e:#}")))?;
    let stem = site_path.file_stem().and_then(|s| s.to_str());
    let blocking: Vec<String> = validate_site(&site, stem)
        .into_iter()
        .filter(|i| {
            !(i.field.ends_with(".sha256") && i.message.starts_with("required with `source`"))
        })
        .map(|i| i.to_string())
        .collect();
    if !blocking.is_empty() {
        return Err(UsageError(blocking.join("\n")).into());
    }
    let all = site
        .plugins
        .iter()
        .map(|p| (PackageKind::Plugin, p))
        .chain(site.themes.iter().map(|p| (PackageKind::Theme, p)));
    let targets: Vec<_> = match only {
        None => all.filter(|(_, p)| p.source.is_some()).collect(),
        Some(slug) => {
            let found: Vec<_> = all.filter(|(_, p)| p.slug == slug).collect();
            match found.first() {
                None => {
                    return Err(UsageError(format!(
                        "no plugin or theme {slug:?} in {}",
                        site_path.display()
                    ))
                    .into());
                }
                Some((_, p)) if p.source.is_none() => {
                    return Err(UsageError(format!(
                        "{slug} is a wordpress.org package; its files are verified against wordpress.org checksums"
                    ))
                    .into());
                }
                Some(_) => {
                    let others: Vec<String> = site
                        .plugins
                        .iter()
                        .map(|p| (PackageKind::Plugin, p))
                        .chain(site.themes.iter().map(|p| (PackageKind::Theme, p)))
                        .filter(|(_, p)| p.slug != slug && p.source.is_some() && p.sha256.is_none())
                        .map(|(k, p)| format!("{}[{}]", k.table(), p.slug))
                        .collect();
                    if !others.is_empty() {
                        return Err(UsageError(format!(
                            "cannot pin only {slug}: these source packages are also unpinned: {}; run `iwp pin {}` to pin all of them",
                            others.join(", "),
                            stem.unwrap_or("<site>")
                        ))
                        .into());
                    }
                    found
                }
            }
        }
    };
    let mut pinned = Vec::new();
    for (kind, p) in targets {
        let h = source_hash(ctx, p).with_context(|| format!("{}[{}]", kind.table(), p.slug))?;
        pinned.push((kind, p.slug.clone(), h));
    }
    if !pinned.is_empty() {
        edit_site_file(site_path, |d| {
            for (kind, slug, h) in &pinned {
                d.set_sha256(*kind, slug, h)?;
            }
            Ok(())
        })?;
    }
    ctx.tofu.borrow().save()?;
    Ok(pinned
        .into_iter()
        .map(|(k, s, h)| (k.table().to_string(), s, h))
        .collect())
}

/// `iwp plugin|theme add <site> <slug> --url <url> | --path <dir>`: hash the source and add
/// it to the site file as a pinned `source` package. Nothing is fetched or written when the
/// slug or source is invalid or the slug is already in the site file.
pub fn add_source(
    ctx: &SourceCtx,
    site_path: &Path,
    kind: PackageKind,
    slug: &str,
    source: Source,
) -> Result<String> {
    let usage = |e: anyhow::Error| anyhow::Error::new(UsageError(format!("{e:#}")));
    let table = kind.table();
    if !valid_slug(slug) {
        return Err(UsageError(format!("invalid {table} slug {slug:?}")).into());
    }
    if let Some(msg) = source_issue(&source) {
        return Err(UsageError(msg.to_string()).into());
    }
    if let Source::Path { path } = &source
        && !std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
    {
        return Err(UsageError(format!("{} is not a directory", path.display())).into());
    }
    let text = std::fs::read_to_string(site_path)
        .with_context(|| format!("reading {}", site_path.display()))?;
    let site = parse_site(&text).map_err(usage)?;
    let existing = match kind {
        PackageKind::Plugin => &site.plugins,
        PackageKind::Theme => &site.themes,
    };
    if existing.iter().any(|p| p.slug == slug) {
        return Err(UsageError(format!("{table}[{slug}] already exists")).into());
    }
    let stem = site_path.file_stem().and_then(|s| s.to_str());
    let issues = validate_site(&site, stem);
    if !issues.is_empty() {
        let list: Vec<String> = issues.iter().map(ToString::to_string).collect();
        return Err(UsageError(list.join("\n")).into());
    }
    let p = Package {
        slug: slug.to_string(),
        version: None,
        source: Some(source),
        sha256: None,
        writable: vec![],
        cache: vec![],
        mu: false,
        hold: false,
    };
    let sha = source_hash(ctx, &p).with_context(|| format!("{table}[{slug}]"))?;
    let source = p.source.as_ref().expect("set above");
    edit_site_file(site_path, |d| d.add_source(kind, slug, source, &sha)).map_err(usage)?;
    Ok(sha)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build::tofu::Tofu;
    use crate::fetch::cache::Cache;
    use crate::hash::tree_hash;
    use crate::testutil::{FakeFetcher, tmp};
    use std::path::PathBuf;

    fn site_file(dir: &Path, src_path: &Path) -> PathBuf {
        let p = dir.join("s.toml");
        std::fs::write(
            &p,
            format!(
                r#"name = "s"
domains = ["s.example.org"]
id = 5
[core]
wordpress = "7.1.2"
php = "8.3"
[[plugin]]
slug = "custom"
source = {{ path = "{}" }}   # our plugin
[[plugin]]
slug = "gt"
version = "1.0.11"
"#,
                src_path.display()
            ),
        )
        .unwrap();
        p
    }

    #[test]
    fn pins_path_source_and_rejects_wporg_slug() {
        let t = tmp();
        let src = t.path().join("custom");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("custom.php"), "<?php").unwrap();
        let file = site_file(t.path(), &src);
        let f = FakeFetcher::new();
        let cache = Cache::new(&t.path().join("cache"));
        let ctx = SourceCtx {
            fetcher: &f,
            cache: &cache,
            tofu: std::cell::RefCell::new(Tofu::load(&t.path().join("tofu.json")).unwrap()),
        };
        let pinned = pin(&ctx, &file, None).unwrap();
        let h = tree_hash(&src).unwrap();
        assert_eq!(
            pinned,
            vec![("plugin".to_string(), "custom".to_string(), h.clone())]
        );
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(
            text.contains(&format!("sha256 = \"{h}\"")) && text.contains("# our plugin"),
            "{text}"
        );

        let err = pin(&ctx, &file, Some("gt")).unwrap_err();
        assert!(err.to_string().contains("wordpress.org package"), "{err}");
        assert!(err.downcast_ref::<crate::cli::UsageError>().is_some());
    }

    #[test]
    fn refuses_to_fetch_when_site_has_other_issues() {
        let t = tmp();
        let src = t.path().join("custom");
        std::fs::create_dir_all(&src).unwrap();
        let file = site_file(t.path(), &src);
        let bad = std::fs::read_to_string(&file)
            .unwrap()
            .replace("s.example.org", "S;bad");
        std::fs::write(&file, bad).unwrap();
        let f = FakeFetcher::new();
        let cache = Cache::new(&t.path().join("cache"));
        let ctx = SourceCtx {
            fetcher: &f,
            cache: &cache,
            tofu: std::cell::RefCell::new(Tofu::load(&t.path().join("tofu.json")).unwrap()),
        };
        let err = pin(&ctx, &file, None).unwrap_err();
        assert!(err.to_string().contains("domains"), "{err}");
    }

    fn two_sources(dir: &Path, second_pinned: bool) -> (PathBuf, PathBuf, PathBuf) {
        let (a, b) = (dir.join("a"), dir.join("b"));
        for d in [&a, &b] {
            std::fs::create_dir_all(d).unwrap();
            std::fs::write(d.join("x.php"), "<?php").unwrap();
        }
        let sha = if second_pinned {
            format!("\nsha256 = \"{}\"", "b".repeat(64))
        } else {
            String::new()
        };
        let p = dir.join("s.toml");
        std::fs::write(
            &p,
            format!(
                "name = \"s\"\ndomains = [\"s.example.org\"]\nid = 5\n[core]\nwordpress = \"7.1.2\"\nphp = \"8.3\"\n[[plugin]]\nslug = \"a\"\nsource = {{ path = \"{}\" }}\n[[plugin]]\nslug = \"b\"\nsource = {{ path = \"{}\" }}{sha}\n",
                a.display(),
                b.display()
            ),
        )
        .unwrap();
        (p, a, b)
    }

    fn ctx_for<'a>(t: &Path, f: &'a FakeFetcher, cache: &'a Cache) -> SourceCtx<'a> {
        SourceCtx {
            fetcher: f,
            cache,
            tofu: std::cell::RefCell::new(Tofu::load(&t.join("tofu.json")).unwrap()),
        }
    }

    #[test]
    fn only_refuses_when_other_sources_unpinned() {
        let t = tmp();
        let (file, _, _) = two_sources(t.path(), false);
        let before = std::fs::read_to_string(&file).unwrap();
        let f = FakeFetcher::new();
        let cache = Cache::new(&t.path().join("cache"));
        let ctx = ctx_for(t.path(), &f, &cache);
        let err = pin(&ctx, &file, Some("a")).unwrap_err();
        assert!(err.downcast_ref::<crate::cli::UsageError>().is_some());
        let m = err.to_string();
        assert!(
            m.contains("cannot pin only a") && m.contains("plugin[b]") && m.contains("iwp pin s"),
            "{m}"
        );
        assert!(f.calls().is_empty());
        assert_eq!(std::fs::read_to_string(&file).unwrap(), before);
    }

    #[test]
    fn only_succeeds_when_other_source_already_pinned() {
        let t = tmp();
        let (file, a, _) = two_sources(t.path(), true);
        let f = FakeFetcher::new();
        let cache = Cache::new(&t.path().join("cache"));
        let ctx = ctx_for(t.path(), &f, &cache);
        let r = pin(&ctx, &file, Some("a")).unwrap();
        assert_eq!(
            r,
            vec![(
                "plugin".to_string(),
                "a".to_string(),
                tree_hash(&a).unwrap()
            )]
        );
    }

    const VURL: &str = "https://vendor.example/prem-1.2.zip";

    fn vurl() -> Source {
        Source::Url { url: VURL.into() }
    }

    #[test]
    fn add_url_fetches_pins_and_builds_without_refetch() {
        use crate::testutil::make_zip;
        let t = tmp();
        let (file, _, _) = two_sources(t.path(), true);
        let zip = make_zip(&[("prem/prem.php", b"<?php")]);
        let f = FakeFetcher::new().with(VURL, zip.clone());
        let cache = Cache::new(&t.path().join("cache"));
        let ctx = ctx_for(t.path(), &f, &cache);
        pin(&ctx, &file, None).unwrap();
        let sha = add_source(&ctx, &file, PackageKind::Theme, "prem", vurl()).unwrap();
        assert_eq!(sha, crate::hash::sha256_hex(&zip));
        let site = parse_site(&std::fs::read_to_string(&file).unwrap()).unwrap();
        assert_eq!(site.themes.len(), 1);
        assert_eq!(site.themes[0].slug, "prem");
        assert_eq!(site.themes[0].source, Some(vurl()));
        assert_eq!(site.themes[0].sha256.as_deref(), Some(sha.as_str()));
        crate::build::sources::stage_package(
            &ctx,
            PackageKind::Theme,
            &site.themes[0],
            &t.path().join("out"),
        )
        .unwrap();
        assert_eq!(f.calls().len(), 1, "build must not refetch after add");
    }

    #[test]
    fn add_path_pins_the_tree_hash() {
        let t = tmp();
        let (file, _, _) = two_sources(t.path(), true);
        let dir = t.path().join("ours");
        std::fs::create_dir_all(dir.join("inc")).unwrap();
        std::fs::write(dir.join("inc/x.php"), "<?php").unwrap();
        let f = FakeFetcher::new();
        let cache = Cache::new(&t.path().join("cache"));
        let ctx = ctx_for(t.path(), &f, &cache);
        pin(&ctx, &file, None).unwrap();
        let src = Source::Path { path: dir.clone() };
        let sha = add_source(&ctx, &file, PackageKind::Plugin, "ours", src.clone()).unwrap();
        assert_eq!(sha, tree_hash(&dir).unwrap());
        let site = parse_site(&std::fs::read_to_string(&file).unwrap()).unwrap();
        let p = site.plugins.last().unwrap();
        assert_eq!((p.slug.as_str(), p.source.as_ref()), ("ours", Some(&src)));
        assert_eq!(p.sha256.as_deref(), Some(sha.as_str()));
        assert!(validate_site(&site, Some("s")).is_empty());
    }

    #[test]
    fn add_source_refuses_before_fetching_or_writing() {
        let t = tmp();
        let (file, _, _) = two_sources(t.path(), true);
        let before = std::fs::read_to_string(&file).unwrap();
        let regular = t.path().join("one.php");
        std::fs::write(&regular, "<?php").unwrap();
        let url = |u: &str| Source::Url { url: u.into() };
        let path = |p: &Path| Source::Path { path: p.into() };
        let f = FakeFetcher::new();
        let cache = Cache::new(&t.path().join("cache"));
        let ctx = ctx_for(t.path(), &f, &cache);
        for (slug, source, want) in [
            ("a", vurl(), "plugin[a] already exists"),
            // the site file itself is invalid: `a` is not pinned yet
            ("prem", vurl(), "plugin[a].sha256"),
            ("prem", url("http://vendor.example/p.zip"), "url must be"),
            (
                "prem",
                url("https://vendor.example/p.zip?x=1"),
                "url must be",
            ),
            ("../prem", vurl(), "invalid plugin slug"),
            ("prem", path(Path::new("rel/dir")), "path must be absolute"),
            ("prem", path(&regular), "is not a directory"),
            (
                "prem",
                path(&t.path().join("missing")),
                "is not a directory",
            ),
        ] {
            let err = add_source(&ctx, &file, PackageKind::Plugin, slug, source).unwrap_err();
            assert!(
                err.downcast_ref::<crate::cli::UsageError>().is_some(),
                "{err:#}"
            );
            assert!(err.to_string().contains(want), "{err}");
        }
        assert!(f.calls().is_empty());
        assert_eq!(std::fs::read_to_string(&file).unwrap(), before);
    }

    #[test]
    fn add_url_with_wrong_top_level_directory_leaves_the_file_alone() {
        use crate::testutil::make_zip;
        let t = tmp();
        let (file, _, _) = two_sources(t.path(), true);
        let f = FakeFetcher::new().with(VURL, make_zip(&[("other/a.php", b"x")]));
        let cache = Cache::new(&t.path().join("cache"));
        let ctx = ctx_for(t.path(), &f, &cache);
        pin(&ctx, &file, None).unwrap();
        let before = std::fs::read_to_string(&file).unwrap();
        let err = add_source(&ctx, &file, PackageKind::Plugin, "prem", vurl()).unwrap_err();
        assert!(format!("{err:#}").contains("expected \"prem\""), "{err:#}");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), before);
    }

    #[test]
    fn only_unknown_slug_is_usage_error() {
        let t = tmp();
        let (file, _, _) = two_sources(t.path(), true);
        let f = FakeFetcher::new();
        let cache = Cache::new(&t.path().join("cache"));
        let ctx = ctx_for(t.path(), &f, &cache);
        let err = pin(&ctx, &file, Some("zzz")).unwrap_err();
        assert!(err.downcast_ref::<crate::cli::UsageError>().is_some());
    }
}
