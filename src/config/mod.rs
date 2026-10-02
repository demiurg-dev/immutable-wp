pub mod edit;
mod global;
mod site;
pub mod validate;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

pub use global::{DEFAULT_GLOBAL_PATH, EgressConfig, GlobalConfig, load_global};
pub use site::*;
pub use validate::{
    Issue, allow_php_regex, shared_rel, validate_all, validate_core_versions, validate_global,
    validate_site,
};

#[derive(Debug, Clone)]
pub struct LoadedSite {
    pub path: PathBuf,
    pub site: Site,
}

pub fn parse_site(text: &str) -> Result<Site> {
    Ok(toml::from_str(text)?)
}

pub fn load_site(path: &Path) -> Result<LoadedSite> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let site = parse_site(&text).with_context(|| format!("parsing {}", path.display()))?;
    Ok(LoadedSite {
        path: path.to_path_buf(),
        site,
    })
}

/// Loads every `*.toml` in `dir`, sorted by file name.
pub fn load_sites_dir(dir: &Path) -> Result<Vec<LoadedSite>> {
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry
            .with_context(|| format!("reading entry of {}", dir.display()))?
            .path();
        if path.extension().is_some_and(|e| e == "toml") {
            paths.push(path);
        }
    }
    paths.sort();
    paths.iter().map(|p| load_site(p)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE: &str = include_str!("../../examples/simple.toml");
    const ACME: &str = include_str!("../../examples/acme.toml");

    #[test]
    fn parses_simple_with_defaults() {
        let s = parse_site(SIMPLE).unwrap();
        assert_eq!(s.name, "simple");
        assert_eq!(s.id, 1);
        assert_eq!(s.core.php, "8.3");
        assert!(s.core.languages.is_empty());
        assert_eq!(s.php.memory_limit, "256M");
        assert_eq!(s.php.fpm.max_children, 10);
        assert_eq!(
            s.php.disable_functions,
            vec![
                "exec",
                "shell_exec",
                "system",
                "passthru",
                "proc_open",
                "popen"
            ]
        );
        assert_eq!(s.plugins[0].version.as_deref(), Some("1.0.11"));
        assert_eq!(s.themes[0].slug, "twentytwentyfive");
        assert_eq!(s.fpm_image(), "localhost/iwp-fpm:7.1.2-php8.3");
        assert_eq!(s.cli_image(), "localhost/iwp-cli:7.1.2-php8.3");
    }

    #[test]
    fn parses_acme_multisite_constants_writable() {
        let s = parse_site(ACME).unwrap();
        let ms = s.config.multisite.as_ref().unwrap();
        assert!(ms.subdomain);
        assert_eq!(ms.domain, "www.example.org");
        assert_eq!(s.config.constants["WP_DEBUG"], ConstValue::Bool(false));
        assert_eq!(
            s.config.constants["WFWAF_STORAGE_ENGINE"],
            ConstValue::Str("mysqli".into())
        );
        assert_eq!(s.writable_paths(), vec!["wp-content/wflogs"]);
        assert_eq!(s.php.fpm.max_children, 20);
    }

    #[test]
    fn parses_sources() {
        let s = parse_site(&format!(
            r#"{SIMPLE}
[[plugin]]
slug = "p1"
source = {{ path = "/srv/p1" }}
sha256 = "{h}"
[[plugin]]
slug = "p2"
source = {{ git = "https://git.example.org/p2.git", rev = "{r}" }}
sha256 = "{h}"
[[plugin]]
slug = "p3"
source = {{ url = "https://example.org/p3.zip" }}
sha256 = "{h}"
"#,
            h = "a".repeat(64),
            r = "b".repeat(40)
        ))
        .unwrap();
        assert_eq!(
            s.plugins[1].source,
            Some(Source::Path {
                path: "/srv/p1".into()
            })
        );
        assert!(matches!(s.plugins[2].source, Some(Source::Git { .. })));
        assert!(matches!(s.plugins[3].source, Some(Source::Url { .. })));
    }

    #[test]
    fn rejects_unknown_keys() {
        let err = parse_site(&format!("{SIMPLE}\nbogus = 1\n")).unwrap_err();
        assert!(format!("{err:#}").contains("bogus"), "{err:#}");
    }

    #[test]
    fn rejects_source_with_mixed_keys() {
        let text = format!(
            "{SIMPLE}\n[[plugin]]\nslug = \"x\"\nsource = {{ path = \"/a\", url = \"https://b\" }}\nsha256 = \"{}\"\n",
            "a".repeat(64)
        );
        assert!(parse_site(&text).is_err());
    }

    #[test]
    fn global_defaults_and_base_dir() {
        let g = GlobalConfig::default();
        assert_eq!(g.keep_releases, 5);
        assert_eq!(g.keep_db_dumps, 10);
        assert_eq!(g.id_offset, 100_000);
        let s = parse_site(SIMPLE).unwrap();
        assert_eq!(
            s.base_dir(&g),
            std::path::PathBuf::from("/var/www/vhosts/simple")
        );
        let b = parse_site(ACME).unwrap();
        assert_eq!(
            b.base_dir(&g),
            std::path::PathBuf::from("/var/www/vhosts/example.org/iwp")
        );
    }

    #[test]
    fn load_global_parses_explicit_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("iwp.toml");
        std::fs::write(&p, "keep_releases = 7\nnginx_group = \"www\"\n").unwrap();
        let g = load_global(Some(&p)).unwrap();
        assert_eq!(g.keep_releases, 7);
        assert_eq!(g.nginx_group, "www");
        assert_eq!(g.keep_db_dumps, 10);
        assert!(load_global(Some(&dir.path().join("missing.toml"))).is_err());
    }

    #[test]
    fn load_sites_dir_sorted() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("simple.toml"), SIMPLE).unwrap();
        std::fs::write(dir.path().join("acme.toml"), ACME).unwrap();
        std::fs::write(dir.path().join("README"), "ignored").unwrap();
        let sites = load_sites_dir(dir.path()).unwrap();
        let names: Vec<_> = sites.iter().map(|l| l.site.name.as_str()).collect();
        assert_eq!(names, vec!["acme", "simple"]);
    }
}
