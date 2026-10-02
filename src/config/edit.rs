use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use toml_edit::{ArrayOfTables, DocumentMut, Item, Table, Value, value};

use crate::config::{parse_site, validate_site};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageKind {
    Plugin,
    Theme,
}

impl PackageKind {
    pub fn table(self) -> &'static str {
        match self {
            PackageKind::Plugin => "plugin",
            PackageKind::Theme => "theme",
        }
    }
}

pub struct SiteDocument {
    doc: DocumentMut,
}

impl SiteDocument {
    pub fn parse(text: &str) -> Result<Self> {
        Ok(Self {
            doc: text.parse().context("parsing site file")?,
        })
    }

    pub fn render(&self) -> String {
        self.doc.to_string()
    }

    fn tables_mut(&mut self, kind: PackageKind) -> Option<&mut ArrayOfTables> {
        self.doc
            .get_mut(kind.table())
            .and_then(Item::as_array_of_tables_mut)
    }

    fn find(aot: &mut ArrayOfTables, slug: &str) -> Option<usize> {
        aot.iter()
            .position(|t| t.get("slug").and_then(Item::as_str) == Some(slug))
    }

    pub fn add(&mut self, kind: PackageKind, slug: &str, version: &str) -> Result<()> {
        if self.doc.get(kind.table()).is_none() {
            self.doc
                .insert(kind.table(), Item::ArrayOfTables(ArrayOfTables::new()));
        }
        let aot = self
            .tables_mut(kind)
            .ok_or_else(|| anyhow!("`{}` is not an array of tables", kind.table()))?;
        if Self::find(aot, slug).is_some() {
            bail!("{}[{slug}] already exists; use `set`", kind.table());
        }
        let mut t = Table::new();
        t["slug"] = value(slug);
        t["version"] = value(version);
        aot.push(t);
        Ok(())
    }

    pub fn set_version(&mut self, kind: PackageKind, slug: &str, version: &str) -> Result<()> {
        let table = kind.table();
        let aot = self
            .tables_mut(kind)
            .ok_or_else(|| anyhow!("no {table} entries"))?;
        let idx = Self::find(aot, slug).ok_or_else(|| anyhow!("{table}[{slug}] not found"))?;
        let t = aot.get_mut(idx).expect("index from find");
        if t.contains_key("source") {
            bail!("{table}[{slug}] uses `source`; update the source and run `iwp pin` instead");
        }
        match t.get_mut("version").and_then(Item::as_value_mut) {
            Some(v) => {
                let decor = v.decor().clone();
                *v = Value::from(version);
                *v.decor_mut() = decor;
            }
            None => t["version"] = value(version),
        }
        Ok(())
    }

    pub fn set_core_wordpress(&mut self, version: &str) -> Result<()> {
        let v = self
            .doc
            .get_mut("core")
            .and_then(|c| c.get_mut("wordpress"))
            .and_then(Item::as_value_mut)
            .ok_or_else(|| anyhow!("no core.wordpress entry"))?;
        let decor = v.decor().clone();
        *v = Value::from(version);
        *v.decor_mut() = decor;
        Ok(())
    }

    pub fn set_sha256(&mut self, kind: PackageKind, slug: &str, sha256: &str) -> Result<()> {
        let table = kind.table();
        let aot = self
            .tables_mut(kind)
            .ok_or_else(|| anyhow!("no {table} entries"))?;
        let idx = Self::find(aot, slug).ok_or_else(|| anyhow!("{table}[{slug}] not found"))?;
        let t = aot.get_mut(idx).expect("index from find");
        if !t.contains_key("source") {
            bail!("{table}[{slug}] is a wordpress.org package; only `source` packages are pinned");
        }
        match t.get_mut("sha256").and_then(Item::as_value_mut) {
            Some(v) => {
                let decor = v.decor().clone();
                *v = Value::from(sha256);
                *v.decor_mut() = decor;
            }
            None => t["sha256"] = value(sha256),
        }
        Ok(())
    }

    pub fn remove(&mut self, kind: PackageKind, slug: &str) -> Result<()> {
        let table = kind.table();
        let aot = self
            .tables_mut(kind)
            .ok_or_else(|| anyhow!("no {table} entries"))?;
        let idx = Self::find(aot, slug).ok_or_else(|| anyhow!("{table}[{slug}] not found"))?;
        aot.remove(idx);
        if aot.is_empty() {
            self.doc.remove(table);
        }
        Ok(())
    }
}

pub fn parse_spec(spec: &str) -> Result<(String, Option<String>)> {
    match spec.split_once('@') {
        None if !spec.is_empty() => Ok((spec.to_string(), None)),
        Some((s, v)) if !s.is_empty() && !v.is_empty() => Ok((s.to_string(), Some(v.to_string()))),
        _ => bail!("expected <slug> or <slug>@<version>, got {spec:?}"),
    }
}

pub fn edit_site_file(path: &Path, f: impl FnOnce(&mut SiteDocument) -> Result<()>) -> Result<()> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut doc = SiteDocument::parse(&text)?;
    f(&mut doc)?;
    let out = doc.render();
    let site = parse_site(&out).context("edited site file no longer parses")?;
    let stem = path.file_stem().and_then(|s| s.to_str());
    let issues = validate_site(&site, stem);
    if !issues.is_empty() {
        let list: Vec<String> = issues.iter().map(ToString::to_string).collect();
        bail!(
            "edit rejected, site file would be invalid:\n  {}",
            list.join("\n  ")
        );
    }
    crate::host::fsx::write_atomic(
        &crate::host::SystemHost::new(),
        path,
        out.as_bytes(),
        &crate::host::fsx::FileSpec::default(),
    )?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = r#"# acme site
name    = "acme"
domains = ["www.example.org"]
id      = 3

[core]
wordpress = "7.1.2"
php       = "8.3"

# tabs block
[[plugin]]
slug    = "gutena-tabs"
version = "1.0.11"   # WP 6.9+ compatible

[[plugin]]
slug   = "custom"
source = { path = "/srv/custom" }
sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#;

    #[test]
    fn set_version_keeps_comments() {
        let mut d = SiteDocument::parse(DOC).unwrap();
        d.set_version(PackageKind::Plugin, "gutena-tabs", "1.0.12")
            .unwrap();
        let out = d.render();
        assert!(
            out.contains("version = \"1.0.12\"   # WP 6.9+ compatible"),
            "{out}"
        );
        assert!(out.contains("# acme site") && out.contains("# tabs block"));
        assert_eq!(out.replace("1.0.12", "1.0.11"), DOC);
    }

    #[test]
    fn set_version_on_source_package_is_refused() {
        let mut d = SiteDocument::parse(DOC).unwrap();
        let err = d
            .set_version(PackageKind::Plugin, "custom", "2.0")
            .unwrap_err();
        assert!(err.to_string().contains("source"), "{err}");
    }

    #[test]
    fn set_version_unknown_slug() {
        let mut d = SiteDocument::parse(DOC).unwrap();
        assert!(d.set_version(PackageKind::Plugin, "nope", "1").is_err());
    }

    #[test]
    fn add_and_remove() {
        let mut d = SiteDocument::parse(DOC).unwrap();
        d.add(PackageKind::Theme, "hello-elementor", "3.4.4")
            .unwrap();
        d.add(PackageKind::Plugin, "wordfence", "8.1.0").unwrap();
        assert!(d.add(PackageKind::Plugin, "wordfence", "8.1.0").is_err());
        let s = crate::config::parse_site(&d.render()).unwrap();
        assert_eq!(s.themes[0].slug, "hello-elementor");
        assert_eq!(s.plugins.last().unwrap().slug, "wordfence");
        d.remove(PackageKind::Theme, "hello-elementor").unwrap();
        assert!(!d.render().contains("[[theme]]"));
        assert!(d.remove(PackageKind::Theme, "hello-elementor").is_err());
    }

    #[test]
    fn parse_spec_forms() {
        assert_eq!(
            parse_spec("a@1.2").unwrap(),
            ("a".into(), Some("1.2".into()))
        );
        assert_eq!(parse_spec("a").unwrap(), ("a".into(), None));
        assert!(parse_spec("@1").is_err());
        assert!(parse_spec("a@").is_err());
    }

    #[test]
    fn edit_site_file_is_atomic_on_invalid_result() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acme.toml");
        std::fs::write(&path, DOC).unwrap();
        let err = edit_site_file(&path, |d| {
            d.set_version(PackageKind::Plugin, "gutena-tabs", "1.0 ; bad")
        })
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("plugin[gutena-tabs].version"),
            "{err:#}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), DOC);
        edit_site_file(&path, |d| {
            d.set_version(PackageKind::Plugin, "gutena-tabs", "1.0.12")
        })
        .unwrap();
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("\"1.0.12\"")
        );
    }

    #[test]
    fn set_sha256_on_source_package_keeps_comment() {
        let doc = DOC.replace(
            "sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\" # pinned",
        );
        let mut d = SiteDocument::parse(&doc).unwrap();
        let b = "b".repeat(64);
        d.set_sha256(PackageKind::Plugin, "custom", &b).unwrap();
        assert!(d.render().contains(&format!("sha256 = \"{b}\" # pinned")));
        assert!(
            d.set_sha256(PackageKind::Plugin, "gutena-tabs", &b)
                .is_err(),
            "wordpress.org packages have no sha256"
        );
    }

    #[test]
    fn set_sha256_inserts_when_missing() {
        let doc = DOC.replace(
            "sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
            "",
        );
        let mut d = SiteDocument::parse(&doc).unwrap();
        d.set_sha256(PackageKind::Plugin, "custom", &"c".repeat(64))
            .unwrap();
        let s = crate::config::parse_site(&d.render()).unwrap();
        assert_eq!(
            s.plugins[1].sha256.as_deref(),
            Some("c".repeat(64).as_str())
        );
    }
}
