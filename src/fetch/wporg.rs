//! wordpress.org / GitHub endpoints used by the builder. All inputs (slugs, versions) are
//! validated by `validate_site` before they reach these URL builders.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::Value;

use crate::fetch::cache::Cache;
use crate::fetch::net::Fetcher;

pub const CORE_VERSION_CHECK_URL: &str = "https://api.wordpress.org/core/version-check/1.7/";
const TRANSLATION_PREFIX: &str = "https://downloads.wordpress.org/translation/";

pub fn plugin_zip_url(slug: &str, ver: &str) -> String {
    format!("https://downloads.wordpress.org/plugin/{slug}.{ver}.zip")
}
pub fn theme_zip_url(slug: &str, ver: &str) -> String {
    format!("https://downloads.wordpress.org/theme/{slug}.{ver}.zip")
}
pub fn plugin_checksums_url(slug: &str, ver: &str) -> String {
    format!("https://downloads.wordpress.org/plugin-checksums/{slug}/{ver}.json")
}
pub fn core_checksums_url(ver: &str) -> String {
    format!("https://api.wordpress.org/core/checksums/1.0/?version={ver}&locale=en_US")
}
pub fn core_sha1_url(ver: &str) -> String {
    format!("https://wordpress.org/wordpress-{ver}.tar.gz.sha1")
}
pub fn wpcli_sha512_url(ver: &str) -> String {
    format!("https://github.com/wp-cli/wp-cli/releases/download/v{ver}/wp-cli-{ver}.phar.sha512")
}
pub fn plugin_info_url(slug: &str) -> String {
    format!(
        "https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request%5Bslug%5D={slug}&request%5Bfields%5D%5Bsections%5D=0"
    )
}
pub fn theme_info_url(slug: &str) -> String {
    format!("https://api.wordpress.org/themes/info/1.2/?action=theme_information&slug={slug}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransKind {
    Core,
    Plugin,
    Theme,
}

pub fn translations_url(kind: TransKind, slug: Option<&str>, ver: &str) -> String {
    match (kind, slug) {
        (TransKind::Core, _) => {
            format!("https://api.wordpress.org/translations/core/1.0/?version={ver}")
        }
        (TransKind::Plugin, Some(s)) => {
            format!("https://api.wordpress.org/translations/plugins/1.0/?slug={s}&version={ver}")
        }
        (TransKind::Theme, Some(s)) => {
            format!("https://api.wordpress.org/translations/themes/1.0/?slug={s}&version={ver}")
        }
        (_, None) => unreachable!("plugin/theme translations need a slug"),
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Translation {
    pub language: String,
    pub version: String,
    pub package: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Info {
    pub version: String,
    pub tested: Option<String>,
    pub requires_php: Option<String>,
    /// Minimum WordPress version.
    pub requires: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
struct FileSums {
    sha256: OneOrMany,
}

#[derive(Deserialize)]
struct PluginChecksums {
    files: BTreeMap<String, FileSums>,
}

fn hex_token(text: &str, len: usize) -> Option<String> {
    let t = text.split_whitespace().next()?;
    (t.len() == len && t.bytes().all(|b| b.is_ascii_hexdigit())).then(|| t.to_ascii_lowercase())
}

pub struct WpOrg<'a> {
    pub fetcher: &'a dyn Fetcher,
    pub cache: &'a Cache,
}

impl WpOrg<'_> {
    pub fn plugin_zip(&self, slug: &str, ver: &str) -> Result<Vec<u8>> {
        self.cache
            .get_url(self.fetcher, &plugin_zip_url(slug, ver))
            .with_context(|| format!("plugin {slug}@{ver}"))
    }

    pub fn theme_zip(&self, slug: &str, ver: &str) -> Result<Vec<u8>> {
        self.cache
            .get_url(self.fetcher, &theme_zip_url(slug, ver))
            .with_context(|| format!("theme {slug}@{ver}"))
    }

    pub fn plugin_checksums(&self, slug: &str, ver: &str) -> Result<BTreeMap<String, Vec<String>>> {
        let url = plugin_checksums_url(slug, ver);
        let ctx = || format!("checksums for plugin {slug}@{ver} ({url})");
        // Always fetched fresh: a poisoned local cache must never defeat verification.
        let bytes = self.fetcher.get(&url).with_context(ctx)?;
        let parsed: PluginChecksums =
            serde_json::from_slice(&bytes).map_err(|e| anyhow::Error::new(e).context(ctx()))?;
        if parsed.files.is_empty() {
            bail!("{}: no files listed", ctx());
        }
        Ok(parsed
            .files
            .into_iter()
            .map(|(k, v)| {
                let list = match v.sha256 {
                    OneOrMany::One(s) => vec![s],
                    OneOrMany::Many(v) => v,
                };
                (k, list)
            })
            .collect())
    }

    pub fn core_checksums(&self, ver: &str) -> Result<BTreeMap<String, String>> {
        let url = core_checksums_url(ver);
        let ctx = || format!("core checksums for WordPress {ver} ({url})");
        let bytes = self.cache.get_url(self.fetcher, &url).with_context(ctx)?;
        let res = (|| -> Result<BTreeMap<String, String>> {
            let v: Value = serde_json::from_slice(&bytes)?;
            let map = v
                .get("checksums")
                .and_then(Value::as_object)
                .context("unknown version")?;
            map.iter()
                .map(|(k, v)| Ok((k.clone(), v.as_str().context("non-string md5")?.to_string())))
                .collect()
        })();
        res.map_err(|e| {
            let _ = self.cache.evict_url(&url);
            e.context(ctx())
        })
    }

    pub fn core_sha1(&self, ver: &str) -> Result<String> {
        let url = core_sha1_url(ver);
        let body = self.fetcher.get(&url)?;
        hex_token(&String::from_utf8_lossy(&body), 40)
            .with_context(|| format!("{url}: not a SHA-1"))
    }

    pub fn wpcli_sha512(&self, ver: &str) -> Result<String> {
        let url = wpcli_sha512_url(ver);
        let body = self.fetcher.get(&url)?;
        hex_token(&String::from_utf8_lossy(&body), 128)
            .with_context(|| format!("{url}: not a SHA-512"))
    }

    pub fn translations(
        &self,
        kind: TransKind,
        slug: Option<&str>,
        ver: &str,
    ) -> Result<Vec<Translation>> {
        #[derive(Deserialize)]
        struct Resp {
            translations: Vec<Translation>,
        }
        let url = translations_url(kind, slug, ver);
        let r: Resp = serde_json::from_slice(&self.fetcher.get(&url)?)
            .with_context(|| format!("parsing {url}"))?;
        Ok(r.translations)
    }

    pub fn translation_zip(&self, t: &Translation) -> Result<Vec<u8>> {
        if !t.package.starts_with(TRANSLATION_PREFIX) {
            bail!(
                "translation package {} is not on downloads.wordpress.org",
                t.package
            );
        }
        self.fetcher.get(&t.package)
    }

    fn info(&self, url: &str) -> Result<Info> {
        let v: Value = serde_json::from_slice(&self.fetcher.get(url)?)
            .with_context(|| format!("parsing {url}"))?;
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
        Ok(Info {
            version: s("version").with_context(|| format!("{url}: no version"))?,
            tested: s("tested"),
            requires_php: s("requires_php"),
            requires: s("requires"),
        })
    }

    pub fn plugin_info(&self, slug: &str) -> Result<Info> {
        self.info(&plugin_info_url(slug))
    }

    pub fn theme_info(&self, slug: &str) -> Result<Info> {
        self.info(&theme_info_url(slug))
    }

    /// Versions wordpress.org offers to a site running `current`: the latest release and
    /// the newest patch release of each still-maintained branch, `current`'s included.
    pub fn core_offers(&self, current: &str) -> Result<Vec<String>> {
        let url = format!("{CORE_VERSION_CHECK_URL}?version={current}");
        let v: Value = serde_json::from_slice(&self.fetcher.get(&url)?)
            .context("parsing core version-check")?;
        let offers = v
            .get("offers")
            .and_then(Value::as_array)
            .with_context(|| format!("{url}: no offers"))?;
        let mut out: Vec<String> = offers
            .iter()
            .filter_map(|o| o.get("version").and_then(Value::as_str))
            .map(str::to_string)
            .collect();
        out.sort();
        out.dedup();
        Ok(out)
    }

    pub fn core_latest(&self) -> Result<String> {
        let v: Value = serde_json::from_slice(&self.fetcher.get(CORE_VERSION_CHECK_URL)?)
            .context("parsing core version-check")?;
        v.pointer("/offers/0/version")
            .and_then(Value::as_str)
            .map(str::to_string)
            .with_context(|| format!("{CORE_VERSION_CHECK_URL}: no offers"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{FakeFetcher, tmp};

    fn client<'a>(f: &'a FakeFetcher, c: &'a Cache) -> WpOrg<'a> {
        WpOrg {
            fetcher: f,
            cache: c,
        }
    }

    #[test]
    fn plugin_checksums_accept_string_or_list() {
        let url = plugin_checksums_url("p", "1.0");
        let f = FakeFetcher::new().with(
            &url,
            r#"{"plugin":"p","version":"1.0","files":{
            "a.php":{"md5":"x","sha256":"aa"},
            "b.js":{"md5":["y","z"],"sha256":["bb","cc"]}}}"#,
        );
        let d = tmp();
        let c = Cache::new(d.path());
        let sums = client(&f, &c).plugin_checksums("p", "1.0").unwrap();
        assert_eq!(sums["a.php"], vec!["aa"]);
        assert_eq!(sums["b.js"], vec!["bb", "cc"]);
    }

    #[test]
    fn plugin_checksums_errors() {
        let d = tmp();
        let c = Cache::new(d.path());
        let empty = FakeFetcher::new().with(&plugin_checksums_url("p", "1.0"), r#"{"files":{}}"#);
        assert!(client(&empty, &c).plugin_checksums("p", "1.0").is_err());
        let d2 = tmp();
        let c2 = Cache::new(d2.path());
        let html = FakeFetcher::new().with(&plugin_checksums_url("p", "1.0"), "<html>");
        let err = client(&html, &c2).plugin_checksums("p", "1.0").unwrap_err();
        assert!(format!("{err:#}").contains("p@1.0"), "{err:#}");
        let d3 = tmp();
        let c3 = Cache::new(d3.path());
        let err = client(&FakeFetcher::new(), &c3)
            .plugin_checksums("p", "9.9")
            .unwrap_err();
        assert!(format!("{err:#}").contains("404"), "{err:#}");
    }

    #[test]
    fn core_checksums_unknown_version() {
        let d = tmp();
        let c = Cache::new(d.path());
        let f = FakeFetcher::new().with(&core_checksums_url("9.9.9"), r#"{"checksums":false}"#);
        let err = client(&f, &c).core_checksums("9.9.9").unwrap_err();
        assert!(format!("{err:#}").contains("9.9.9"), "{err:#}");
        let f = FakeFetcher::new().with(
            &core_checksums_url("7.1.2"),
            r#"{"checksums":{"index.php":"abc"}}"#,
        );
        let d2 = tmp();
        let c2 = Cache::new(d2.path());
        assert_eq!(
            client(&f, &c2).core_checksums("7.1.2").unwrap()["index.php"],
            "abc"
        );
    }

    #[test]
    fn core_sha1_and_wpcli_sha512_are_validated() {
        let d = tmp();
        let c = Cache::new(d.path());
        let sha1 = "761b8101538f0631a0bfc4fba7bc4abeea92f81c";
        let sha512 = "a".repeat(128);
        let f = FakeFetcher::new()
            .with(&core_sha1_url("7.1.2"), format!("{sha1}\n"))
            .with(
                &wpcli_sha512_url("2.12.0"),
                format!("{sha512}  wp-cli-2.12.0.phar\n"),
            )
            .with(&core_sha1_url("0.0"), "<html>");
        let w = client(&f, &c);
        assert_eq!(w.core_sha1("7.1.2").unwrap(), sha1);
        assert_eq!(w.wpcli_sha512("2.12.0").unwrap(), sha512);
        assert!(w.core_sha1("0.0").is_err());
    }

    #[test]
    fn translations_and_zip_origin_check() {
        let url = translations_url(TransKind::Plugin, Some("wordfence"), "8.1.0");
        assert_eq!(
            url,
            "https://api.wordpress.org/translations/plugins/1.0/?slug=wordfence&version=8.1.0"
        );
        assert_eq!(
            translations_url(TransKind::Core, None, "7.1.2"),
            "https://api.wordpress.org/translations/core/1.0/?version=7.1.2"
        );
        let f = FakeFetcher::new().with(&url, r#"{"translations":[{"language":"hr","version":"8.1.0","updated":"x",
            "english_name":"Croatian","native_name":"Hrvatski","package":"https://downloads.wordpress.org/translation/plugin/wordfence/8.1.0/hr.zip","iso":{"1":"hr"}}]}"#);
        let d = tmp();
        let c = Cache::new(d.path());
        let w = client(&f, &c);
        let t = w
            .translations(TransKind::Plugin, Some("wordfence"), "8.1.0")
            .unwrap();
        assert_eq!(t[0].language, "hr");
        let evil = Translation {
            language: "hr".into(),
            version: "1".into(),
            package: "https://evil.example/hr.zip".into(),
        };
        assert!(w.translation_zip(&evil).is_err());
    }

    #[test]
    fn info_endpoints() {
        let f = FakeFetcher::new()
            .with(&plugin_info_url("gutena-tabs"), r#"{"slug":"gutena-tabs","version":"1.0.11","tested":"7.0.6","requires_php":"5.6"}"#)
            .with(&theme_info_url("t"), r#"{"slug":"t","version":"3.5.1","requires_php":false}"#)
            .with(CORE_VERSION_CHECK_URL, r#"{"offers":[{"response":"upgrade","version":"7.1.2"}]}"#);
        let d = tmp();
        let c = Cache::new(d.path());
        let w = client(&f, &c);
        let p = w.plugin_info("gutena-tabs").unwrap();
        assert_eq!(
            (p.version.as_str(), p.tested.as_deref()),
            ("1.0.11", Some("7.0.6"))
        );
        let t = w.theme_info("t").unwrap();
        assert_eq!((t.version.as_str(), t.requires_php), ("3.5.1", None));
        assert_eq!(w.core_latest().unwrap(), "7.1.2");
        assert_eq!(
            plugin_info_url("x"),
            "https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request%5Bslug%5D=x&request%5Bfields%5D%5Bsections%5D=0"
        );
    }

    #[test]
    fn plugin_checksums_never_use_the_url_cache() {
        let d = tmp();
        let c = Cache::new(d.path());
        let purl = plugin_checksums_url("p", "1.0");
        let poison = FakeFetcher::new().with(&purl, r#"{"files":{"a":{"sha256":"evil"}}}"#);
        c.get_url(&poison, &purl).unwrap();
        let good = FakeFetcher::new().with(&purl, r#"{"files":{"a":{"sha256":"aa"}}}"#);
        assert_eq!(
            client(&good, &c).plugin_checksums("p", "1.0").unwrap()["a"],
            vec!["aa"]
        );
    }

    #[test]
    fn plugin_checksums_are_never_cached_but_bad_core_checksums_are_evicted() {
        let d = tmp();
        let c = Cache::new(d.path());
        let purl = plugin_checksums_url("p", "1.0");
        let bad = FakeFetcher::new().with(&purl, "<html>");
        assert!(client(&bad, &c).plugin_checksums("p", "1.0").is_err());
        assert!(!c.has_url(&purl), "plugin checksums must not be cached");
        let good = FakeFetcher::new().with(&purl, r#"{"files":{"a":{"sha256":"aa"}}}"#);
        assert_eq!(
            client(&good, &c).plugin_checksums("p", "1.0").unwrap()["a"],
            vec!["aa"]
        );
        assert!(!c.has_url(&purl), "plugin checksums must not be cached");

        let curl = core_checksums_url("7.1.2");
        let bad = FakeFetcher::new().with(&curl, r#"{"checksums":false}"#);
        assert!(client(&bad, &c).core_checksums("7.1.2").is_err());
        let good = FakeFetcher::new().with(&curl, r#"{"checksums":{"index.php":"abc"}}"#);
        assert_eq!(
            client(&good, &c).core_checksums("7.1.2").unwrap()["index.php"],
            "abc"
        );
    }

    #[test]
    fn garbage_bodies_are_errors() {
        let d = tmp();
        let c = Cache::new(&d.path().join("c"));
        let turl = translations_url(TransKind::Core, None, "7.1.2");
        for body in ["<html>oops</html>", r#"{"translations":"x"}"#] {
            let f = FakeFetcher::new().with(&turl, body);
            let err = client(&f, &c)
                .translations(TransKind::Core, None, "7.1.2")
                .unwrap_err();
            assert!(format!("{err:#}").contains(&turl), "{body}: {err:#}");
        }
        let purl = plugin_info_url("p");
        let f = FakeFetcher::new().with(&purl, r#"{"name":"p"}"#);
        let err = client(&f, &c).plugin_info("p").unwrap_err();
        assert!(format!("{err:#}").contains("no version"), "{err:#}");
        let f = FakeFetcher::new().with(CORE_VERSION_CHECK_URL, r#"{"offers":[]}"#);
        let err = client(&f, &c).core_latest().unwrap_err();
        assert!(format!("{err:#}").contains("no offers"), "{err:#}");
    }
}
