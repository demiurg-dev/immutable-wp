//! `iwp outdated`: compare pinned versions with wordpress.org (read-only).

use std::cmp::Ordering;

use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

use crate::config::Site;
use crate::fetch::wporg::{Info, WpOrg};

pub fn version_cmp(a: &str, b: &str) -> Ordering {
    let split = |s: &str| {
        s.split(['.', '-', '+'])
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    let (pa, pb) = (split(a), split(b));
    for i in 0..pa.len().max(pb.len()) {
        let x = pa.get(i).map_or("0", String::as_str);
        let y = pb.get(i).map_or("0", String::as_str);
        let all_digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        let ord = if all_digits(x) && all_digits(y) {
            // Compare digit strings numerically without overflow: strip zeros, then length, then lexically.
            let (x, y) = (x.trim_start_matches('0'), y.trim_start_matches('0'));
            x.len().cmp(&y.len()).then_with(|| x.cmp(y))
        } else {
            x.cmp(y)
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}

#[derive(Debug, Clone, PartialEq)]
pub enum Status {
    UpToDate,
    Outdated,
    Pinned,
    Error(String),
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::UpToDate => "uptodate",
            Status::Outdated => "outdated",
            Status::Pinned => "pinned",
            Status::Error(_) => "error",
        }
    }
}

#[derive(Debug, Clone)]
pub struct OutdatedRow {
    pub kind: String,
    pub slug: String,
    pub current: String,
    pub latest: Option<String>,
    pub tested: Option<String>,
    pub status: Status,
}

// Manual impl: serde cannot flatten a newtype-variant enum into a struct cleanly, and the
// `error` key must only appear for Status::Error.
impl Serialize for OutdatedRow {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let n = if matches!(self.status, Status::Error(_)) {
            7
        } else {
            6
        };
        let mut st = s.serialize_struct("OutdatedRow", n)?;
        st.serialize_field("kind", &self.kind)?;
        st.serialize_field("slug", &self.slug)?;
        st.serialize_field("current", &self.current)?;
        st.serialize_field("latest", &self.latest)?;
        st.serialize_field("tested", &self.tested)?;
        st.serialize_field("status", self.status.as_str())?;
        if let Status::Error(m) = &self.status {
            st.serialize_field("error", m)?;
        }
        st.end()
    }
}

fn row(kind: &str, slug: &str, current: &str, info: anyhow::Result<Info>) -> OutdatedRow {
    match info {
        Ok(i) => OutdatedRow {
            kind: kind.into(),
            slug: slug.into(),
            current: current.into(),
            status: if version_cmp(&i.version, current) == Ordering::Greater {
                Status::Outdated
            } else {
                Status::UpToDate
            },
            latest: Some(i.version),
            tested: i.tested,
        },
        Err(e) => OutdatedRow {
            kind: kind.into(),
            slug: slug.into(),
            current: current.into(),
            latest: None,
            tested: None,
            status: Status::Error(format!("{e:#}")),
        },
    }
}

pub fn outdated(w: &WpOrg, site: &Site) -> Vec<OutdatedRow> {
    let mut rows = vec![row(
        "core",
        "wordpress",
        &site.core.wordpress,
        w.core_latest().map(|v| Info {
            version: v,
            tested: None,
            requires_php: None,
            requires: None,
        }),
    )];
    for (kind, list) in [("plugin", &site.plugins), ("theme", &site.themes)] {
        for p in list {
            match &p.version {
                Some(v) => rows.push(row(
                    kind,
                    &p.slug,
                    v,
                    if kind == "plugin" {
                        w.plugin_info(&p.slug)
                    } else {
                        w.theme_info(&p.slug)
                    },
                )),
                None => rows.push(OutdatedRow {
                    kind: kind.into(),
                    slug: p.slug.clone(),
                    current: "source".into(),
                    latest: None,
                    tested: None,
                    status: Status::Pinned,
                }),
            }
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_site;
    use crate::fetch::cache::Cache;
    use crate::fetch::wporg::{CORE_VERSION_CHECK_URL, plugin_info_url, theme_info_url};
    use crate::testutil::{FakeFetcher, tmp};
    use std::cmp::Ordering::*;

    #[test]
    fn json_shape() {
        let r = |status| OutdatedRow {
            kind: "plugin".into(),
            slug: "a".into(),
            current: "1".into(),
            latest: None,
            tested: None,
            status,
        };
        let e = serde_json::to_value(r(Status::Error("boom".into()))).unwrap();
        assert_eq!(e["status"], "error");
        assert_eq!(e["error"], "boom");
        let u = serde_json::to_value(r(Status::UpToDate)).unwrap();
        assert_eq!(u["status"], "uptodate");
        assert!(u.get("error").is_none());
    }

    #[test]
    fn version_ordering() {
        assert_eq!(version_cmp("1.0.10", "1.0.9"), Greater);
        assert_eq!(version_cmp("1.0", "1.0.0"), Equal);
        assert_eq!(version_cmp("1.01", "1.1"), Equal);
        assert_eq!(version_cmp("7.1.2", "7.1.10"), Less);
        assert_eq!(version_cmp("2.0-beta", "2.0-rc"), Less);
    }

    #[test]
    fn rows_for_core_plugins_themes_sources_and_errors() {
        let site = parse_site(&format!(
            r#"
name = "o"
domains = ["o.example.org"]
id = 9
[core]
wordpress = "7.0.6"
php = "8.3"
[[plugin]]
slug = "a"
version = "1.0.11"
[[plugin]]
slug = "b"
version = "2.0"
[[plugin]]
slug = "c"
source = {{ path = "/srv/c" }}
sha256 = "{}"
[[theme]]
slug = "t"
version = "3.5.1"
"#,
            "a".repeat(64)
        ))
        .unwrap();
        let f = FakeFetcher::new()
            .with(
                CORE_VERSION_CHECK_URL,
                r#"{"offers":[{"version":"7.1.2"}]}"#,
            )
            .with(
                &plugin_info_url("a"),
                r#"{"version":"1.0.12","tested":"7.1.2"}"#,
            )
            .with(&theme_info_url("t"), r#"{"version":"3.5.1"}"#);
        let d = tmp();
        let c = Cache::new(d.path());
        let rows = outdated(
            &WpOrg {
                fetcher: &f,
                cache: &c,
            },
            &site,
        );
        let s: Vec<_> = rows
            .iter()
            .map(|r| (r.kind.as_str(), r.slug.as_str(), &r.status))
            .collect();
        assert_eq!(s[0], ("core", "wordpress", &Status::Outdated));
        assert_eq!(s[1], ("plugin", "a", &Status::Outdated));
        assert!(matches!(s[2].2, Status::Error(m) if m.contains("404")));
        assert_eq!(s[3], ("plugin", "c", &Status::Pinned));
        assert_eq!(s[4], ("theme", "t", &Status::UpToDate));
        assert_eq!(rows[1].tested.as_deref(), Some("7.1.2"));
    }
}
