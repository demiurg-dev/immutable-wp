//! `iwp verify`.

use super::*;
use crate::lifecycle::verify::VerifyReport;

fn exit_code(r: &VerifyReport) -> u8 {
    if r.findings.is_empty() { 0 } else { 3 }
}

fn text_output(r: &VerifyReport) -> String {
    if r.findings.is_empty() {
        return "ok".into();
    }
    let mut out = String::new();
    for f in &r.findings {
        let path = f.path.as_deref().unwrap_or("-");
        out.push_str(&format!("{} {}: {}\n", f.kind, path, f.detail));
    }
    out.push_str(&format!("{} finding(s)", r.findings.len()));
    out
}

pub(super) fn verify_cmd(global: &GlobalConfig, name: &str, json: bool) -> Result<ExitCode> {
    let host = SystemHost::new();
    let name = site_arg(name)?;
    let sites = load_valid_sites(global, &[name.to_string()])?;
    let site = loaded_site(&sites, name);
    require_root(&host, "verify")?;
    match run_verify(&host, global, site) {
        Ok(report) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                for n in &report.notes {
                    eprintln!("note: {n}");
                }
                println!("{}", text_output(&report));
            }
            Ok(ExitCode::from(exit_code(&report)))
        }
        Err(e) => {
            if json {
                println!("{}", error_json(name, &e)?);
                Ok(ExitCode::from(1))
            } else {
                Err(e)
            }
        }
    }
}

fn error_json(site: &str, e: &anyhow::Error) -> Result<String> {
    Ok(serde_json::to_string_pretty(
        &serde_json::json!({"site": site, "error": format!("{e:#}")}),
    )?)
}

/// A note when the current release has no snapshot, so `deployed_site` fell back to the site file.
fn snapshot_note(base: &std::path::Path, release: Option<&str>) -> Option<String> {
    let r = release?;
    if crate::lifecycle::releases::snapshot_path(base, r).exists() {
        return None;
    }
    Some(format!(
        "no site snapshot for release {r}; using the current site file (allow_php may differ from what is deployed)"
    ))
}

fn run_verify(host: &SystemHost, global: &GlobalConfig, site: &Site) -> Result<VerifyReport> {
    let mut warnings = Vec::new();
    let mut live = crate::lifecycle::deploy::deployed_site(host, global, site, &mut warnings)?;
    // Who may be an administrator is not release content: the site file decides, undeployed.
    live.verify.admins = site.verify.admins.clone();
    let fetcher = crate::fetch::net::HttpFetcher::new();
    let cache = crate::fetch::cache::Cache::new(&global.cache_dir);
    let ops = crate::lifecycle::verify::SystemVerifyOps {
        host,
        g: global,
        wporg: crate::fetch::wporg::WpOrg {
            fetcher: &fetcher,
            cache: &cache,
        },
    };
    let base = crate::host::sys(host, site.base_dir(global));
    let current = crate::lifecycle::releases::current(&base)?;
    warnings.extend(snapshot_note(&base, current.as_deref()));
    let mut report = crate::lifecycle::verify::verify(host, global, &live, &ops)?;
    report.notes.extend(warnings);
    if global.egress.restrict && !crate::host::egress::loaded(host)? {
        report.findings.push(crate::lifecycle::verify::Finding {
            kind: "egress_not_loaded",
            path: None,
            detail: "[egress] restrict = true, but the nftables table inet iwp_egress is not loaded; run `iwp egress apply`".into(),
        });
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::verify::Finding;

    fn rep(n: usize) -> VerifyReport {
        VerifyReport {
            site: "a".into(),
            findings: (0..n)
                .map(|i| Finding {
                    kind: "release_modified",
                    path: Some(format!("f{i}")),
                    detail: "x".into(),
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn snapshot_note_only_when_missing() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(snapshot_note(d.path(), None), None);
        let n = snapshot_note(d.path(), Some("r1")).unwrap();
        assert_eq!(
            n,
            "no site snapshot for release r1; using the current site file (allow_php may differ from what is deployed)"
        );
        let p = crate::lifecycle::releases::snapshot_path(d.path(), "r1");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, "{}").unwrap();
        assert_eq!(snapshot_note(d.path(), Some("r1")), None);
    }

    #[test]
    fn error_json_shape() {
        let e = anyhow::anyhow!("inner").context("outer");
        let v: serde_json::Value = serde_json::from_str(&error_json("a", &e).unwrap()).unwrap();
        assert_eq!(v["site"], "a");
        assert_eq!(v["error"], "outer: inner");
        assert_eq!(v.as_object().unwrap().len(), 2);
    }

    #[test]
    fn exit_codes() {
        assert_eq!(exit_code(&rep(0)), 0);
        assert_eq!(exit_code(&rep(2)), 3);
    }

    #[test]
    fn text() {
        assert_eq!(text_output(&rep(0)), "ok");
        assert_eq!(
            text_output(&rep(2)),
            "release_modified f0: x\nrelease_modified f1: x\n2 finding(s)"
        );
    }
}
