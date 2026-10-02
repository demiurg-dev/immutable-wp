//! `iwp status` and `iwp releases`.

use super::*;

#[derive(Debug, serde::Serialize)]
struct SiteStatus {
    name: String,
    current: Option<String>,
    previous: Option<String>,
    state: String,
    image: Option<String>,
    releases: usize,
}

impl SiteStatus {
    fn failed(name: &str, msg: &str) -> Self {
        Self {
            name: name.into(),
            current: None,
            previous: None,
            state: format!("error: {msg}"),
            image: None,
            releases: 0,
        }
    }
}

fn site_status(host: &dyn Host, global: &GlobalConfig, site: &Site) -> Result<SiteStatus> {
    let base = crate::host::sys(host, site.base_dir(global));
    let current = crate::lifecycle::releases::current(&base)?;
    let image = current
        .as_deref()
        .and_then(|c| crate::lifecycle::releases::read_manifest(&base, c).ok())
        .map(|m| m.image_digest);
    let state = host
        .run(&crate::host::Cmd::new("systemctl").args([
            "is-active".to_string(),
            format!("iwp-{}.service", site.name),
        ]))
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into());
    Ok(SiteStatus {
        name: site.name.clone(),
        previous: crate::lifecycle::releases::previous(&base)?,
        releases: crate::lifecycle::releases::list(&base)?.len(),
        current,
        state,
        image,
    })
}

fn short_image(id: &str) -> String {
    id.strip_prefix("sha256:")
        .unwrap_or(id)
        .chars()
        .take(12)
        .collect()
}

pub(super) fn status_cmd(
    global: &GlobalConfig,
    site: Option<&str>,
    json: bool,
) -> Result<ExitCode> {
    let host = SystemHost::new();
    let only: Vec<String> = site.map(|s| vec![s.to_string()]).unwrap_or_default();
    let sites = load_valid_sites(global, &only)?;
    let mut rows = Vec::new();
    for l in sites
        .iter()
        .filter(|l| only.is_empty() || l.site.name == only[0])
    {
        rows.push(site_status(&host, global, &l.site).unwrap_or_else(|e| {
            SiteStatus::failed(&l.site.name, &format!("{e:#}").replace('\n', " "))
        }));
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(ExitCode::SUCCESS);
    }
    let dash = |o: &Option<String>| o.clone().unwrap_or_else(|| "-".into());
    println!(
        "{:<20} {:<12} {:<25} {:<25} {:<13} RELEASES",
        "SITE", "STATE", "CURRENT", "PREVIOUS", "IMAGE"
    );
    for r in &rows {
        println!(
            "{:<20} {:<12} {:<25} {:<25} {:<13} {}",
            r.name,
            r.state,
            dash(&r.current),
            dash(&r.previous),
            r.image.as_deref().map(short_image).unwrap_or("-".into()),
            r.releases
        );
    }
    Ok(ExitCode::SUCCESS)
}

pub(super) fn releases_cmd(global: &GlobalConfig, name: &str) -> Result<ExitCode> {
    let host = SystemHost::new();
    let name = site_arg(name)?;
    let sites = load_valid_sites(global, &[name.to_string()])?;
    let site = loaded_site(&sites, name);
    let base = crate::host::sys(&host, site.base_dir(global));
    let list = crate::lifecycle::releases::list(&base)?;
    if list.is_empty() {
        println!("no releases");
        return Ok(ExitCode::SUCCESS);
    }
    let current = crate::lifecycle::releases::current(&base)?;
    let previous = crate::lifecycle::releases::previous(&base)?;
    for r in list {
        let marker = if current.as_deref() == Some(&r) {
            '*'
        } else if previous.as_deref() == Some(&r) {
            '-'
        } else {
            ' '
        };
        let info = match crate::lifecycle::releases::read_manifest(&base, &r) {
            Ok(m) => format!("{}/{}", m.wordpress, m.php),
            Err(_) => "?".into(),
        };
        println!("{marker} {r}  {info}");
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_error_row_carries_message() {
        let r = SiteStatus::failed("acme", "boom");
        assert_eq!(r.state, "error: boom");
        assert_eq!(r.name, "acme");
    }
}
