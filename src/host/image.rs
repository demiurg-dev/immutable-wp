//! Podman-backed container images.

use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use include_dir::{Dir, include_dir};

use crate::build::ImageOps;
use crate::fetch::wporg::WpOrg;

pub const WPCLI_VERSION: &str = "2.12.0";
pub(crate) static CONTAINERFILE: Dir<'static> =
    include_dir!("$CARGO_MANIFEST_DIR/share/containerfile");

pub fn fpm_tag(wp: &str, php: &str) -> String {
    format!("localhost/iwp-fpm:{wp}-php{php}")
}
pub fn cli_tag(wp: &str, php: &str) -> String {
    format!("localhost/iwp-cli:{wp}-php{php}")
}

/// Runs podman capturing stdout; on failure the error includes stderr.
fn podman(args: &[&str]) -> Result<String> {
    let out = Command::new("podman")
        .args(args)
        .output()
        .context("running podman (is it installed?)")?;
    if !out.status.success() {
        bail!(
            "podman {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub struct PodmanImages<'a> {
    pub wporg: WpOrg<'a>,
    pub refresh_base: bool,
}

impl PodmanImages<'_> {
    pub fn exists(&self, tag: &str) -> Result<bool> {
        let out = Command::new("podman")
            .args(["image", "exists", tag])
            .output()
            .context("running podman (is it installed?)")?;
        match out.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => bail!(
                "podman image exists {tag}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        }
    }

    /// The content-derived image ID (locally built images have no registry digest).
    pub fn image_id(&self, tag: &str) -> Result<String> {
        let id = podman(&["image", "inspect", "--format", "{{.Id}}", tag])?;
        if id.is_empty() {
            bail!("podman image inspect {tag}: empty image ID");
        }
        Ok(id)
    }

    pub fn list(&self) -> Result<Vec<String>> {
        let out = podman(&[
            "images",
            "--format",
            "{{.Repository}}:{{.Tag}}",
            "--filter",
            "reference=localhost/iwp-*",
        ])?;
        let mut tags: Vec<String> = out
            .lines()
            .map(str::to_string)
            .filter(|l| !l.is_empty())
            .collect();
        tags.sort();
        tags.dedup();
        Ok(tags)
    }

    pub fn remove(&self, tag: &str) -> Result<()> {
        podman(&["rmi", tag]).map(|_| ())
    }

    pub fn build(&self, wp: &str, php: &str) -> Result<()> {
        let ctx = tempfile::Builder::new().prefix("iwp-image-").tempdir()?;
        CONTAINERFILE
            .extract(ctx.path())
            .context("writing build context")?;
        let sha1 = self.wporg.core_sha1(wp)?;
        let sha512 = self.wporg.wpcli_sha512(WPCLI_VERSION)?;
        let pull = if self.refresh_base {
            "--pull=always"
        } else {
            "--pull=missing"
        };
        let dir = ctx.path().to_str().context("non-UTF-8 temp path")?;
        for (target, tag) in [
            ("production", fpm_tag(wp, php)),
            ("maintenance", cli_tag(wp, php)),
        ] {
            let st = Command::new("podman")
                .args(["build", pull, "--target", target, "-t", &tag])
                .args([
                    "--label",
                    &format!("iwp.wordpress={wp}"),
                    "--label",
                    &format!("iwp.php={php}"),
                ])
                .args(["--build-arg", &format!("PHP_VERSION={php}")])
                .args(["--build-arg", &format!("WORDPRESS_VERSION={wp}")])
                .args(["--build-arg", &format!("WORDPRESS_SHA1={sha1}")])
                .args(["--build-arg", &format!("WPCLI_VERSION={WPCLI_VERSION}")])
                .args(["--build-arg", &format!("WPCLI_SHA512={sha512}")])
                .args(["-f", &format!("{dir}/Containerfile"), dir])
                .stdin(Stdio::null())
                .status()
                .context("running podman build")?;
            if !st.success() {
                bail!("podman build of {tag} failed");
            }
        }
        Ok(())
    }
}

impl ImageOps for PodmanImages<'_> {
    fn ensure(&self, wp: &str, php: &str) -> Result<String> {
        if !self.exists(&fpm_tag(wp, php))? || !self.exists(&cli_tag(wp, php))? {
            self.build(wp, php)?;
        }
        self.image_id(&fpm_tag(wp, php))
    }

    fn export_webroot(&self, image: &str, dest: &Path) -> Result<()> {
        std::fs::create_dir_all(dest)?;
        let dest_s = dest.to_str().context("non-UTF-8 path")?;
        let id = podman(&["create", image])?;
        let copied = podman(&["cp", &format!("{id}:/var/www/html/."), dest_s]);
        let removed = podman(&["rm", &id]);
        copied?;
        removed?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_match_site_helpers() {
        let s = crate::config::parse_site(include_str!("../../examples/acme.toml")).unwrap();
        let (wp, php) = (s.core.wordpress.clone(), s.core.php.clone());
        assert_eq!(fpm_tag(&wp, &php), s.fpm_image());
        assert_eq!(cli_tag(&wp, &php), s.cli_image());
    }
}
