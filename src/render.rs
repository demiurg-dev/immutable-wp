use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use include_dir::{Dir, include_dir};
use minijinja::{AutoEscape, Environment};
use serde::Serialize;

use crate::config::{ConstValue, GlobalConfig, Site, shared_rel};
use crate::host::identity::Identity;

pub(crate) static TEMPLATES: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/share/templates");

#[derive(Debug, Clone)]
pub struct RenderEnv {
    /// Gateway of the podman network; the container reaches host MariaDB here.
    pub db_host_ip: Ipv4Addr,
    pub iwp_bin: PathBuf,
    /// Overrides the quadlet `Image=` (e.g. an image id); `None` uses the site's fpm tag.
    pub image: Option<String>,
}

impl Default for RenderEnv {
    fn default() -> Self {
        Self {
            db_host_ip: Ipv4Addr::new(10, 88, 0, 1),
            iwp_bin: crate::BIN_PATH.into(),
            image: None,
        }
    }
}

#[derive(Serialize)]
struct Mount {
    /// Path under the WP root, e.g. wp-content/wflogs
    rel: String,
    /// Path under <base>/shared, e.g. wflogs
    shared: String,
}

#[derive(Serialize)]
struct PhpConst {
    name: String,
    value: String,
}

#[derive(Serialize)]
struct PhpCtx {
    memory_limit: String,
    upload_max_filesize: String,
    post_max_size: String,
    max_execution_time: u32,
    fastcgi_read_timeout: u32,
    request_terminate_timeout: u32,
    disable_functions: String,
    max_children: u32,
    start_servers: u32,
    min_spare: u32,
    max_spare: u32,
}

#[derive(Serialize)]
struct Ctx {
    db_charset: Option<String>,
    db_collate: Option<String>,
    name: String,
    domains: Vec<String>,
    base: String,
    image: String,
    uid_base: u32,
    www_uid: u32,
    selinux_level: String,
    tmp_size: String,
    memory_max_mib: u64,
    network: String,
    nginx_group: String,
    db_host_ip: String,
    iwp_bin: String,
    /// Failed verify runs are mailed (`alert_email` is set).
    alert: bool,
    writable: Vec<Mount>,
    dropins: Vec<String>,
    writable_regex: String,
    extra_entrypoints: Vec<String>,
    constants: Vec<PhpConst>,
    multisite_domain: Option<String>,
    multisite_path: String,
    multisite_site_id: u32,
    multisite_blog_id: u32,
    php: PhpCtx,
}

pub fn php_literal(v: &ConstValue) -> String {
    match v {
        ConstValue::Bool(b) => b.to_string(),
        ConstValue::Int(i) => i.to_string(),
        ConstValue::Str(s) => format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'")),
    }
}

pub fn output_paths(name: &str) -> Vec<String> {
    vec![
        format!("containers/iwp-{name}.container"),
        format!("nginx/{name}.conf"),
        format!("nginx/{name}.fastcgi.conf"),
        "config/wp-config.site.php".into(),
        "config/zz-site.ini".into(),
        "config/zz-site.conf".into(),
        format!("systemd/iwp-{name}-cron.service"),
        format!("systemd/iwp-{name}-cron.timer"),
        format!("systemd/iwp-{name}-verify.service"),
        format!("systemd/iwp-{name}-verify.timer"),
        format!("tmpfiles/iwp-{name}.conf"),
    ]
}

/// Template name for each output path, parallel to `output_paths`.
fn template_for(path: &str) -> &'static str {
    match path {
        p if p.starts_with("containers/") => "quadlet.container.j2",
        p if p.ends_with(".fastcgi.conf") => "nginx-fastcgi.conf.j2",
        p if p.starts_with("nginx/") => "nginx-site.conf.j2",
        "config/wp-config.site.php" => "wp-config.site.php.j2",
        "config/zz-site.ini" => "zz-site.ini.j2",
        "config/zz-site.conf" => "zz-site.conf.j2",
        p if p.ends_with("-cron.service") => "cron.service.j2",
        p if p.ends_with("-cron.timer") => "cron.timer.j2",
        p if p.ends_with("-verify.service") => "verify.service.j2",
        p if p.ends_with("-verify.timer") => "verify.timer.j2",
        p if p.starts_with("tmpfiles/") => "tmpfiles.conf.j2",
        other => unreachable!("no template for {other}"),
    }
}

fn environment() -> Result<Environment<'static>> {
    let mut env = Environment::new();
    env.set_auto_escape_callback(|_| AutoEscape::None);
    env.set_trim_blocks(true);
    env.set_lstrip_blocks(true);
    env.set_keep_trailing_newline(true);
    env.set_undefined_behavior(minijinja::UndefinedBehavior::Strict);
    for f in TEMPLATES.files() {
        let name = f.path().to_string_lossy().into_owned();
        let src = f
            .contents_utf8()
            .with_context(|| format!("template {name} is not UTF-8"))?;
        env.add_template_owned(name, src.to_owned())?;
    }
    Ok(env)
}

fn context(g: &GlobalConfig, site: &Site, env: &RenderEnv) -> Ctx {
    let id = Identity::for_site(site.id, g.id_offset);
    let writable: Vec<Mount> = site
        .writable_paths()
        .into_iter()
        .map(|w| Mount {
            rel: w.to_string(),
            shared: shared_rel(w).to_string(),
        })
        .collect();
    let writable_regex = std::iter::once("uploads".to_string())
        .chain(writable.iter().map(|m| m.shared.replace('.', "\\.")))
        .collect::<Vec<_>>()
        .join("|");
    let p = &site.php;
    Ctx {
        db_charset: site.database.charset.clone(),
        db_collate: site.database.collate.clone(),
        name: site.name.clone(),
        domains: site.domains.clone(),
        base: site.base_dir(g).to_string_lossy().into_owned(),
        image: env.image.clone().unwrap_or_else(|| site.fpm_image()),
        uid_base: id.base_id,
        www_uid: id.www_uid,
        selinux_level: id.selinux_level(),
        tmp_size: site.tmp_size(),
        memory_max_mib: site.memory_max_mib(),
        network: g.podman_network.clone(),
        nginx_group: g.nginx_group.clone(),
        db_host_ip: env.db_host_ip.to_string(),
        iwp_bin: env.iwp_bin.to_string_lossy().into_owned(),
        alert: g.alert_email.is_some(),
        writable,
        dropins: site.dropins.keys().cloned().collect(),
        writable_regex,
        extra_entrypoints: site.nginx.php_entrypoints.clone(),
        constants: site
            .config
            .constants
            .iter()
            .map(|(k, v)| PhpConst {
                name: k.clone(),
                value: php_literal(v),
            })
            .collect(),
        multisite_domain: site.config.multisite.as_ref().map(|m| m.domain.clone()),
        multisite_path: site
            .config
            .multisite
            .as_ref()
            .map_or_else(|| "/".to_string(), |m| m.path.clone()),
        multisite_site_id: site.config.multisite.as_ref().map_or(1, |m| m.site_id),
        multisite_blog_id: site.config.multisite.as_ref().map_or(1, |m| m.blog_id),
        php: PhpCtx {
            memory_limit: p.memory_limit.clone(),
            upload_max_filesize: p.upload_max_filesize.clone(),
            post_max_size: p.post_max_size.clone(),
            max_execution_time: p.max_execution_time,
            fastcgi_read_timeout: p.max_execution_time + 10,
            request_terminate_timeout: p.max_execution_time + 30,
            disable_functions: p.disable_functions.join(","),
            max_children: p.fpm.max_children,
            start_servers: p.fpm.start_servers,
            min_spare: p.fpm.min_spare,
            max_spare: p.fpm.max_spare,
        },
    }
}

/// Renders every generated file for `site`. `site` must already be validated.
pub fn render_site(
    g: &GlobalConfig,
    site: &Site,
    env: &RenderEnv,
) -> Result<BTreeMap<String, String>> {
    let jenv = environment()?;
    let ctx = context(g, site, env);
    let mut out = BTreeMap::new();
    for path in output_paths(&site.name) {
        let tmpl = template_for(&path);
        let body = jenv
            .get_template(tmpl)?
            .render(&ctx)
            .with_context(|| format!("rendering {tmpl}"))?;
        out.insert(path, body);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ConstValue, GlobalConfig, parse_site};

    fn acme() -> BTreeMap<String, String> {
        let s = parse_site(include_str!("../examples/acme.toml")).unwrap();
        render_site(&GlobalConfig::default(), &s, &RenderEnv::default()).unwrap()
    }

    #[test]
    fn php_literals() {
        assert_eq!(php_literal(&ConstValue::Bool(false)), "false");
        assert_eq!(php_literal(&ConstValue::Int(-3)), "-3");
        assert_eq!(
            php_literal(&ConstValue::Str(r"it's a \ test".into())),
            r"'it\'s a \\ test'"
        );
    }

    #[test]
    fn wp_config_site() {
        let out = acme();
        let php = &out["config/wp-config.site.php"];
        assert!(php.starts_with("<?php\n// Generated by iwp for site acme."));
        assert!(php.contains("define( 'MULTISITE', true );"));
        assert!(php.contains("define( 'SUBDOMAIN_INSTALL', true );"));
        assert!(php.contains("define( 'DOMAIN_CURRENT_SITE', 'www.example.org' );"));
        assert!(php.contains("define( 'WFWAF_STORAGE_ENGINE', 'mysqli' );"));
        assert!(php.contains("define( 'WP_DEBUG', false );"));
        assert!(!php.contains("DB_PASSWORD"));
    }

    #[test]
    fn multisite_path_and_ids_are_rendered() {
        let w = &acme()["config/wp-config.site.php"];
        assert!(w.contains("define( 'PATH_CURRENT_SITE', '/' );"), "{w}");
        assert!(w.contains("define( 'SITE_ID_CURRENT_SITE', 1 );"), "{w}");
        assert!(w.contains("define( 'BLOG_ID_CURRENT_SITE', 1 );"), "{w}");
        let text = include_str!("../examples/acme.toml").replace(
            "multisite = { subdomain = true, domain = \"www.example.org\" }",
            "multisite = { subdomain = true, domain = \"www.example.org\", path = \"/net/\", site_id = 2, blog_id = 5 }",
        );
        let s = parse_site(&text).unwrap();
        assert!(crate::config::validate_site(&s, Some("acme")).is_empty());
        let out = render_site(&GlobalConfig::default(), &s, &RenderEnv::default()).unwrap();
        let w = &out["config/wp-config.site.php"];
        assert!(w.contains("define( 'PATH_CURRENT_SITE', '/net/' );"), "{w}");
        assert!(w.contains("define( 'SITE_ID_CURRENT_SITE', 2 );"), "{w}");
        assert!(w.contains("define( 'BLOG_ID_CURRENT_SITE', 5 );"), "{w}");
    }

    #[test]
    fn wp_config_site_charset_only_when_set() {
        let mut s = crate::config::parse_site(include_str!("../examples/simple.toml")).unwrap();
        let out = render_site(&GlobalConfig::default(), &s, &RenderEnv::default()).unwrap();
        assert!(!out["config/wp-config.site.php"].contains("DB_CHARSET"));
        s.database.charset = Some("utf8".into());
        s.database.collate = Some("".into());
        let out = render_site(&GlobalConfig::default(), &s, &RenderEnv::default()).unwrap();
        let w = &out["config/wp-config.site.php"];
        assert!(w.contains("define( 'DB_CHARSET', 'utf8' );"), "{w}");
        assert!(w.contains("define( 'DB_COLLATE', '' );"), "{w}");
    }

    #[test]
    fn php_ini_and_pool() {
        let out = acme();
        let ini = &out["config/zz-site.ini"];
        assert!(ini.contains("memory_limit = 256M\n"));
        assert!(ini.contains("upload_max_filesize = 256M\n"));
        assert!(ini.contains("max_execution_time = 120\n"));
        assert!(
            ini.contains("disable_functions = exec,shell_exec,system,passthru,proc_open,popen\n")
        );
        let pool = &out["config/zz-site.conf"];
        assert!(pool.contains("[www]\n"));
        assert!(pool.contains("pm.max_children = 20\n"));
        assert!(pool.contains("pm.start_servers = 4\n"));
        assert!(pool.contains("request_terminate_timeout = 150s\n"));
    }

    #[test]
    fn deterministic() {
        assert_eq!(acme(), acme());
    }

    fn complex_site() -> crate::config::Site {
        let mut s = parse_site(include_str!("../examples/acme.toml")).unwrap();
        s.nginx.php_entrypoints = vec!["/wp-content/plugins/some-plugin/ajax.php".into()];
        s
    }

    fn pos(hay: &str, needle: &str) -> usize {
        hay.find(needle)
            .unwrap_or_else(|| panic!("missing {needle:?} in:\n{hay}"))
    }

    #[test]
    fn nginx_rule_order_is_fixed() {
        let out = render_site(
            &GlobalConfig::default(),
            &complex_site(),
            &RenderEnv::default(),
        )
        .unwrap();
        let n = &out["nginx/acme.conf"];
        let deny_hidden = pos(n, "location ~ /\\.(?!well-known/)");
        let deny_writable = pos(
            n,
            "location ~* ^/wp-content/(?:uploads|wflogs)/.*\\.(?:php[0-9]?|phtml|phar)$",
        );
        let cron = pos(n, "location = /wp-cron.php");
        let extra = pos(n, "location = /wp-content/plugins/some-plugin/ajax.php");
        let core = pos(
            n,
            "location ~ ^/(?:index|wp-login|wp-signup|wp-activate|wp-comments-post|wp-trackback|wp-links-opml|wp-mail)\\.php$",
        );
        let admin = pos(
            n,
            "location ~ ^/wp-admin/(?:network/|user/)?[a-z0-9_-]+\\.php$",
        );
        let other_php = pos(n, "location ~* \\.(?:php[0-9]?|phtml|phar)$");
        let fallback = pos(n, "location / {");
        assert!(
            deny_hidden < deny_writable
                && deny_writable < cron
                && cron < extra
                && extra < core
                && core < admin
                && admin < other_php
                && other_php < fallback,
            "{n}"
        );
        assert!(n.contains("root /var/www/vhosts/example.org/iwp/current;"));
        assert!(n.contains("include iwp/acme.fastcgi.conf;"));
        assert!(n.contains("try_files $uri /index.php?$args;"));
        assert!(
            !n.contains("$uri/"),
            "directory try_files would 403 on a PHP-less release"
        );
    }

    #[test]
    fn nginx_denies_docs_and_xmlrpc() {
        let n = &acme()["nginx/acme.conf"];
        for loc in [
            "location = /readme.html",
            "location = /license.txt",
            "location = /xmlrpc.php",
            "location = /wp-config.php",
            "location = /wp-config-sample.php",
        ] {
            assert!(n.contains(&format!("{loc} {{ deny all; }}")), "{loc}");
        }
    }

    #[test]
    fn fastcgi_params_file() {
        let f = &acme()["nginx/acme.fastcgi.conf"];
        assert!(f.contains("fastcgi_pass unix:/run/iwp/acme/php.sock;"));
        assert!(f.contains("fastcgi_param SCRIPT_FILENAME /var/www/html$fastcgi_script_name;"));
        assert!(f.contains("fastcgi_param DOCUMENT_ROOT /var/www/html;"));
        assert!(f.contains("fastcgi_param HTTPS $https if_not_empty;"));
        assert!(f.contains("fastcgi_read_timeout 130s;"));
        assert!(!f.contains("include fastcgi_params"));
    }

    #[test]
    fn quadlet() {
        let q = &acme()["containers/iwp-acme.container"];
        for line in [
            "Image=localhost/iwp-fpm:7.1.2-php8.3",
            "ContainerName=iwp-acme",
            "ReadOnly=true",
            "DropCapability=ALL",
            "NoNewPrivileges=true",
            "UIDMap=0:296608:65536",
            "GIDMap=0:296608:65536",
            "SecurityLabelLevel=s0:c3,c515",
            "Network=podman",
            "AddHost=iwp-db-host:10.88.0.1",
            "Secret=iwp-acme-db,type=mount,target=iwp-db,uid=33,gid=33,mode=0400",
            "Secret=iwp-acme-salts,type=mount,target=iwp-salts,uid=33,gid=33,mode=0400",
            "Volume=/var/www/vhosts/example.org/iwp/current/wp-content/plugins:/var/www/html/wp-content/plugins:ro",
            "Volume=/var/www/vhosts/example.org/iwp/shared/uploads:/var/www/html/wp-content/uploads:rw,noexec,nosuid,nodev",
            "Volume=/var/www/vhosts/example.org/iwp/shared/wflogs:/var/www/html/wp-content/wflogs:rw,noexec,nosuid,nodev",
            "Volume=/var/www/vhosts/example.org/iwp/config/wp-config.site.php:/etc/iwp/wp-config.site.php:ro",
            "Volume=/run/iwp/acme:/run/iwp:rw,noexec,nosuid,nodev",
        ] {
            assert!(q.lines().any(|l| l == line), "missing {line:?} in:\n{q}");
        }
        assert!(
            !q.contains(":Z") && !q.contains(":z"),
            "labels are managed by iwp, not podman relabel"
        );
        assert!(!q.contains("PublishPort"), "no TCP");
    }

    #[test]
    fn quadlet_limits() {
        let g = GlobalConfig::default();
        let mut site = parse_site(include_str!("../examples/simple.toml")).unwrap();
        let q = |s: &crate::config::Site| {
            render_site(&g, s, &RenderEnv::default()).unwrap()["containers/iwp-simple.container"]
                .clone()
        };
        // Defaults: /tmp is capped, memory is what the pool can legitimately use:
        // max_children (10) x memory_limit (256M) + /tmp (1G) + 384M overhead.
        let d = q(&site);
        assert!(
            d.contains("\nTmpfs=/tmp:rw,size=1G,mode=1777,noexec,nosuid,nodev\n"),
            "{d}"
        );
        // An out-of-memory kill takes one worker, not the whole site.
        assert!(
            d.contains("\n[Service]\nMemoryMax=3968M\nOOMPolicy=continue\n"),
            "{d}"
        );
        site.limits.tmp_size = Some("512M".into());
        site.limits.memory = Some("2G".into());
        let o = q(&site);
        assert!(o.contains("\nTmpfs=/tmp:rw,size=512M,"), "{o}");
        assert!(o.contains("\nMemoryMax=2048M\n"), "{o}");
    }

    #[test]
    fn quadlet_dropins() {
        let mut s = complex_site();
        s.plugins.push(crate::config::Package {
            slug: "redis-cache".into(),
            version: Some("2.6.0".into()),
            source: None,
            sha256: None,
            writable: vec![],
            cache: vec![],
            mu: false,
            hold: false,
        });
        s.dropins.insert(
            "object-cache.php".into(),
            crate::config::Dropin {
                plugin: "redis-cache".into(),
                file: "includes/object-cache.php".into(),
            },
        );
        let q = &render_site(&GlobalConfig::default(), &s, &RenderEnv::default()).unwrap()["containers/iwp-acme.container"];
        assert!(q.contains("Volume=/var/www/vhosts/example.org/iwp/current/wp-content/object-cache.php:/var/www/html/wp-content/object-cache.php:ro"));
    }

    #[test]
    fn timers_and_tmpfiles() {
        let out = acme();
        assert!(
            out["systemd/iwp-acme-cron.service"]
                .contains("ExecStart=/usr/local/bin/iwp cron acme\n")
        );
        assert!(out["systemd/iwp-acme-cron.timer"].contains("OnUnitActiveSec=5min\n"));
        assert!(
            out["systemd/iwp-acme-verify.service"]
                .contains("ExecStart=/usr/local/bin/iwp verify acme\n")
        );
        assert!(out["systemd/iwp-acme-verify.timer"].contains("OnCalendar=daily\n"));
    }

    #[test]
    fn phase3a_template_changes() {
        let out = acme();
        let t = &out["tmpfiles/iwp-acme.conf"];
        assert!(
            !t.contains("d /run/iwp 0755"),
            "shared /run/iwp line moved to iwp.conf"
        );
        assert!(t.contains("d /run/iwp/acme 0710 root nginx -\n"), "{t}");
        // Explicit mask: the `d` line's chmod 0710 leaves the ACL mask at --x, which made the
        // www entry effectively --x and FPM could not bind its socket (found by e2e).
        assert!(
            t.contains("a+ /run/iwp/acme - - - - u:296641:rwx,m::rwx\n"),
            "{t}"
        );
        assert!(out["nginx/acme.fastcgi.conf"].contains("fastcgi_intercept_errors off;"));
        let cron = &out["systemd/iwp-acme-cron.service"];
        assert!(
            cron.contains("Requisite=iwp-acme.service\n") && !cron.contains("Requires="),
            "{cron}"
        );
        assert!(cron.contains("TimeoutStartSec=10min\n"));
        assert!(out["systemd/iwp-acme-verify.service"].contains("TimeoutStartSec=30min\n"));
        let q = &out["containers/iwp-acme.container"];
        assert!(q.lines().any(|l| l == "Pull=never"));
        assert!(
            q.lines()
                .any(|l| l == "Image=localhost/iwp-fpm:7.1.2-php8.3")
        );
    }

    #[test]
    fn image_override() {
        let s = crate::config::parse_site(include_str!("../examples/acme.toml")).unwrap();
        let env = RenderEnv {
            image: Some("0123456789ab".into()),
            ..RenderEnv::default()
        };
        let q = &render_site(&GlobalConfig::default(), &s, &env).unwrap()["containers/iwp-acme.container"];
        assert!(q.lines().any(|l| l == "Image=0123456789ab"), "{q}");
    }

    #[test]
    fn no_placeholders_left() {
        for (path, body) in acme() {
            assert!(!body.contains("# pending"), "{path} is still a placeholder");
        }
    }
}
