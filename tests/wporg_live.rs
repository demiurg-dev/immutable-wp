//! Opt-in: IWP_NET_TESTS=1 cargo test --test wporg_live -- --nocapture
use iwp::fetch::cache::Cache;
use iwp::fetch::net::HttpFetcher;
use iwp::fetch::wporg::{TransKind, WpOrg};

#[test]
fn live_wordpress_org_endpoints() {
    if std::env::var_os("IWP_NET_TESTS").is_none() {
        eprintln!("skipped: set IWP_NET_TESTS=1");
        return;
    }
    let d = tempfile::Builder::new()
        .prefix("iwp-test-")
        .tempdir()
        .unwrap();
    let f = HttpFetcher::new();
    let c = Cache::new(d.path());
    let w = WpOrg {
        fetcher: &f,
        cache: &c,
    };

    let sums = w.plugin_checksums("gutena-tabs", "1.0.11").unwrap();
    assert!(
        sums.contains_key("gutena-tabs.php"),
        "{:?}",
        sums.keys().take(5).collect::<Vec<_>>()
    );
    let zip = w.plugin_zip("gutena-tabs", "1.0.11").unwrap();
    let out = d.path().join("gt");
    std::fs::create_dir(&out).unwrap();
    let top = iwp::fetch::archive::extract_zip(&zip, &out, &Default::default()).unwrap();
    assert_eq!(top.as_deref(), Some("gutena-tabs"));
    for (file, allowed) in &sums {
        let got = iwp::hash::sha256_file(&out.join(file)).unwrap();
        assert!(allowed.contains(&got), "{file}");
    }
    assert!(w.core_checksums("7.1.2").unwrap().len() > 1000);
    assert_eq!(w.core_sha1("7.1.2").unwrap().len(), 40);
    assert_eq!(
        w.wpcli_sha512(iwp::host::image::WPCLI_VERSION)
            .unwrap()
            .len(),
        128
    );
    assert!(
        w.translations(TransKind::Core, None, "7.1.2")
            .unwrap()
            .iter()
            .any(|t| t.language == "hr")
    );
    assert!(!w.plugin_info("gutena-tabs").unwrap().version.is_empty());
    assert!(!w.core_latest().unwrap().is_empty());
}
