use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use iwp::config::{GlobalConfig, parse_site, validate_site};
use iwp::render::{RenderEnv, render_site};

fn files_under(root: &Path) -> BTreeMap<String, String> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, String>) {
        for e in fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(root, &p, out);
            } else {
                let rel = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
                out.insert(rel, fs::read_to_string(&p).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    if root.exists() {
        walk(root, root, &mut out);
    }
    out
}

#[test]
fn golden_cases() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden");
    let update = std::env::var_os("UPDATE_GOLDEN").is_some();
    let mut cases: Vec<PathBuf> = fs::read_dir(&root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_dir())
        .collect();
    cases.sort();
    assert!(
        cases.len() >= 3,
        "expected golden cases in {}",
        root.display()
    );
    for case in cases {
        let site = parse_site(&fs::read_to_string(case.join("site.toml")).unwrap()).unwrap();
        let issues = validate_site(&site, None);
        assert!(issues.is_empty(), "{}: {issues:?}", case.display());
        let rendered = render_site(&GlobalConfig::default(), &site, &RenderEnv::default()).unwrap();
        let expected_dir = case.join("expected");
        if update {
            let _ = fs::remove_dir_all(&expected_dir);
            for (rel, body) in &rendered {
                let p = expected_dir.join(rel);
                fs::create_dir_all(p.parent().unwrap()).unwrap();
                fs::write(p, body).unwrap();
            }
            continue;
        }
        let expected = files_under(&expected_dir);
        let got_keys: Vec<_> = rendered.keys().collect();
        let exp_keys: Vec<_> = expected.keys().collect();
        pretty_assertions::assert_eq!(
            got_keys,
            exp_keys,
            "file set differs for {}",
            case.display()
        );
        for (rel, body) in &rendered {
            pretty_assertions::assert_eq!(body, &expected[rel], "{}/{rel}", case.display());
        }
    }
}
