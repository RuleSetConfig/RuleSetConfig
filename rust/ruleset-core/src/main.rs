//! Validate and project routing companions without widening hostname scope.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const SOURCE: &str = "source/domain-keywords.json";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    schema: u8,
    proxy: Vec<String>,
    direct: Vec<String>,
    #[serde(default)]
    proxy_domain_suffixes: Vec<String>,
    #[serde(default)]
    direct_domain_suffixes: Vec<String>,
    #[serde(default)]
    proxy_domains: Vec<String>,
    #[serde(default)]
    direct_domains: Vec<String>,
    #[serde(default)]
    rule_counts: Option<HashMap<String, usize>>,
}

#[derive(Clone, Default)]
struct Scope {
    words: Vec<String>,
    suffixes: Vec<String>,
    exact: Vec<String>,
}
#[derive(Default)]
struct Domains {
    suffixes: HashSet<String>,
    exact: HashSet<String>,
}

fn covered(host: &str, suffixes: &HashSet<String>, include_self: bool) -> bool {
    (include_self && suffixes.contains(host))
        || host
            .match_indices('.')
            .any(|(i, _)| suffixes.contains(&host[i + 1..]))
}
fn keyword(host: &str, words: &[String]) -> bool {
    words.iter().any(|word| host.contains(word))
}
fn valid_host(host: &str, single_label: bool) -> bool {
    host.len() <= 253
        && (single_label || host.contains('.'))
        && host.parse::<IpAddr>().is_err()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
}
fn host_set(values: &[String]) -> Result<HashSet<String>> {
    let result: HashSet<String> = values.iter().cloned().collect();
    if result.len() != values.len() || values.iter().any(|host| !valid_host(host, false)) {
        return Err("invalid or duplicate companion hostname".into());
    }
    Ok(result)
}
fn domain_set(path: &Path) -> Result<Domains> {
    if !path.is_file() {
        return Ok(Domains::default());
    }
    let mut result = Domains::default();
    for raw in fs::read_to_string(path)?.lines() {
        let row = raw.split('#').next().unwrap_or("").trim();
        if row.is_empty() || row.starts_with("//") {
            continue;
        }
        let suffix = row.starts_with('.');
        let host = row.strip_prefix('.').unwrap_or(row);
        if !valid_host(host, suffix) {
            return Err(format!("invalid DOMAIN-SET host: {row}").into());
        }
        if suffix {
            result.suffixes.insert(host.into());
        } else {
            result.exact.insert(host.into());
        }
    }
    Ok(result)
}
fn prepare(root: &Path, raw: &str) -> Result<[Scope; 2]> {
    let value: Value = serde_json::from_str(raw)?;
    let object = value
        .as_object()
        .ok_or("expected companion policy object")?;
    let schema = object
        .get("schema")
        .and_then(Value::as_u64)
        .ok_or("missing schema")?;
    let mut fields = vec!["schema", "proxy", "direct"];
    match schema {
        1 => (),
        2 | 3 => fields.extend([
            "proxy_domain_suffixes",
            "direct_domain_suffixes",
            "rule_counts",
        ]),
        _ => return Err("unsupported companion policy schema".into()),
    }
    if schema == 3 {
        fields.extend(["proxy_domains", "direct_domains"]);
    }
    if object.len() != fields.len() || fields.iter().any(|key| !object.contains_key(*key)) {
        return Err("unexpected companion policy fields".into());
    }
    let policy: Policy = serde_json::from_value(value)?;
    let mut scopes = [
        Scope {
            words: policy.proxy,
            suffixes: policy.proxy_domain_suffixes,
            exact: policy.proxy_domains,
        },
        Scope {
            words: policy.direct,
            suffixes: policy.direct_domain_suffixes,
            exact: policy.direct_domains,
        },
    ];
    for scope in &mut scopes {
        let unique: HashSet<&String> = scope.words.iter().collect();
        if unique.len() != scope.words.len()
            || scope.words.iter().any(|word| {
                word.bytes().filter(u8::is_ascii_lowercase).count() < 5
                    || !word
                        .bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
            })
        {
            return Err("invalid or duplicate companion keyword".into());
        }
        if policy.schema >= 2
            && scope.words.iter().any(|word| {
                scope
                    .words
                    .iter()
                    .any(|other| word != other && word.contains(other))
            })
        {
            return Err("parent-covered companion keyword".into());
        }
        scope.words.sort();
        scope.suffixes.sort();
        scope.exact.sort();
    }
    if policy.schema == 1 {
        return Ok(scopes);
    }
    let sets = [
        domain_set(&root.join("PROXY-DOMAIN-SET.list"))?,
        domain_set(&root.join("DIRECT-DOMAIN-SET.list"))?,
    ];
    let own = [
        Domains {
            suffixes: host_set(&scopes[0].suffixes)?,
            exact: host_set(&scopes[0].exact)?,
        },
        Domains {
            suffixes: host_set(&scopes[1].suffixes)?,
            exact: host_set(&scopes[1].exact)?,
        },
    ];
    for (i, scope) in scopes.iter().enumerate() {
        for (is_exact, hosts) in [(false, &scope.suffixes), (true, &scope.exact)] {
            for host in hosts {
                if keyword(host, &scope.words)
                    || covered(host, &sets[i].suffixes, true)
                    || (is_exact && sets[i].exact.contains(host))
                {
                    return Err(format!("hostname covered by DOMAIN-SET or keyword: {host}").into());
                }
                if covered(host, &own[i].suffixes, is_exact) {
                    return Err(format!("parent-covered companion hostname: {host}").into());
                }
                let other = 1 - i;
                if keyword(host, &scopes[other].words)
                    || own[other].exact.contains(host)
                    || covered(host, &own[other].suffixes, true)
                    || covered(host, &sets[other].suffixes, true)
                    || (is_exact && sets[other].exact.contains(host))
                {
                    return Err(format!("opposite-policy coverage overlaps: {host}").into());
                }
            }
        }
    }
    let counts = policy.rule_counts.ok_or("missing rule counts")?;
    if counts.len() != 2 {
        return Err("invalid count inventory".into());
    }
    for (i, name) in ["proxy", "direct"].iter().enumerate() {
        let actual = scopes[i].words.len() + scopes[i].suffixes.len() + scopes[i].exact.len();
        if actual == 0 || counts.get(*name) != Some(&actual) {
            return Err(format!("{name}: companion rule count mismatch").into());
        }
    }
    Ok(scopes)
}

#[derive(Serialize)]
struct Document {
    version: u8,
    rules: Vec<Value>,
}
fn project(root: &Path, output: &Path) -> Result<()> {
    fs::create_dir_all(output)?;
    if fs::canonicalize(root)? == fs::canonicalize(output)? {
        return Err("use an isolated output directory".into());
    }
    let scopes = prepare(root, &fs::read_to_string(root.join(SOURCE))?)?;
    for (i, name) in ["proxy", "direct"].iter().enumerate() {
        let scope = &scopes[i];
        let description = if scope.suffixes.is_empty() {
            "domain keywords"
        } else {
            "maintained domain rules"
        };
        let mut text = format!("# Surge RULE-SET; companion {name} {description}.\n# Source: {SOURCE}; do not edit generated outputs.\n");
        if root.join("source/companion-import.json").is_file() {
            text.push_str("# Ranked hostname data: Majestic Million, CC BY 3.0; https://majestic.com/reports/majestic-million\n# Attribution and projection: source/ranked-domain-NOTICE.md.\n");
        }
        let mut rules = Vec::new();
        for (kind, field, values) in [
            ("DOMAIN-KEYWORD", "domain_keyword", &scope.words),
            ("DOMAIN-SUFFIX", "domain_suffix", &scope.suffixes),
            ("DOMAIN", "domain", &scope.exact),
        ] {
            for value in values {
                text.push_str(&format!("{kind},{value}\n"));
            }
            if !values.is_empty() {
                rules.push(json!({field: values}));
            }
        }
        let basename = format!("{}-RULE-SET", name.to_uppercase());
        fs::write(output.join(format!("{basename}.list")), text)?;
        let document = Document { version: 5, rules };
        fs::write(
            output.join(format!("{basename}.json")),
            serde_json::to_string(&document)? + "\n",
        )?;
    }
    let summary = json!({
        "keywords": {"proxy": scopes[0].words, "direct": scopes[1].words},
        "domain_suffixes": {"proxy": scopes[0].suffixes, "direct": scopes[1].suffixes},
        "domains": {"proxy": scopes[0].exact, "direct": scopes[1].exact}
    });
    fs::write(
        output.join("companion-summary.json"),
        serde_json::to_string(&summary)? + "\n",
    )?;
    Ok(())
}
fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut root = PathBuf::from(".");
    let mut output = None;
    let mut index = 0;
    while index < args.len() {
        let value = args
            .get(index + 1)
            .ok_or("expected --root PATH --output-dir PATH")?;
        match args[index].as_str() {
            "--root" => root = PathBuf::from(value),
            "--output-dir" => output = Some(PathBuf::from(value)),
            _ => return Err("unknown argument".into()),
        }
        index += 2;
    }
    project(&root, &output.ok_or("missing --output-dir")?)
}
fn main() {
    if let Err(error) = run() {
        eprintln!("ruleset-core: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn suffix_boundaries_preserve_apex_and_children() {
        let set = HashSet::from(["example.com".to_string()]);
        assert!(covered("example.com", &set, true));
        assert!(covered("child.example.com", &set, true));
        assert!(!covered("notexample.com", &set, true));
        assert!(!covered("example.com.invalid", &set, true));
        assert!(!covered("example.com", &set, false));
    }
    #[test]
    fn projection_retains_exact_host_scope() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("ruleset-core-test-{}-{stamp}", std::process::id()));
        fs::create_dir_all(root.join("source")).unwrap();
        fs::write(root.join(SOURCE), r#"{"schema":3,"proxy":["python"],"direct":["weixin"],"proxy_domain_suffixes":[],"direct_domain_suffixes":[],"proxy_domains":["www.example.com"],"direct_domains":[],"rule_counts":{"proxy":2,"direct":1}}"#).unwrap();
        let output = root.join("output");
        project(&root, &output).unwrap();
        let document: Value =
            serde_json::from_str(&fs::read_to_string(output.join("PROXY-RULE-SET.json")).unwrap())
                .unwrap();
        assert_eq!(document["rules"][1]["domain"], json!(["www.example.com"]));
        assert!(document["rules"][1].get("domain_suffix").is_none());
        let text = fs::read_to_string(output.join("PROXY-RULE-SET.list")).unwrap();
        assert!(text.contains("\nDOMAIN,www.example.com\n"));
        assert!(!text.contains("DOMAIN-SUFFIX,www.example.com"));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn hostnames_keep_bounded_dns_scope() {
        for host in [
            "*.example.com",
            ".example.com",
            "192.0.2.1",
            "UPPER.example",
        ] {
            assert!(!valid_host(host, false));
        }
        assert!(valid_host("xn--fiqs8s", true));
        assert!(valid_host("7-zip.org", false));
    }
    #[test]
    fn unknown_fields_and_counts_fail_closed() {
        assert!(prepare(
            Path::new("."),
            r#"{"schema":1,"proxy":[],"direct":[],"extra":1}"#
        )
        .is_err());
        assert!(prepare(Path::new("."), r#"{"schema":2,"proxy":["python"],"direct":["tencent"],"proxy_domain_suffixes":[],"direct_domain_suffixes":[],"rule_counts":{"proxy":9,"direct":1}}"#).is_err());
    }
}
