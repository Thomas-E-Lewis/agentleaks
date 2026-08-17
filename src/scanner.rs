//! The scanning engine: applies rules to file content and produces findings.

use crate::rules::{self, Severity};
use crate::stores::FoundFile;
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: &'static str,
    pub rule_name: &'static str,
    pub severity: Severity,
    pub agent: &'static str,
    pub store_label: &'static str,
    pub file: PathBuf,
    /// 1-based line number of the (first) occurrence.
    pub line: usize,
    /// The raw secret. Held in memory for scrubbing; only ever printed
    /// masked unless the user passes --unmask.
    pub secret: String,
    /// Dotted path of the JSON value containing the secret, when known.
    pub json_path: Option<String>,
    /// True when the secret only appears after JSON string decoding
    /// (i.e. it contains escape sequences in the raw text).
    pub escaped_only: bool,
}

impl Finding {
    pub fn masked(&self) -> String {
        rules::mask(&self.secret)
    }
    pub fn fingerprint(&self) -> String {
        rules::fingerprint(&self.secret)
    }
}

/// Scan one file from disk.
pub fn scan_file(found: &FoundFile) -> Result<Vec<Finding>> {
    let bytes =
        std::fs::read(&found.path).with_context(|| format!("reading {}", found.path.display()))?;
    // Binary files are not agent transcripts; skip them quietly.
    if bytes[..bytes.len().min(8192)].contains(&0) {
        return Ok(Vec::new());
    }
    let content = String::from_utf8_lossy(&bytes);
    let is_jsonl = found
        .path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("jsonl"));
    Ok(scan_content(
        &content,
        is_jsonl,
        found.agent,
        found.label,
        &found.path,
    ))
}

/// Scan a string of content. Exposed for tests and for stdin-style input.
pub fn scan_content(
    content: &str,
    is_jsonl: bool,
    agent: &'static str,
    store_label: &'static str,
    path: &std::path::Path,
) -> Vec<Finding> {
    let compiled = rules::compiled();
    let mut findings: Vec<Finding> = Vec::new();
    // Byte spans (into `content`) already claimed by an earlier rule.
    let mut claimed: Vec<(usize, usize)> = Vec::new();
    // (line, rule_id, secret) triples already reported.
    let mut seen: std::collections::HashSet<(usize, &'static str, String)> =
        std::collections::HashSet::new();

    let overlaps = |claimed: &[(usize, usize)], start: usize, end: usize| {
        claimed.iter().any(|&(s, e)| start < e && s < end)
    };
    let line_of = |offset: usize| content[..offset].matches('\n').count() + 1;

    // Block rules first (PEM blocks can span lines and would otherwise be
    // shredded into meaningless per-line generic matches).
    for (rule, re) in &compiled.block_rules {
        for caps in re.captures_iter(content) {
            let m = caps.get(rule.group).expect("group in pattern");
            if overlaps(&claimed, m.start(), m.end()) {
                continue;
            }
            let secret = m.as_str().to_string();
            if rules::is_allowlisted(&secret) {
                continue;
            }
            claimed.push((m.start(), m.end()));
            let line = line_of(m.start());
            if seen.insert((line, rule.id, secret.clone())) {
                findings.push(Finding {
                    rule_id: rule.id,
                    rule_name: rule.name,
                    severity: rule.severity,
                    agent,
                    store_label,
                    file: path.to_path_buf(),
                    line,
                    secret,
                    json_path: None,
                    escaped_only: false,
                });
            }
        }
    }

    // Line rules over the raw text. Secrets are almost always plain
    // ASCII tokens, so they appear verbatim even inside JSON strings.
    let mut offset = 0usize;
    for (idx, line_text) in content.split_inclusive('\n').enumerate() {
        let line_no = idx + 1;
        if compiled.line_set.is_match(line_text) {
            for set_idx in compiled.line_set.matches(line_text) {
                let (rule, re) = &compiled.line_rules[set_idx];
                for caps in re.captures_iter(line_text) {
                    let m = caps.get(rule.group).expect("group in pattern");
                    let (gs, ge) = (offset + m.start(), offset + m.end());
                    if overlaps(&claimed, gs, ge) {
                        continue;
                    }
                    let secret = m.as_str().to_string();
                    if rules::is_allowlisted(&secret) || rules::is_false_positive(rule.id, &secret)
                    {
                        continue;
                    }
                    if let Some(min) = rule.min_entropy {
                        if rules::shannon_entropy(&secret) < min {
                            continue;
                        }
                    }
                    claimed.push((gs, ge));
                    if seen.insert((line_no, rule.id, secret.clone())) {
                        let json_path =
                            is_jsonl.then(|| json_path_of(line_text, &secret)).flatten();
                        findings.push(Finding {
                            rule_id: rule.id,
                            rule_name: rule.name,
                            severity: rule.severity,
                            agent,
                            store_label,
                            file: path.to_path_buf(),
                            line: line_no,
                            secret,
                            json_path,
                            escaped_only: false,
                        });
                    }
                }
            }
        }
        offset += line_text.len();
    }

    // Decode pass for JSONL: catches secrets whose raw form is broken up
    // by JSON escape sequences (e.g. passwords containing quotes).
    if is_jsonl {
        let raw_secrets: std::collections::HashSet<&str> =
            findings.iter().map(|f| f.secret.as_str()).collect();
        let mut decoded: Vec<Finding> = Vec::new();
        for (idx, line_text) in content.lines().enumerate() {
            let line_no = idx + 1;
            // Escape-splitting requires two consecutive backslashes in the
            // raw text (an escaped backslash or a double-escaped quote);
            // lines without them cannot hide anything from the raw pass.
            if !line_text.contains(r"\\") {
                continue;
            }
            let Ok(value) = serde_json::from_str::<Value>(line_text) else {
                continue;
            };
            walk_strings(&value, &mut String::new(), &mut |json_path, s| {
                if !compiled.line_set.is_match(s) {
                    return;
                }
                for set_idx in compiled.line_set.matches(s) {
                    let (rule, re) = &compiled.line_rules[set_idx];
                    for caps in re.captures_iter(s) {
                        let m = caps.get(rule.group).expect("group in pattern");
                        let secret = m.as_str().to_string();
                        if raw_secrets.contains(secret.as_str())
                            || rules::is_allowlisted(&secret)
                            || rules::is_false_positive(rule.id, &secret)
                        {
                            continue;
                        }
                        if let Some(min) = rule.min_entropy {
                            if rules::shannon_entropy(&secret) < min {
                                continue;
                            }
                        }
                        decoded.push(Finding {
                            rule_id: rule.id,
                            rule_name: rule.name,
                            severity: rule.severity,
                            agent,
                            store_label,
                            file: path.to_path_buf(),
                            line: line_no,
                            secret,
                            json_path: Some(json_path.to_string()),
                            escaped_only: true,
                        });
                    }
                }
            });
        }
        let mut seen_decoded = std::collections::HashSet::new();
        for f in decoded {
            if seen_decoded.insert((f.line, f.rule_id, f.secret.clone())) {
                findings.push(f);
            }
        }
    }

    findings.sort_by(|a, b| (a.line, a.rule_id).cmp(&(b.line, b.rule_id)));
    findings
}

/// Locate the dotted path of the first JSON string value containing
/// `needle` within a JSONL line, e.g. `message.content[0].text`.
fn json_path_of(line: &str, needle: &str) -> Option<String> {
    let value: Value = serde_json::from_str(line.trim_end()).ok()?;
    let mut result = None;
    walk_strings(&value, &mut String::new(), &mut |path, s| {
        if result.is_none() && s.contains(needle) {
            result = Some(path.to_string());
        }
    });
    result
}

fn walk_strings(value: &Value, path: &mut String, visit: &mut dyn FnMut(&str, &str)) {
    match value {
        Value::String(s) => visit(path, s),
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                let saved = path.len();
                path.push_str(&format!("[{i}]"));
                walk_strings(item, path, visit);
                path.truncate(saved);
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                let saved = path.len();
                if !path.is_empty() {
                    path.push('.');
                }
                path.push_str(key);
                walk_strings(item, path, visit);
                path.truncate(saved);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fake_anthropic_key() -> String {
        format!("sk-ant-api03-{}", "aB3dEfGh1JkLmN0p".repeat(6))
    }

    #[test]
    fn finds_secret_in_jsonl_tool_result() {
        let key = fake_anthropic_key();
        let line = serde_json::json!({
            "type": "user",
            "message": {
                "content": [{"type": "tool_result", "content": format!("ANTHROPIC_API_KEY={key}")}]
            }
        });
        let content = format!("{line}\n");
        let findings = scan_content(&content, true, "Claude Code", "test", Path::new("s.jsonl"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "anthropic-api-key");
        assert_eq!(findings[0].line, 1);
        assert_eq!(
            findings[0].json_path.as_deref(),
            Some("message.content[0].content")
        );
        assert!(!findings[0].escaped_only);
    }

    #[test]
    fn finds_escaped_secret_via_decode_pass() {
        // Doubly-nested JSON (an API response captured inside a tool
        // result): the quotes around "api_key" are double-escaped in the
        // raw text, so only the decode pass can see the assignment.
        let secret = "hVx91mPqL0siTk3ZbNwyRe8u";
        let inner = serde_json::json!({ "api_key": secret }).to_string();
        let middle = serde_json::json!({ "payload": inner }).to_string();
        let line = serde_json::json!({ "text": middle });
        let content = format!("{line}\n");
        let findings = scan_content(&content, true, "a", "b", Path::new("s.jsonl"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "generic-api-key");
        assert!(findings[0].escaped_only);
        assert_eq!(findings[0].secret, secret);
        assert_eq!(findings[0].json_path.as_deref(), Some("text"));
    }

    #[test]
    fn jwt_not_double_reported_as_bearer() {
        let jwt = format!(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.{}",
            "a1B2c3D4e5F6g7H8"
        );
        let content = format!("Authorization: Bearer {jwt}\n");
        let findings = scan_content(&content, false, "a", "b", Path::new("t.txt"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "jwt");
    }

    #[test]
    fn pem_block_not_shredded() {
        let content =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n";
        let findings = scan_content(content, false, "a", "b", Path::new("k.pem"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "private-key");
        assert_eq!(findings[0].line, 1);
    }

    #[test]
    fn placeholders_are_ignored() {
        let content = "ANTHROPIC_API_KEY=sk-ant-your-key-here-xxxxxxxxxxxxxxxx\n";
        let findings = scan_content(content, false, "a", "b", Path::new("t.txt"));
        assert!(findings.is_empty());
    }

    #[test]
    fn duplicate_secret_on_same_line_reported_once() {
        let key = fake_anthropic_key();
        let content = format!("{key} and again {key}\n");
        let findings = scan_content(&content, false, "a", "b", Path::new("t.txt"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn line_numbers_are_accurate() {
        let key = fake_anthropic_key();
        let content = format!("clean line\nanother\n{key}\n");
        let findings = scan_content(&content, false, "a", "b", Path::new("t.txt"));
        assert_eq!(findings[0].line, 3);
    }
}
