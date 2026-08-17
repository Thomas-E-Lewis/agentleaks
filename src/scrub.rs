//! In-place, structure-preserving redaction.
//!
//! Strategy: secrets are almost always plain ASCII tokens, so they appear
//! byte-for-byte in the raw file even inside JSON strings. We therefore
//! replace the exact secret bytes and touch nothing else - formatting,
//! escapes and key order all survive, so agent session files stay valid
//! and resumable. Only secrets that are split by JSON escape sequences
//! (rare: passwords containing quotes or backslashes) require re-encoding
//! their single line, and every touched JSONL line is re-parsed before
//! anything is written back.

use crate::rules;
use crate::scanner::Finding;
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy)]
pub struct ScrubOptions {
    pub dry_run: bool,
    pub backup: bool,
}

#[derive(Debug)]
pub struct ScrubOutcome {
    pub file: PathBuf,
    pub redactions: usize,
    pub reencoded_lines: usize,
    pub backup_path: Option<PathBuf>,
}

/// Scrub every finding in one file. `findings` must all belong to `path`.
pub fn scrub_file(path: &Path, findings: &[Finding], opts: ScrubOptions) -> Result<ScrubOutcome> {
    let src_meta =
        std::fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let original = match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => bail!(
            "{} is not valid UTF-8; refusing to scrub it in place",
            path.display()
        ),
    };
    let is_jsonl = path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("jsonl"));

    let mut redactions = 0usize;
    let mut reencoded_lines = 0usize;

    // Secrets that appear verbatim in the raw bytes get byte-exact
    // replacement; only secrets split by JSON escape sequences force
    // their line to be re-encoded.
    let (verbatim, escaped): (Vec<&Finding>, Vec<&Finding>) =
        findings.iter().partition(|f| original.contains(&f.secret));

    // Pass 1: re-encode lines containing escape-split secrets. Done
    // first because line numbers refer to the original file.
    let mut content = if escaped.is_empty() {
        original.clone()
    } else {
        let mut lines: Vec<String> = original.split_inclusive('\n').map(String::from).collect();
        for f in &escaped {
            let Some(line) = lines.get_mut(f.line - 1) else {
                bail!(
                    "{}: line {} no longer exists; re-scan before scrubbing",
                    path.display(),
                    f.line
                );
            };
            let ending_len = line.len() - line.trim_end_matches(['\r', '\n']).len();
            let (body, ending) = line.split_at(line.len() - ending_len);
            let mut value: Value = serde_json::from_str(body).with_context(|| {
                format!("{} line {}: no longer valid JSON", path.display(), f.line)
            })?;
            let replacement = rules::placeholder(f.rule_id, &f.secret);
            let mut replaced = 0usize;
            walk_strings_mut(&mut value, &mut |s| {
                if s.contains(&f.secret) {
                    *s = s.replace(&f.secret, &replacement);
                    replaced += 1;
                }
            });
            if replaced > 0 {
                *line = format!("{}{}", serde_json::to_string(&value)?, ending);
                redactions += replaced;
                reencoded_lines += 1;
            }
        }
        lines.concat()
    };

    // Pass 2: byte-exact replacement of every remaining secret, longest
    // first so a secret embedded in a larger one (e.g. inside a PEM
    // block) can never mangle the larger replacement.
    let mut raw: Vec<(&'static str, &str)> = verbatim
        .iter()
        .map(|f| (f.rule_id, f.secret.as_str()))
        .collect();
    raw.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.1.cmp(b.1)));
    raw.dedup();
    for (rule_id, secret) in raw {
        let count = content.matches(secret).count();
        if count > 0 {
            content = content.replace(secret, &rules::placeholder(rule_id, secret));
            redactions += count;
        }
    }

    if content == original {
        return Ok(ScrubOutcome {
            file: path.to_path_buf(),
            redactions: 0,
            reencoded_lines: 0,
            backup_path: None,
        });
    }

    // Safety gate: a scrubbed JSONL file must be at least as parseable as
    // the original, line by line, or we refuse to write it.
    if is_jsonl {
        verify_jsonl(&original, &content, path)?;
    }

    if opts.dry_run {
        return Ok(ScrubOutcome {
            file: path.to_path_buf(),
            redactions,
            reencoded_lines,
            backup_path: None,
        });
    }

    // Freshness gate: agent session files are appended to by *live*
    // sessions. If the file changed since we read it, replacing it would
    // silently destroy whatever was appended - refuse instead.
    let now_meta =
        std::fs::metadata(path).with_context(|| format!("re-checking {}", path.display()))?;
    if now_meta.len() != src_meta.len() || now_meta.modified().ok() != src_meta.modified().ok() {
        bail!(
            "{} changed while scrubbing (an agent session may be writing to it) - close the session and re-run",
            path.display()
        );
    }

    let backup_path = if opts.backup {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let name = format!(
            "{}.agentleaks-{stamp}.bak",
            path.file_name().unwrap_or_default().to_string_lossy()
        );
        let backup = path.with_file_name(name);
        std::fs::copy(path, &backup).with_context(|| format!("backing up {}", path.display()))?;
        Some(backup)
    } else {
        None
    };

    // Write via a synced sibling temp file, then rename over the
    // original, preserving its permissions - a crash mid-write can never
    // leave a half-scrubbed session file.
    let tmp = path.with_file_name(format!(
        "{}.agentleaks-tmp",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    {
        use std::io::Write;
        let mut file =
            std::fs::File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
        file.write_all(content.as_bytes())
            .with_context(|| format!("writing {}", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("syncing {}", tmp.display()))?;
    }
    let _ = std::fs::set_permissions(&tmp, src_meta.permissions());
    std::fs::rename(&tmp, path).with_context(|| {
        let _ = std::fs::remove_file(&tmp);
        format!("replacing {}", path.display())
    })?;

    Ok(ScrubOutcome {
        file: path.to_path_buf(),
        redactions,
        reencoded_lines,
        backup_path,
    })
}

fn verify_jsonl(original: &str, scrubbed: &str, path: &Path) -> Result<()> {
    let orig_lines: Vec<&str> = original.lines().collect();
    let new_lines: Vec<&str> = scrubbed.lines().collect();
    if orig_lines.len() != new_lines.len() {
        bail!(
            "internal error: scrubbing would change the line count of {}; aborting without writing",
            path.display()
        );
    }
    for (i, (before, after)) in orig_lines.iter().zip(new_lines.iter()).enumerate() {
        if before == after || after.trim().is_empty() {
            continue;
        }
        let was_valid = serde_json::from_str::<serde::de::IgnoredAny>(before).is_ok();
        let is_valid = serde_json::from_str::<serde::de::IgnoredAny>(after).is_ok();
        if was_valid && !is_valid {
            bail!(
                "internal error: scrubbing would corrupt JSON on line {} of {}; aborting without writing",
                i + 1,
                path.display()
            );
        }
    }
    Ok(())
}

fn walk_strings_mut(value: &mut Value, visit: &mut dyn FnMut(&mut String)) {
    match value {
        Value::String(s) => visit(s),
        Value::Array(items) => {
            for item in items {
                walk_strings_mut(item, visit);
            }
        }
        Value::Object(map) => {
            for (_, item) in map.iter_mut() {
                walk_strings_mut(item, visit);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::scan_content;

    const OPTS: ScrubOptions = ScrubOptions {
        dry_run: false,
        backup: true,
    };

    fn fake_key() -> String {
        format!("sk-ant-api03-{}", "aB3dEfGh1JkLmN0p".repeat(6))
    }

    fn write_and_scan(
        dir: &tempfile::TempDir,
        name: &str,
        content: &str,
    ) -> (PathBuf, Vec<Finding>) {
        let path = dir.path().join(name);
        std::fs::write(&path, content).unwrap();
        let is_jsonl = name.ends_with(".jsonl");
        let findings = scan_content(content, is_jsonl, "test", "test", &path);
        (path, findings)
    }

    #[test]
    fn raw_scrub_is_byte_exact_outside_the_secret() {
        let dir = tempfile::tempdir().unwrap();
        let key = fake_key();
        let line = serde_json::json!({
            "type": "user",
            "message": {"content": [{"type": "tool_result", "content": format!("key={key}")}]},
            "uuid": "0000-1111"
        });
        let content = format!("{line}\n{{\"type\":\"summary\"}}\n");
        let (path, findings) = write_and_scan(&dir, "session.jsonl", &content);
        assert_eq!(findings.len(), 1);

        let outcome = scrub_file(&path, &findings, OPTS).unwrap();
        assert_eq!(outcome.redactions, 1);
        assert_eq!(outcome.reencoded_lines, 0);

        let after = std::fs::read_to_string(&path).unwrap();
        let expected = content.replace(&key, &rules::placeholder("anthropic-api-key", &key));
        assert_eq!(after, expected);
        // Every line still parses.
        for l in after.lines() {
            serde_json::from_str::<Value>(l).unwrap();
        }
        // Backup holds the original.
        let backup = outcome.backup_path.unwrap();
        assert_eq!(std::fs::read_to_string(backup).unwrap(), content);
    }

    #[test]
    fn escaped_secret_is_reencoded_and_valid() {
        let dir = tempfile::tempdir().unwrap();
        // A backslash in the password means its decoded form never
        // appears verbatim in the raw bytes: the line must be re-encoded.
        let url = r"postgres://admin:pa55\word9@db:5432/x";
        let line = serde_json::json!({"a": 1, "text": url, "z": true});
        let content = format!("{line}\n");
        let (path, findings) = write_and_scan(&dir, "session.jsonl", &content);
        assert!(findings.iter().any(|f| f.escaped_only));

        let outcome = scrub_file(&path, &findings, OPTS).unwrap();
        assert_eq!(outcome.reencoded_lines, 1);

        let after = std::fs::read_to_string(&path).unwrap();
        let value: Value = serde_json::from_str(after.lines().next().unwrap()).unwrap();
        let text = value["text"].as_str().unwrap();
        assert!(!text.contains("word9"));
        assert!(text.contains("[REDACTED:connection-string-password:"));
        assert_eq!(value["a"], 1);
        assert_eq!(value["z"], true);
    }

    #[test]
    fn scrub_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let key = fake_key();
        let content = format!("{{\"text\":\"{key}\"}}\n");
        let (path, findings) = write_and_scan(&dir, "s.jsonl", &content);
        scrub_file(&path, &findings, OPTS).unwrap();

        let after = std::fs::read_to_string(&path).unwrap();
        let rescan = scan_content(&after, true, "t", "t", &path);
        assert!(rescan.is_empty(), "scrubbed file must scan clean");
    }

    #[test]
    fn dry_run_leaves_file_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let key = fake_key();
        let content = format!("token = {key}\n");
        let (path, findings) = write_and_scan(&dir, "config.toml", &content);
        let outcome = scrub_file(
            &path,
            &findings,
            ScrubOptions {
                dry_run: true,
                backup: true,
            },
        )
        .unwrap();
        assert_eq!(outcome.redactions, 1);
        assert!(outcome.backup_path.is_none());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), content);
    }

    #[test]
    fn multiline_pem_scrubbed_from_text_file() {
        let dir = tempfile::tempdir().unwrap();
        let content = "before\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\nafter\n";
        let (path, findings) = write_and_scan(&dir, "snapshot.sh", content);
        assert_eq!(findings.len(), 1);
        scrub_file(&path, &findings, OPTS).unwrap();
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.starts_with("before\n"));
        assert!(after.ends_with("\nafter\n"));
        assert!(after.contains("[REDACTED:private-key:"));
        assert!(!after.contains("BEGIN RSA"));
    }

    #[test]
    fn unterminated_pem_scrub_removes_key_body() {
        let dir = tempfile::tempdir().unwrap();
        let content =
            "before\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\nQUFBQkc1dio=\n";
        let (path, findings) = write_and_scan(&dir, "snapshot.sh", content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "private-key-marker");
        scrub_file(&path, &findings, OPTS).unwrap();
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.contains("[REDACTED:private-key-marker:"));
        assert!(
            !after.contains("b3BlbnNzaC1rZXk="),
            "key body must be scrubbed"
        );
        let rescan = scan_content(&after, false, "t", "t", &path);
        assert!(rescan.is_empty());
    }

    #[test]
    fn reencoding_preserves_big_numbers_exactly() {
        let dir = tempfile::tempdir().unwrap();
        // The number does not round-trip through f64; the escaped
        // backslash in the password forces this line to be re-encoded.
        let content = "{\"n\":123456789012345678901234567890,\"text\":\"postgres://admin:pa55\\\\word9@db:5432/x\"}\n";
        let (path, findings) = write_and_scan(&dir, "s.jsonl", content);
        assert!(findings.iter().any(|f| f.escaped_only));
        let outcome = scrub_file(&path, &findings, OPTS).unwrap();
        assert_eq!(outcome.reencoded_lines, 1);
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(
            after.contains("123456789012345678901234567890"),
            "number literal must survive re-encoding exactly"
        );
        assert!(!after.contains("word9"));
    }

    #[test]
    fn same_secret_on_many_lines_scrubbed_everywhere() {
        let dir = tempfile::tempdir().unwrap();
        let key = fake_key();
        let content = format!("{{\"a\":\"{key}\"}}\n{{\"b\":\"{key}\"}}\n{{\"c\":\"{key}\"}}\n");
        let (path, findings) = write_and_scan(&dir, "s.jsonl", &content);
        let outcome = scrub_file(&path, &findings, OPTS).unwrap();
        assert_eq!(outcome.redactions, 3);
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(!after.contains(&key));
    }
}
