//! Secret detection rules.
//!
//! Rules are ordered from most to least specific; when two rules match
//! overlapping text on the same line, the earlier rule wins.

use regex::{Regex, RegexSet};
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    High,
    Medium,
}

pub struct Rule {
    pub id: &'static str,
    pub name: &'static str,
    pub severity: Severity,
    pub pattern: &'static str,
    /// Capture group holding the secret itself (0 = whole match).
    pub group: usize,
    /// Minimum Shannon entropy required of the captured secret, if any.
    pub min_entropy: Option<f64>,
}

/// Rules matched against a single line at a time.
pub const LINE_RULES: &[Rule] = &[
    Rule {
        id: "anthropic-api-key",
        name: "Anthropic API key",
        severity: Severity::High,
        pattern: r"\bsk-ant-[A-Za-z0-9_-]{24,}",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "openai-api-key",
        name: "OpenAI API key",
        severity: Severity::High,
        pattern: r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "openai-legacy-key",
        name: "OpenAI API key (legacy)",
        severity: Severity::High,
        pattern: r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20,}\b",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "openrouter-api-key",
        name: "OpenRouter API key",
        severity: Severity::High,
        pattern: r"\bsk-or-v1-[a-f0-9]{64}\b",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "github-token",
        name: "GitHub token",
        severity: Severity::High,
        pattern: r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "github-fine-grained-pat",
        name: "GitHub fine-grained PAT",
        severity: Severity::High,
        pattern: r"\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "gitlab-pat",
        name: "GitLab personal access token",
        severity: Severity::High,
        pattern: r"\bglpat-[A-Za-z0-9_-]{20,}",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "aws-access-key-id",
        name: "AWS access key ID",
        severity: Severity::High,
        pattern: r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "aws-secret-access-key",
        name: "AWS secret access key",
        severity: Severity::High,
        pattern: r#"(?i)aws[^\n]{0,30}?\\?["']([A-Za-z0-9/+=]{40})\\?["']"#,
        group: 1,
        min_entropy: Some(3.0),
    },
    Rule {
        id: "google-api-key",
        name: "Google API key",
        severity: Severity::High,
        pattern: r"\bAIza[A-Za-z0-9_-]{35}\b",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "slack-token",
        name: "Slack token",
        severity: Severity::High,
        pattern: r"\bxox[baprse]-[A-Za-z0-9-]{10,}",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "slack-webhook",
        name: "Slack webhook URL",
        severity: Severity::High,
        pattern: r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "discord-webhook",
        name: "Discord webhook URL",
        severity: Severity::High,
        pattern: r"https://(?:discord|discordapp)\.com/api/webhooks/\d+/[A-Za-z0-9_-]{60,}",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "stripe-live-key",
        name: "Stripe live key",
        severity: Severity::High,
        pattern: r"\b[sr]k_live_[A-Za-z0-9]{20,}",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "stripe-webhook-secret",
        name: "Stripe webhook signing secret",
        severity: Severity::Medium,
        pattern: r"\bwhsec_[A-Za-z0-9]{32,}",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "sendgrid-api-key",
        name: "SendGrid API key",
        severity: Severity::High,
        pattern: r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "twilio-api-key",
        name: "Twilio API key SID",
        severity: Severity::Medium,
        pattern: r"\bSK[a-f0-9]{32}\b",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "npm-token",
        name: "npm access token",
        severity: Severity::High,
        pattern: r"\bnpm_[A-Za-z0-9]{36}\b",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "pypi-token",
        name: "PyPI API token",
        severity: Severity::High,
        pattern: r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{40,}",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "huggingface-token",
        name: "Hugging Face token",
        severity: Severity::High,
        pattern: r"\bhf_[A-Za-z0-9]{30,}\b",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "digitalocean-token",
        name: "DigitalOcean token",
        severity: Severity::High,
        pattern: r"\bdo[opr]_v1_[a-f0-9]{64}\b",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "tailscale-key",
        name: "Tailscale key",
        severity: Severity::Medium,
        pattern: r"\btskey-[A-Za-z0-9-]{16,}",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "netlify-token",
        name: "Netlify personal access token",
        severity: Severity::High,
        pattern: r"\bnfp_[A-Za-z0-9]{30,}\b",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "doppler-token",
        name: "Doppler token",
        severity: Severity::High,
        pattern: r"\bdp\.pt\.[A-Za-z0-9]{40,}\b",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "linear-api-key",
        name: "Linear API key",
        severity: Severity::High,
        pattern: r"\blin_api_[A-Za-z0-9]{30,}\b",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "notion-token",
        name: "Notion integration token",
        severity: Severity::High,
        pattern: r"\bntn_[A-Za-z0-9]{40,}\b",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "figma-token",
        name: "Figma personal access token",
        severity: Severity::High,
        pattern: r"\bfigd_[A-Za-z0-9_-]{30,}",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "postman-api-key",
        name: "Postman API key",
        severity: Severity::High,
        pattern: r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "databricks-token",
        name: "Databricks token",
        severity: Severity::High,
        pattern: r"\bdapi[a-f0-9]{32}\b",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "shopify-token",
        name: "Shopify token",
        severity: Severity::High,
        pattern: r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "telegram-bot-token",
        name: "Telegram bot token",
        severity: Severity::High,
        pattern: r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "groq-api-key",
        name: "Groq API key",
        severity: Severity::High,
        pattern: r"\bgsk_[A-Za-z0-9]{40,}\b",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "perplexity-api-key",
        name: "Perplexity API key",
        severity: Severity::High,
        pattern: r"\bpplx-[A-Za-z0-9]{40,}\b",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "xai-api-key",
        name: "xAI API key",
        severity: Severity::High,
        pattern: r"\bxai-[A-Za-z0-9]{40,}\b",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "supabase-token",
        name: "Supabase access token",
        severity: Severity::High,
        pattern: r"\bsbp_[a-f0-9]{40}\b",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "planetscale-token",
        name: "PlanetScale token",
        severity: Severity::High,
        pattern: r"\bpscale_tkn_[A-Za-z0-9_.-]{30,}",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "age-secret-key",
        name: "age secret key",
        severity: Severity::High,
        pattern: r"\bAGE-SECRET-KEY-1[A-Z0-9]{40,}",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "azure-storage-key",
        name: "Azure storage account key",
        severity: Severity::High,
        pattern: r"(?i)AccountKey=([A-Za-z0-9+/=]{60,})",
        group: 1,
        min_entropy: None,
    },
    Rule {
        id: "connection-string-password",
        name: "Database URL with password",
        severity: Severity::High,
        pattern: r#"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|ftp)://[^\s:/@"']{0,64}:([^\s@"'<>{}]{4,})@"#,
        group: 1,
        min_entropy: None,
    },
    Rule {
        id: "url-basic-auth",
        name: "URL with basic-auth password",
        severity: Severity::Medium,
        pattern: r#"https?://[^\s:/@"']{1,64}:([^\s@"'<>{}]{4,})@"#,
        group: 1,
        min_entropy: None,
    },
    Rule {
        id: "jwt",
        name: "JSON Web Token",
        severity: Severity::Medium,
        pattern: r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}\b",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "bearer-token",
        name: "Bearer token in header",
        severity: Severity::Medium,
        pattern: r"(?i)\bBearer\s+([A-Za-z0-9_+/=.-]{25,})",
        group: 1,
        min_entropy: Some(3.0),
    },
    Rule {
        id: "generic-api-key",
        name: "Generic secret assignment",
        severity: Severity::Medium,
        pattern: r#"(?i)\\?["']?\b(?:api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|bearer[_-]?token)\b\\?["']?\s*[:=]\s*\\?["']([A-Za-z0-9_+/=.-]{16,})\\?["']"#,
        group: 1,
        min_entropy: Some(3.0),
    },
];

/// Rules matched against whole file content (may span lines).
///
/// The body class `(?:[A-Za-z0-9+/=\s]|\\[nrt])*` matches base64 key
/// material across real newlines and across JSON-escaped `\n` - and
/// nothing else. Bounding the body this way means a BEGIN marker can
/// never pair with an unrelated END marker further down the file and
/// swallow legitimate content between them.
pub const BLOCK_RULES: &[Rule] = &[
    Rule {
        id: "private-key",
        name: "Private key (PEM)",
        severity: Severity::High,
        pattern: r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----(?:[A-Za-z0-9+/=\s]|\\[nrt])*?-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----",
        group: 0,
        min_entropy: None,
    },
    Rule {
        id: "private-key-marker",
        name: "Private key (PEM, unterminated)",
        severity: Severity::High,
        pattern: r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----(?:[A-Za-z0-9+/=\s]|\\[nrt])*",
        group: 0,
        min_entropy: None,
    },
];

/// Targeted rejections for shapes that satisfy a rule's pattern but are
/// demonstrably something else.
pub fn is_false_positive(rule_id: &str, secret: &str) -> bool {
    match rule_id {
        // A 40-char pure lowercase-hex string near "aws" is a git SHA,
        // not an AWS secret key (real ones are mixed-case base64).
        "aws-secret-access-key" => {
            secret.len() == 40
                && secret
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        }
        _ => false,
    }
}

pub struct CompiledRules {
    pub line_rules: Vec<(&'static Rule, Regex)>,
    pub line_set: RegexSet,
    pub block_rules: Vec<(&'static Rule, Regex)>,
}

/// Secrets are ASCII; ASCII word boundaries keep every pattern eligible
/// for the regex crate's fast lazy-DFA path even on unicode-heavy
/// transcript content (unicode \b forces a slower engine there).
fn ascii_boundaries(pattern: &str) -> String {
    pattern.replace(r"\b", r"(?-u:\b)")
}

pub fn compiled() -> &'static CompiledRules {
    static COMPILED: OnceLock<CompiledRules> = OnceLock::new();
    COMPILED.get_or_init(|| {
        let line_rules: Vec<(&'static Rule, Regex)> = LINE_RULES
            .iter()
            .map(|r| (r, Regex::new(&ascii_boundaries(r.pattern)).expect(r.id)))
            .collect();
        let line_set = RegexSet::new(LINE_RULES.iter().map(|r| ascii_boundaries(r.pattern)))
            .expect("line rule set");
        let block_rules = BLOCK_RULES
            .iter()
            .map(|r| (r, Regex::new(&ascii_boundaries(r.pattern)).expect(r.id)))
            .collect();
        CompiledRules {
            line_rules,
            line_set,
            block_rules,
        }
    })
}

/// Shannon entropy of a string, in bits per character.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
    }
    let len = s.chars().count() as f64;
    counts
        .values()
        .map(|&n| {
            let p = n as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Returns true when a matched string is clearly a placeholder or an
/// already-redacted value rather than a live secret.
pub fn is_allowlisted(secret: &str) -> bool {
    static ALLOW: OnceLock<Regex> = OnceLock::new();
    let re = ALLOW.get_or_init(|| {
        // Deliberately conservative: only words very unlikely to occur by
        // chance inside a random token. Short words like "fake" or "test"
        // WOULD occur by chance and would drop real secrets.
        Regex::new(
            r"(?ix)
            example | placeholder | your[_-]?(?:api[_-]?)?key | your[_-] |
            changeme | change[_-]me | insert[_-] | redacted | \[REDACTED |
            x{4,} | \*{3,} | \.{3} | <[^>]*> | \u2026
            ",
        )
        .expect("allowlist")
    });
    if re.is_match(secret) {
        return true;
    }
    // Template/env-var references, e.g. ${API_KEY} or $Env:KEY.
    if secret.contains("${") || secret.starts_with('$') {
        return true;
    }
    // Long runs of one repeated character (aaaa..., 0000...).
    let mut chars = secret.chars();
    if let Some(first) = chars.next() {
        if secret.chars().count() >= 8 && chars.all(|c| c == first) {
            return true;
        }
    }
    // Simple ascending sequences like 1234567890...
    if secret.len() >= 8
        && secret
            .as_bytes()
            .windows(2)
            .all(|w| w[1] == w[0] + 1 || w[1] == w[0].wrapping_sub(9))
    {
        return true;
    }
    false
}

/// First 8 hex chars of SHA-256 - stable fingerprint for a secret value.
pub fn fingerprint(secret: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(secret.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    hex[..8].to_string()
}

/// Redaction placeholder written in place of a secret.
pub fn placeholder(rule_id: &str, secret: &str) -> String {
    format!("[REDACTED:{}:{}]", rule_id, fingerprint(secret))
}

/// Mask a secret for display: keep a short prefix/suffix, hide the rest.
pub fn mask(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    let n = chars.len();
    if n >= 16 {
        let head: String = chars[..6].iter().collect();
        let tail: String = chars[n - 4..].iter().collect();
        format!("{head}\u{2026}{tail} ({n} chars)")
    } else if n >= 8 {
        let head: String = chars[..3].iter().collect();
        format!("{head}\u{2026} ({n} chars)")
    } else {
        format!("\u{2026} ({n} chars)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(rule_id: &str, text: &str) -> bool {
        let c = compiled();
        c.line_rules
            .iter()
            .chain(c.block_rules.iter())
            .filter(|(r, _)| r.id == rule_id)
            .any(|(r, re)| {
                re.captures(text)
                    .and_then(|caps| caps.get(r.group))
                    .is_some()
            })
    }

    #[test]
    fn anthropic_key_detected() {
        let key = format!("sk-ant-api03-{}", "aB3dEfGh".repeat(12));
        assert!(matches("anthropic-api-key", &format!("key = {key}")));
        assert!(!matches("anthropic-api-key", "sk-ant-short"));
    }

    #[test]
    fn openai_keys_detected() {
        let modern = format!("sk-proj-{}", "Ab1Cd2Ef".repeat(8));
        assert!(matches("openai-api-key", &modern));
        let legacy = format!(
            "sk-{}T3BlbkFJ{}",
            "a1B2c3D4e5F6g7H8i9J0", "Z9y8X7w6V5u4T3s2R1q0"
        );
        assert!(matches("openai-legacy-key", &legacy));
    }

    #[test]
    fn github_tokens_detected() {
        let classic = format!("ghp_{}", "A1b2C3d4E5f6".repeat(3));
        assert!(matches("github-token", &classic));
        let fine = format!("github_pat_{}_{}", "A1b2C3d4E5f6G7h8I9j0K1", "a".repeat(59));
        assert!(matches("github-fine-grained-pat", &fine));
    }

    #[test]
    fn aws_detected() {
        assert!(matches("aws-access-key-id", "AKIAIOSFODNN7EXAMPLE"));
        let line = r#"aws_secret_access_key = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY12""#;
        assert!(matches("aws-secret-access-key", line));
    }

    #[test]
    fn connection_string_detected() {
        assert!(matches(
            "connection-string-password",
            "postgres://admin:hunter2secret@db.internal:5432/prod"
        ));
        assert!(!matches(
            "connection-string-password",
            "postgres://admin:${DB_PASS}@db.internal:5432/prod"
        ));
    }

    #[test]
    fn jwt_detected() {
        let jwt = format!(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.{}",
            "a1B2c3D4e5F6g7H8"
        );
        assert!(matches("jwt", &jwt));
    }

    #[test]
    fn generic_assignment_needs_entropy() {
        let c = compiled();
        let (rule, re) = c
            .line_rules
            .iter()
            .find(|(r, _)| r.id == "generic-api-key")
            .unwrap();
        let line = r#""api_key": "hVx91mPqL0siTk3ZbNwyRe8u""#;
        let caps = re.captures(line).unwrap();
        let secret = caps.get(rule.group).unwrap().as_str();
        assert!(shannon_entropy(secret) >= 3.5);

        let dull = r#""api_key": "aaaaaaaaaaaaaaaaaaaa""#;
        if let Some(caps) = re.captures(dull) {
            let secret = caps.get(rule.group).unwrap().as_str();
            assert!(shannon_entropy(secret) < 3.5);
        }
    }

    #[test]
    fn pem_block_detected() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----";
        assert!(matches("private-key", pem));
        assert!(matches(
            "private-key-marker",
            "-----BEGIN OPENSSH PRIVATE KEY-----"
        ));
    }

    #[test]
    fn mismatched_pem_markers_do_not_cross_match() {
        // A truncated key followed by unrelated content and a different
        // END marker must never be swallowed as one giant "secret".
        let content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n{\"unrelated\": true}\n-----END OPENSSH PRIVATE KEY-----";
        let c = compiled();
        let (_, re) = c
            .block_rules
            .iter()
            .find(|(r, _)| r.id == "private-key")
            .unwrap();
        assert!(re.find(content).is_none());
        // The marker rule captures the header plus its base64 body only.
        let (_, marker) = c
            .block_rules
            .iter()
            .find(|(r, _)| r.id == "private-key-marker")
            .unwrap();
        let m = marker.find(content).unwrap();
        assert!(m.as_str().contains("MIIEow=="));
        assert!(!m.as_str().contains("unrelated"));
    }

    #[test]
    fn aws_git_sha_is_rejected_as_false_positive() {
        assert!(is_false_positive(
            "aws-secret-access-key",
            "3f2a8c9d1e4b5a6f7c8d9e0a1b2c3d4e5f6a7b8c"
        ));
        assert!(!is_false_positive(
            "aws-secret-access-key",
            "wJalrXUtnFEMIK7MDENGbPxRfiCYRRSTUVKEY12x"
        ));
    }

    #[test]
    fn connection_string_edge_forms() {
        // Empty username (standard for redis) and passwords containing $.
        assert!(matches(
            "connection-string-password",
            "redis://:hunter2secret9@cache:6379"
        ));
        assert!(matches(
            "connection-string-password",
            "postgres://admin:pa$$word99@db:5432/x"
        ));
    }

    #[test]
    fn allowlist_filters_placeholders() {
        assert!(is_allowlisted("sk-ant-your-key-here-aaaaaaaaaaaa"));
        assert!(is_allowlisted("<YOUR_API_KEY_GOES_RIGHT_HERE>"));
        assert!(is_allowlisted("xxxxxxxxxxxxxxxxxxxxxxxx"));
        assert!(is_allowlisted("[REDACTED:github-token:12ab34cd]"));
        assert!(is_allowlisted("${OPENAI_API_KEY}"));
        assert!(is_allowlisted("aaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(!is_allowlisted("hVx91mPqL0siTk3ZbNwyRe8u"));
    }

    #[test]
    fn masking_never_reveals_middle() {
        let secret = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789";
        let masked = mask(secret);
        assert!(masked.starts_with("sk-ant"));
        assert!(!masked.contains("abcdefghijklmnop"));
    }

    #[test]
    fn placeholder_is_stable_and_inert() {
        let p1 = placeholder("github-token", "some-secret-value");
        let p2 = placeholder("github-token", "some-secret-value");
        assert_eq!(p1, p2);
        assert!(p1.starts_with("[REDACTED:github-token:"));
        // A placeholder must never itself look like a secret.
        assert!(is_allowlisted(&p1));
    }

    #[test]
    fn all_rules_compile_and_ids_unique() {
        let c = compiled();
        let mut ids: Vec<&str> = LINE_RULES
            .iter()
            .chain(BLOCK_RULES.iter())
            .map(|r| r.id)
            .collect();
        let before = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(before, ids.len(), "duplicate rule id");
        assert_eq!(c.line_rules.len(), LINE_RULES.len());
    }

    #[test]
    fn entropy_sanity() {
        assert!(shannon_entropy("aaaa") < 0.1);
        assert!(shannon_entropy("hVx91mPqL0siTk3Zb") > 3.5);
    }
}
