//! Terminal and JSON reporting.

use crate::rules::Severity;
use crate::scanner::Finding;
use owo_colors::OwoColorize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Replace the home-directory prefix with `~` for display.
pub fn display_path(path: &Path, home: &Path) -> String {
    match path.strip_prefix(home) {
        Ok(rest) => format!("~{}{}", std::path::MAIN_SEPARATOR, rest.display()),
        Err(_) => path.display().to_string(),
    }
}

fn severity_tag(severity: Severity) -> String {
    match severity {
        Severity::High => "HIGH".red().bold().to_string(),
        Severity::Medium => "MEDIUM".yellow().bold().to_string(),
    }
}

/// Pretty-print findings grouped by file.
pub fn pretty(findings: &[Finding], unmask: bool, home: &Path) {
    let mut by_file: BTreeMap<&PathBuf, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        by_file.entry(&f.file).or_default().push(f);
    }

    for (file, file_findings) in &by_file {
        let first = file_findings[0];
        println!();
        println!(
            "{} {}",
            display_path(file, home).bold(),
            format!("({} - {})", first.agent, first.store_label).dimmed()
        );
        for f in file_findings {
            let shown = if unmask { f.secret.clone() } else { f.masked() };
            let location = match &f.json_path {
                Some(p) => format!("line {} at {}", f.line, p),
                None => format!("line {}", f.line),
            };
            println!(
                "  {} {} {}",
                severity_tag(f.severity),
                f.rule_name.bold(),
                format!("[{}]", f.rule_id).dimmed()
            );
            println!("       {} {}", shown.cyan(), location.dimmed());
        }
    }
}

/// One-line-per-item summary printed after a scan.
pub fn summary(findings: &[Finding], files_scanned: usize) {
    let files_with: std::collections::BTreeSet<&PathBuf> =
        findings.iter().map(|f| &f.file).collect();
    let unique: std::collections::BTreeSet<String> =
        findings.iter().map(|f| f.fingerprint()).collect();
    let high = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();

    println!();
    if findings.is_empty() {
        println!(
            "{} scanned {files_scanned} files - no secrets found",
            "clean".green().bold()
        );
    } else {
        println!(
            "{} {} finding(s) ({high} high) - {} unique secret(s) across {} file(s), {files_scanned} files scanned",
            "found".red().bold(),
            findings.len(),
            unique.len(),
            files_with.len(),
        );
        println!(
            "{}",
            "run `agentleaks scrub` to redact them in place (backups are kept)".dimmed()
        );
    }
}

#[derive(serde::Serialize)]
struct JsonFinding<'a> {
    rule: &'a str,
    name: &'a str,
    severity: Severity,
    agent: &'a str,
    store: &'a str,
    file: String,
    line: usize,
    json_path: Option<&'a str>,
    secret_masked: String,
    fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret: Option<&'a str>,
}

#[derive(serde::Serialize)]
struct JsonReport<'a> {
    version: &'static str,
    files_scanned: usize,
    findings: Vec<JsonFinding<'a>>,
    total: usize,
    unique_secrets: usize,
}

/// Machine-readable report on stdout. Secrets stay masked unless
/// `unmask` is set.
pub fn json(findings: &[Finding], files_scanned: usize, unmask: bool) -> anyhow::Result<()> {
    let unique: std::collections::BTreeSet<String> =
        findings.iter().map(|f| f.fingerprint()).collect();
    let report = JsonReport {
        version: env!("CARGO_PKG_VERSION"),
        files_scanned,
        findings: findings
            .iter()
            .map(|f| JsonFinding {
                rule: f.rule_id,
                name: f.rule_name,
                severity: f.severity,
                agent: f.agent,
                store: f.store_label,
                file: f.file.display().to_string(),
                line: f.line,
                json_path: f.json_path.as_deref(),
                secret_masked: f.masked(),
                fingerprint: f.fingerprint(),
                secret: unmask.then_some(f.secret.as_str()),
            })
            .collect(),
        total: findings.len(),
        unique_secrets: unique.len(),
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
