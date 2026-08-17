use agentleaks::scanner::{scan_file, Finding};
use agentleaks::scrub::{scrub_file, ScrubOptions};
use agentleaks::stores::{self, FoundFile};
use agentleaks::{report, rules};
use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use owo_colors::OwoColorize;
use std::collections::BTreeMap;
use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;

/// Find and scrub secrets from AI coding agent session logs and configs.
#[derive(Parser)]
#[command(name = "agentleaks", version, about, propagate_version = true)]
struct Cli {
    /// Disable colored output
    #[arg(long, global = true)]
    no_color: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Pretty,
    Json,
}

#[derive(Subcommand)]
enum Command {
    /// Scan agent data stores (or explicit paths) for secrets.
    ///
    /// With no paths, scans every known agent store on this machine plus
    /// agent files in the current directory. Exits 1 if secrets are
    /// found, which makes it usable as a pre-commit or CI gate.
    Scan {
        /// Files or directories to scan instead of auto-discovery
        paths: Vec<PathBuf>,
        /// Read newline-separated paths from stdin (for pre-commit hooks)
        #[arg(long)]
        stdin_paths: bool,
        /// Output format
        #[arg(long, value_enum, default_value = "pretty")]
        format: Format,
        /// Print full secrets instead of masked previews
        #[arg(long)]
        unmask: bool,
    },
    /// Scan, then redact findings in place (with backups).
    Scrub {
        /// Files or directories to scrub instead of auto-discovery
        paths: Vec<PathBuf>,
        /// Show what would change without writing anything
        #[arg(long)]
        dry_run: bool,
        /// Skip the confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
        /// Do not keep .bak copies of modified files
        #[arg(long)]
        no_backup: bool,
    },
    /// Delete the backup files created by scrub.
    ///
    /// Backups are byte-for-byte copies of the originals, so they still
    /// contain the secrets. Once you have checked that a scrub went
    /// well, purge removes them.
    Purge {
        /// Directories to search instead of auto-discovery
        paths: Vec<PathBuf>,
        /// Skip the confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// List the agent data stores agentleaks knows about and which exist here.
    Stores,
    /// List the detection rules.
    Rules,
}

fn main() {
    let cli = Cli::parse();

    #[cfg(windows)]
    let _ = enable_ansi_support::enable_ansi_support();
    if cli.no_color || std::env::var_os("NO_COLOR").is_some() || !std::io::stdout().is_terminal() {
        owo_colors::set_override(false);
    }

    let code = match run(cli.command) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{} {err:#}", "error:".red().bold());
            2
        }
    };
    std::process::exit(code);
}

fn run(command: Command) -> Result<i32> {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    match command {
        Command::Scan {
            paths,
            stdin_paths,
            format,
            unmask,
        } => {
            let files = resolve_targets(paths, stdin_paths, &home, &cwd)?;
            let (findings, scanned, errors) = scan_all(&files);
            match format {
                Format::Pretty => {
                    report::pretty(&findings, unmask, &home);
                    report::summary(&findings, scanned);
                }
                Format::Json => report::json(&findings, scanned, unmask)?,
            }
            Ok(if errors > 0 {
                2
            } else if findings.is_empty() {
                0
            } else {
                1
            })
        }
        Command::Scrub {
            paths,
            dry_run,
            yes,
            no_backup,
        } => {
            if !yes && !dry_run && !std::io::stdin().is_terminal() {
                anyhow::bail!(
                    "stdin is not a terminal, so scrubbing cannot be confirmed interactively - pass --yes (or --dry-run)"
                );
            }
            let files = resolve_targets(paths, false, &home, &cwd)?;
            let (findings, scanned, scan_errors) = scan_all(&files);
            if findings.is_empty() {
                report::summary(&findings, scanned);
                return Ok(if scan_errors > 0 { 2 } else { 0 });
            }
            report::pretty(&findings, false, &home);
            report::summary(&findings, scanned);
            println!();

            if dry_run {
                println!("{} no files were modified", "dry run:".yellow().bold());
                return Ok(0);
            }
            if !yes && !confirm(&findings)? {
                println!("aborted - no files were modified");
                return Ok(0);
            }

            let mut by_file: BTreeMap<PathBuf, Vec<Finding>> = BTreeMap::new();
            for f in findings {
                by_file.entry(f.file.clone()).or_default().push(f);
            }
            let opts = ScrubOptions {
                dry_run: false,
                backup: !no_backup,
            };
            let mut total = 0usize;
            let mut failures = 0usize;
            for (file, file_findings) in &by_file {
                match scrub_file(file, file_findings, opts) {
                    Ok(outcome) => {
                        total += outcome.redactions;
                        let backup_note = outcome
                            .backup_path
                            .as_ref()
                            .map(|b| format!(" (backup: {})", report::display_path(b, &home)))
                            .unwrap_or_default();
                        println!(
                            "{} {} - {} redaction(s){backup_note}",
                            "scrubbed".green().bold(),
                            report::display_path(file, &home),
                            outcome.redactions,
                        );
                    }
                    Err(err) => {
                        failures += 1;
                        eprintln!(
                            "{} {}: {err:#}",
                            "failed:".red().bold(),
                            report::display_path(file, &home)
                        );
                    }
                }
            }
            println!();
            println!(
                "{} {total} secret(s) redacted across {} file(s)",
                "done:".green().bold(),
                by_file.len() - failures
            );
            println!(
                "{}",
                "note: scrubbing removes secrets from disk - if they were live, rotate them too"
                    .dimmed()
            );
            println!(
                "{}",
                "note: the .bak backups still contain the originals - run `agentleaks purge` once you have checked the scrub"
                    .dimmed()
            );
            Ok(if failures > 0 || scan_errors > 0 {
                2
            } else {
                0
            })
        }
        Command::Purge { paths, yes } => {
            if !yes && !std::io::stdin().is_terminal() {
                anyhow::bail!(
                    "stdin is not a terminal, so purging cannot be confirmed interactively - pass --yes"
                );
            }
            let backups = if paths.is_empty() {
                stores::find_backups(&home, &cwd)
            } else {
                stores::find_backups_under(&paths)
            };
            if backups.is_empty() {
                println!("no scrub backups found");
                return Ok(0);
            }
            let total: u64 = backups
                .iter()
                .filter_map(|b| std::fs::metadata(b).ok())
                .map(|m| m.len())
                .sum();
            for b in &backups {
                println!("  {}", report::display_path(b, &home));
            }
            println!();
            println!(
                "{} backup file(s), {} - these still contain the original secrets",
                backups.len(),
                human_bytes(total)
            );
            if !yes {
                eprint!("Delete them? [y/N] ");
                std::io::stderr().flush()?;
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                if !matches!(answer.trim(), "y" | "Y" | "yes" | "Yes") {
                    println!("aborted - nothing was deleted");
                    return Ok(0);
                }
            }
            let mut failures = 0usize;
            for b in &backups {
                if let Err(err) = std::fs::remove_file(b) {
                    failures += 1;
                    eprintln!(
                        "{} {}: {err}",
                        "failed:".red().bold(),
                        report::display_path(b, &home)
                    );
                }
            }
            println!(
                "{} {} backup file(s) deleted",
                "done:".green().bold(),
                backups.len() - failures
            );
            Ok(if failures > 0 { 2 } else { 0 })
        }
        Command::Stores => {
            print_stores(&home, &cwd);
            Ok(0)
        }
        Command::Rules => {
            print_rules();
            Ok(0)
        }
    }
}

fn resolve_targets(
    paths: Vec<PathBuf>,
    stdin_paths: bool,
    home: &std::path::Path,
    cwd: &std::path::Path,
) -> Result<Vec<FoundFile>> {
    if stdin_paths {
        let stdin = std::io::stdin();
        let mut list = Vec::new();
        for line in stdin.lock().lines() {
            let line = line?;
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                list.push(PathBuf::from(trimmed));
            }
        }
        return stores::expand_paths(&list, home);
    }
    if !paths.is_empty() {
        return stores::expand_paths(&paths, home);
    }
    let discovered = stores::discover(home, cwd);
    let files = stores::flatten(&discovered);
    eprintln!(
        "scanning {} file(s) across {} store(s)\u{2026}",
        files.len(),
        discovered.len()
    );
    Ok(files)
}

fn scan_all(files: &[FoundFile]) -> (Vec<Finding>, usize, usize) {
    use rayon::prelude::*;
    let results: Vec<Result<Vec<Finding>>> = files.par_iter().map(scan_file).collect();
    let mut findings = Vec::new();
    let mut errors = 0usize;
    for result in results {
        match result {
            Ok(mut f) => findings.append(&mut f),
            Err(err) => {
                errors += 1;
                eprintln!("{} {err:#}", "warning:".yellow().bold());
            }
        }
    }
    (findings, files.len(), errors)
}

fn confirm(findings: &[Finding]) -> Result<bool> {
    let files: std::collections::BTreeSet<&PathBuf> = findings.iter().map(|f| &f.file).collect();
    // stderr, so the prompt is visible even when stdout is redirected.
    eprint!(
        "Scrub {} finding(s) in {} file(s)? [y/N] ",
        findings.len(),
        files.len()
    );
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "Yes"))
}

fn print_stores(home: &std::path::Path, cwd: &std::path::Path) {
    let discovered = stores::discover(home, cwd);
    println!("{}", "Known agent data stores".bold());
    println!();
    let mut current_agent = "";
    for spec in stores::STORES {
        if spec.agent != current_agent {
            current_agent = spec.agent;
            println!("{}", current_agent.bold());
        }
        let base = match spec.base {
            stores::Base::Home => "~",
            stores::Base::Project => ".",
        };
        let root = match spec.base {
            stores::Base::Home => home.join(spec.rel),
            stores::Base::Project => cwd.join(spec.rel),
        };
        let found = discovered
            .iter()
            .find(|s| s.root == root && !s.files.is_empty());
        match found {
            Some(s) => {
                let bytes: u64 = s
                    .files
                    .iter()
                    .filter_map(|f| std::fs::metadata(f).ok())
                    .map(|m| m.len())
                    .sum();
                println!(
                    "  {} {base}/{} - {} ({} file(s), {})",
                    "✓".green().bold(),
                    spec.rel,
                    spec.label,
                    s.files.len(),
                    human_bytes(bytes)
                );
            }
            None => {
                println!(
                    "  {} {base}/{} - {}",
                    "·".dimmed(),
                    spec.rel.dimmed(),
                    spec.label.dimmed()
                );
            }
        }
    }
    println!();
    println!(
        "{}",
        "Skipped by design (these files exist to hold credentials):".dimmed()
    );
    for f in stores::CREDENTIAL_FILES {
        println!("  {} ~/{f}", "-".dimmed());
    }
}

fn print_rules() {
    println!("{}", "Detection rules".bold());
    println!();
    for rule in rules::LINE_RULES.iter().chain(rules::BLOCK_RULES.iter()) {
        let sev = match rule.severity {
            rules::Severity::High => "HIGH  ".red().bold().to_string(),
            rules::Severity::Medium => "MEDIUM".yellow().bold().to_string(),
        };
        println!("  {sev} {:32} {}", rule.id, rule.name.dimmed());
    }
    println!();
    println!(
        "{} placeholders, template variables and already-redacted values are always ignored",
        "note:".bold()
    );
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}
