//! Discovery of AI coding agent data stores on the local machine.
//!
//! Two kinds of locations exist: files whose *purpose* is to hold
//! credentials (skipped by default - a finding there is by design), and
//! everything else: session transcripts, histories and configs where a
//! secret is an accident. We scan the latter.

use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base {
    Home,
    Project,
}

#[derive(Debug, Clone, Copy)]
pub enum Kind {
    File,
    /// Recursively walk a directory, taking every regular file.
    Dir,
}

pub struct StoreSpec {
    pub agent: &'static str,
    pub label: &'static str,
    pub base: Base,
    pub rel: &'static str,
    pub kind: Kind,
}

/// Everything agentleaks knows how to find. Paths are relative to the
/// user's home directory or to the project directory being scanned.
pub const STORES: &[StoreSpec] = &[
    // Claude Code
    StoreSpec {
        agent: "Claude Code",
        label: "session transcripts",
        base: Base::Home,
        rel: ".claude/projects",
        kind: Kind::Dir,
    },
    StoreSpec {
        agent: "Claude Code",
        label: "session state",
        base: Base::Home,
        rel: ".claude/sessions",
        kind: Kind::Dir,
    },
    StoreSpec {
        agent: "Claude Code",
        label: "shell snapshots",
        base: Base::Home,
        rel: ".claude/shell-snapshots",
        kind: Kind::Dir,
    },
    StoreSpec {
        agent: "Claude Code",
        label: "command history",
        base: Base::Home,
        rel: ".claude/history.jsonl",
        kind: Kind::File,
    },
    StoreSpec {
        agent: "Claude Code",
        label: "global config",
        base: Base::Home,
        rel: ".claude.json",
        kind: Kind::File,
    },
    StoreSpec {
        agent: "Claude Code",
        label: "user settings",
        base: Base::Home,
        rel: ".claude/settings.json",
        kind: Kind::File,
    },
    StoreSpec {
        agent: "Claude Code",
        label: "user settings (local)",
        base: Base::Home,
        rel: ".claude/settings.local.json",
        kind: Kind::File,
    },
    StoreSpec {
        agent: "Claude Code",
        label: "project settings",
        base: Base::Project,
        rel: ".claude/settings.json",
        kind: Kind::File,
    },
    StoreSpec {
        agent: "Claude Code",
        label: "project settings (local)",
        base: Base::Project,
        rel: ".claude/settings.local.json",
        kind: Kind::File,
    },
    StoreSpec {
        agent: "Claude Code",
        label: "project MCP config",
        base: Base::Project,
        rel: ".mcp.json",
        kind: Kind::File,
    },
    // OpenAI Codex CLI
    StoreSpec {
        agent: "Codex CLI",
        label: "session transcripts",
        base: Base::Home,
        rel: ".codex/sessions",
        kind: Kind::Dir,
    },
    StoreSpec {
        agent: "Codex CLI",
        label: "command history",
        base: Base::Home,
        rel: ".codex/history.jsonl",
        kind: Kind::File,
    },
    StoreSpec {
        agent: "Codex CLI",
        label: "config",
        base: Base::Home,
        rel: ".codex/config.toml",
        kind: Kind::File,
    },
    StoreSpec {
        agent: "Codex CLI",
        label: "config",
        base: Base::Home,
        rel: ".codex/config.json",
        kind: Kind::File,
    },
    // Google Gemini CLI
    StoreSpec {
        agent: "Gemini CLI",
        label: "settings",
        base: Base::Home,
        rel: ".gemini/settings.json",
        kind: Kind::File,
    },
    StoreSpec {
        agent: "Gemini CLI",
        label: "session checkpoints",
        base: Base::Home,
        rel: ".gemini/tmp",
        kind: Kind::Dir,
    },
    // aider
    StoreSpec {
        agent: "aider",
        label: "chat history",
        base: Base::Project,
        rel: ".aider.chat.history.md",
        kind: Kind::File,
    },
    StoreSpec {
        agent: "aider",
        label: "input history",
        base: Base::Project,
        rel: ".aider.input.history",
        kind: Kind::File,
    },
    StoreSpec {
        agent: "aider",
        label: "config",
        base: Base::Project,
        rel: ".aider.conf.yml",
        kind: Kind::File,
    },
    StoreSpec {
        agent: "aider",
        label: "config",
        base: Base::Home,
        rel: ".aider.conf.yml",
        kind: Kind::File,
    },
    // Cursor
    StoreSpec {
        agent: "Cursor",
        label: "MCP config",
        base: Base::Home,
        rel: ".cursor/mcp.json",
        kind: Kind::File,
    },
    StoreSpec {
        agent: "Cursor",
        label: "project MCP config",
        base: Base::Project,
        rel: ".cursor/mcp.json",
        kind: Kind::File,
    },
    // Windsurf
    StoreSpec {
        agent: "Windsurf",
        label: "MCP config",
        base: Base::Home,
        rel: ".codeium/windsurf/mcp_config.json",
        kind: Kind::File,
    },
    // opencode
    StoreSpec {
        agent: "opencode",
        label: "config",
        base: Base::Home,
        rel: ".config/opencode/opencode.json",
        kind: Kind::File,
    },
    StoreSpec {
        agent: "opencode",
        label: "project config",
        base: Base::Project,
        rel: "opencode.json",
        kind: Kind::File,
    },
    // Continue
    StoreSpec {
        agent: "Continue",
        label: "config",
        base: Base::Home,
        rel: ".continue/config.json",
        kind: Kind::File,
    },
    StoreSpec {
        agent: "Continue",
        label: "config",
        base: Base::Home,
        rel: ".continue/config.yaml",
        kind: Kind::File,
    },
];

/// Files that exist *to* store credentials. Scanning them would only
/// report their intended contents, so they are excluded from discovery
/// and from explicit path arguments unless the file is named directly.
pub const CREDENTIAL_FILES: &[&str] = &[
    ".claude/.credentials.json",
    ".codex/auth.json",
    ".gemini/oauth_creds.json",
    ".gemini/access_token",
];

const MAX_FILE_BYTES: u64 = 200 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct FoundFile {
    pub agent: &'static str,
    pub label: &'static str,
    pub path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct FoundStore {
    pub agent: &'static str,
    pub label: &'static str,
    pub root: PathBuf,
    pub files: Vec<PathBuf>,
}

fn is_credential_file(path: &Path, _home: &Path) -> bool {
    // Component-wise suffix comparison - no syscalls, correct on both
    // separator conventions.
    CREDENTIAL_FILES
        .iter()
        .any(|rel| path.ends_with(Path::new(rel)))
}

fn looks_scannable(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(md) => {
            if md.is_file() && md.len() > MAX_FILE_BYTES {
                eprintln!(
                    "warning: skipping {} ({} bytes exceeds the {} MB scan limit)",
                    path.display(),
                    md.len(),
                    MAX_FILE_BYTES / (1024 * 1024)
                );
                return false;
            }
            md.is_file() && md.len() > 0
        }
        Err(_) => false,
    }
}

/// Our own scrub backups and temp files. Directory walks skip them so a
/// re-scan after `scrub` reports the store as clean; naming one
/// explicitly still scans it.
fn is_own_artifact(path: &Path) -> bool {
    path.file_name()
        .map(|n| n.to_string_lossy().contains(".agentleaks-"))
        .unwrap_or(false)
}

/// A scrub backup file: `<original>.agentleaks-<stamp>.bak`.
fn is_backup(path: &Path) -> bool {
    path.file_name()
        .map(|n| {
            let n = n.to_string_lossy();
            n.contains(".agentleaks-") && n.ends_with(".bak")
        })
        .unwrap_or(false)
}

/// Locate every scrub backup next to the known stores. Backups of
/// single-file stores sit as siblings in the store's parent directory,
/// so directory walks alone would miss them.
pub fn find_backups(home: &Path, project_dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for spec in STORES {
        let base = match spec.base {
            Base::Home => home,
            Base::Project => project_dir,
        };
        let root = base.join(spec.rel);
        match spec.kind {
            Kind::Dir => {
                if root.is_dir() {
                    out.extend(
                        WalkDir::new(&root)
                            .follow_links(false)
                            .into_iter()
                            .filter_map(Result::ok)
                            .filter(|e| e.file_type().is_file())
                            .map(|e| e.into_path())
                            .filter(|p| is_backup(p)),
                    );
                }
            }
            Kind::File => {
                let (Some(parent), Some(name)) = (root.parent(), root.file_name()) else {
                    continue;
                };
                let prefix = format!("{}.agentleaks-", name.to_string_lossy());
                if let Ok(entries) = std::fs::read_dir(parent) {
                    for entry in entries.flatten() {
                        let n = entry.file_name().to_string_lossy().to_string();
                        if n.starts_with(&prefix) && n.ends_with(".bak") && entry.path().is_file() {
                            out.push(entry.path());
                        }
                    }
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Locate scrub backups under explicit paths.
pub fn find_backups_under(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for path in paths {
        if path.is_dir() {
            out.extend(
                WalkDir::new(path)
                    .follow_links(false)
                    .into_iter()
                    .filter_map(Result::ok)
                    .filter(|e| e.file_type().is_file())
                    .map(|e| e.into_path())
                    .filter(|p| is_backup(p)),
            );
        } else if path.is_file() && is_backup(path) {
            out.push(path.clone());
        }
    }
    out.sort();
    out.dedup();
    out
}

fn walk_files(root: &Path) -> Vec<PathBuf> {
    WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .filter(|p| looks_scannable(p) && !is_own_artifact(p))
        .collect()
}

/// Discover every known agent store present on this machine, plus the
/// project-level stores under `project_dir`.
pub fn discover(home: &Path, project_dir: &Path) -> Vec<FoundStore> {
    let mut out = Vec::new();
    for spec in STORES {
        let base = match spec.base {
            Base::Home => home,
            Base::Project => project_dir,
        };
        let root = base.join(spec.rel);
        if !root.exists() {
            continue;
        }
        let files = match spec.kind {
            Kind::File => {
                if looks_scannable(&root) && !is_credential_file(&root, home) {
                    vec![root.clone()]
                } else {
                    Vec::new()
                }
            }
            Kind::Dir => {
                let mut files = walk_files(&root);
                files.retain(|p| !is_credential_file(p, home));
                files.sort();
                files
            }
        };
        if !files.is_empty() {
            out.push(FoundStore {
                agent: spec.agent,
                label: spec.label,
                root,
                files,
            });
        }
    }
    out
}

/// Expand explicit path arguments into scannable files. Directories are
/// walked recursively. Explicitly named files are always included, even
/// credential files - naming a file is an unambiguous request. A path
/// that does not exist is a hard error: a CI gate must never pass
/// because of a typo.
pub fn expand_paths(paths: &[PathBuf], home: &Path) -> anyhow::Result<Vec<FoundFile>> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for path in paths {
        if path.is_dir() {
            for file in walk_files(path) {
                if !is_credential_file(&file, home) && seen.insert(file.clone()) {
                    out.push(FoundFile {
                        agent: "path",
                        label: "explicit path",
                        path: file,
                    });
                }
            }
        } else if path.is_file() {
            if seen.insert(path.clone()) {
                out.push(FoundFile {
                    agent: "path",
                    label: "explicit path",
                    path: path.clone(),
                });
            }
        } else {
            anyhow::bail!("{} does not exist", path.display());
        }
    }
    Ok(out)
}

/// Flatten discovered stores into individual files for scanning,
/// deduplicating paths that appear in more than one store (e.g. when the
/// current directory *is* the home directory).
pub fn flatten(stores: &[FoundStore]) -> Vec<FoundFile> {
    let mut seen = std::collections::HashSet::new();
    stores
        .iter()
        .flat_map(|s| {
            s.files.iter().map(|f| FoundFile {
                agent: s.agent,
                label: s.label,
                path: f.clone(),
            })
        })
        .filter(|f| seen.insert(f.path.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_finds_planted_stores() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(home.join(".claude/projects/demo")).unwrap();
        std::fs::write(
            home.join(".claude/projects/demo/session.jsonl"),
            "{\"type\":\"user\"}\n",
        )
        .unwrap();
        std::fs::write(home.join(".claude.json"), "{}").unwrap();
        std::fs::create_dir_all(proj.join(".claude")).unwrap();
        std::fs::write(proj.join(".mcp.json"), "{\"mcpServers\":{}}").unwrap();

        let stores = discover(&home, &proj);
        let agents: Vec<_> = stores.iter().map(|s| (s.agent, s.label)).collect();
        assert!(agents.contains(&("Claude Code", "session transcripts")));
        assert!(agents.contains(&("Claude Code", "global config")));
        assert!(agents.contains(&("Claude Code", "project MCP config")));
    }

    #[test]
    fn credential_files_are_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::write(home.join(".claude/.credentials.json"), "{\"token\":\"x\"}").unwrap();
        std::fs::write(home.join(".claude/settings.json"), "{}").unwrap();

        let stores = discover(&home, &home.join("nowhere"));
        for store in &stores {
            for file in &store.files {
                assert!(!file.ends_with(".credentials.json"));
            }
        }
    }

    #[test]
    fn scrub_artifacts_are_skipped_in_walks() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let dir = home.join(".claude/projects/demo");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("session.jsonl"), "{\"type\":\"user\"}\n").unwrap();
        std::fs::write(
            dir.join("session.jsonl.agentleaks-1700000000.bak"),
            "{\"old\":\"content\"}\n",
        )
        .unwrap();

        let stores = discover(&home, &home.join("nowhere"));
        let files: Vec<_> = stores.iter().flat_map(|s| s.files.iter()).collect();
        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("session.jsonl"));
    }

    #[test]
    fn empty_files_are_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(home.join(".claude.json"), "").unwrap();
        let stores = discover(&home, &home.join("nowhere"));
        assert!(stores.is_empty());
    }
}
