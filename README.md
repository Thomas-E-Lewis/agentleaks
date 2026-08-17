# agentleaks

> Your AI coding agent has been quietly saving your API keys to disk. Find them. Scrub them.

[![CI](https://github.com/Thomas-E-Lewis/agentleaks/actions/workflows/ci.yml/badge.svg)](https://github.com/Thomas-E-Lewis/agentleaks/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/agentleaks.svg)](https://crates.io/crates/agentleaks)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Claude Code, Codex, Gemini CLI and aider persist every session to plaintext files in your home directory: every prompt, every tool result, every `cat .env` you or the agent ever ran. If a secret was ever on screen, it is still on disk. Generic scanners like gitleaks don't know where these stores live, and they can only report, not clean.

agentleaks is a single binary. No config, no network.

```
agentleaks scan     # find secrets in every agent store on your machine
agentleaks scrub    # redact them in place (backups kept, sessions stay resumable)
```

```
scanning 871 file(s) across 12 store(s)…

~\.claude\projects\C--Users-you-app\a1b2c3d4.jsonl (Claude Code - session transcripts)
  HIGH Anthropic API key [anthropic-api-key]
       sk-ant…Xk2A (108 chars) line 214 at message.content[0].content
  HIGH GitHub token [github-token]
       ghp_A1…9fQz (40 chars) line 892 at toolUseResult.stdout

found 2 finding(s) (2 high) - 2 unique secret(s) across 1 file(s), 871 files scanned
run `agentleaks scrub` to redact them in place (backups are kept)
```

Secrets are always shown masked (`--unmask` to reveal, `--format json` for machines).

## Install

```
cargo install agentleaks
```

Prebuilt binaries for Windows, macOS and Linux are on the [releases page](https://github.com/Thomas-E-Lewis/agentleaks/releases).

## What it scans

| Agent | Locations |
|---|---|
| **Claude Code** | `~/.claude/projects/`, `~/.claude/sessions/`, `~/.claude/history.jsonl`, `~/.claude/shell-snapshots/`, `~/.claude.json`, `~/.claude/settings*.json`, project `.claude/settings*.json`, `.mcp.json` |
| **Codex CLI** | `~/.codex/sessions/`, `~/.codex/history.jsonl`, `~/.codex/config.toml`, `~/.codex/config.json` |
| **Gemini CLI** | `~/.gemini/settings.json`, `~/.gemini/tmp/` |
| **aider** | `.aider.chat.history.md`, `.aider.input.history`, `.aider.conf.yml` |
| **Cursor** | `~/.cursor/mcp.json`, project `.cursor/mcp.json` |
| **Windsurf** | `~/.codeium/windsurf/mcp_config.json` |
| **opencode** | `opencode.json`, `~/.config/opencode/opencode.json` |
| **Continue** | `~/.continue/config.json` / `config.yaml` |

`agentleaks stores` shows which exist on your machine. Files that exist *to* hold credentials (`~/.claude/.credentials.json`, `~/.codex/auth.json`, OAuth caches) are skipped unless you name them explicitly. You can also scan any path: `agentleaks scan some/dir`.

## Scrubbing is safe by design

- Only the secret bytes are replaced, with an inert `[REDACTED:rule:fingerprint]` marker. Every other byte survives, so session files stay valid and `claude --resume` keeps working.
- Every modified JSONL line is re-parsed before anything is written. If a change would corrupt a file, nothing is written.
- Timestamped backups by default, atomic writes, `--dry-run` to preview, and it refuses to touch a file a live session is still writing to. Backups are copies of the originals, so they still contain the secrets: once you have checked the scrub, `agentleaks purge` deletes them.
- Scrubbing removes secrets from disk, it doesn't revoke them: rotate anything live.

## As a commit / CI gate

`scan` exits 1 on findings, 0 when clean:

```
git diff --cached --name-only | agentleaks scan --stdin-paths
```

## Commands

| Command | What it does |
|---|---|
| `agentleaks scan [paths…]` | Scan agent stores (or explicit paths). Exit 1 on findings. |
| `agentleaks scrub [paths…]` | Scan, confirm, redact in place. `--dry-run`, `--yes`, `--no-backup`. |
| `agentleaks purge [paths…]` | Delete the backups scrub created, once you have checked the result. |
| `agentleaks stores` | Show every known store and which exist here. |
| `agentleaks rules` | List all detection rules. |

45 rules cover Anthropic, OpenAI, GitHub, AWS, Google, Slack, Stripe, private-key PEM blocks, JWTs, database URLs with passwords, and entropy-gated generic `api_key = "…"` assignments. Placeholders and template values are filtered out, so output stays high-signal and scrubbing is idempotent.

## License

MIT
