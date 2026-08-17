# agentleaks

> Your AI coding agent has been quietly saving your API keys to disk. Find them. Scrub them.

[![CI](https://github.com/Thomas-E-Lewis/agentleaks/actions/workflows/ci.yml/badge.svg)](https://github.com/Thomas-E-Lewis/agentleaks/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Every session you run with Claude Code, Codex CLI, Gemini CLI or aider is persisted to plaintext files in your home directory - every prompt, every tool result, every `cat .env` you or the agent ever ran. Those transcripts never expire and nothing ever scrubs them:

- `~/.claude/projects/**/*.jsonl` - complete Claude Code session transcripts, kept forever
- `~/.codex/sessions/` - the same, for Codex CLI
- `.claude/settings.local.json`, `.mcp.json` - MCP configs where API keys get pasted "just to test", then committed ([428 npm packages shipped one; 33 contained live credentials](https://bdtechtalks.com/2026/04/27/claude-code-api-token-leak/))
- `~/.claude/shell-snapshots/` - snapshots of your shell environment

If a secret was ever on screen in a session, it is still on your disk. Users have been [asking for exactly this cleanup](https://github.com/anthropics/claude-code/issues/50014) - and generic scanners like gitleaks or trufflehog can't help: they don't know where agent stores live, and they can only *report*, not rewrite a session file in place without breaking it.

**agentleaks** is a single small binary, no config, no network, that:

- **finds** secrets across the data stores of 8 AI coding agents - 45 rules plus entropy analysis, in about a second for hundreds of MB of transcripts
- **scrubs** them in place, structure-aware, so your sessions stay valid and `claude --resume` keeps working
- **gates** commits and CI so agent config files with live credentials never ship again

## Quick start

```
agentleaks scan
```

That's it - no arguments, no config. It discovers every agent store on your machine and tells you what's leaked:

```
scanning 871 file(s) across 12 store(s)…

~\.claude\projects\C--Users-you-app\a1b2c3d4.jsonl (Claude Code - session transcripts)
  HIGH Anthropic API key [anthropic-api-key]
       sk-ant…Xk2A (108 chars) line 214 at message.content[0].content
  HIGH GitHub token [github-token]
       ghp_A1…9fQz (40 chars) line 892 at toolUseResult.stdout

~\.claude.json (Claude Code - global config)
  HIGH OpenAI API key [openai-api-key]
       sk-pro…M4dS (164 chars) line 1

found 3 finding(s) (3 high) - 3 unique secret(s) across 2 file(s), 871 files scanned
run `agentleaks scrub` to redact them in place (backups are kept)
```

Secrets are always shown masked. Then:

```
agentleaks scrub
```

reviews the findings with you and rewrites each file in place, replacing every secret with an inert `[REDACTED:rule:fingerprint]` marker. Backups are kept next to each modified file.

## Install

Prebuilt binaries for Windows, macOS and Linux are on the [releases page](https://github.com/Thomas-E-Lewis/agentleaks/releases).

Or build from source with Rust:

```
cargo install --locked --git https://github.com/Thomas-E-Lewis/agentleaks
```

## What it scans

| Agent | Locations |
|---|---|
| **Claude Code** | `~/.claude/projects/` (session transcripts), `~/.claude/sessions/`, `~/.claude/history.jsonl`, `~/.claude/shell-snapshots/`, `~/.claude.json`, `~/.claude/settings*.json`, project `.claude/settings*.json`, `.mcp.json` |
| **Codex CLI** | `~/.codex/sessions/`, `~/.codex/history.jsonl`, `~/.codex/config.toml`, `~/.codex/config.json` |
| **Gemini CLI** | `~/.gemini/settings.json`, `~/.gemini/tmp/` |
| **aider** | `.aider.chat.history.md`, `.aider.input.history`, `.aider.conf.yml` (project and home) |
| **Cursor** | `~/.cursor/mcp.json`, project `.cursor/mcp.json` |
| **Windsurf** | `~/.codeium/windsurf/mcp_config.json` |
| **opencode** | `opencode.json`, `~/.config/opencode/opencode.json` |
| **Continue** | `~/.continue/config.json` / `config.yaml` |

Run `agentleaks stores` to see which of these exist on your machine and how big they are.

Files whose *purpose* is to hold credentials (`~/.claude/.credentials.json`, `~/.codex/auth.json`, OAuth token caches) are skipped by default - a finding there would be by design, not a leak. You can still scan one by naming it explicitly.

You can also point it at anything else: `agentleaks scan path/to/dir` scans arbitrary files with the same rules.

## How scrubbing works - and why it's safe

Claude Code session files are JSONL and must stay parseable or your session history (and `--resume`) breaks. `agentleaks scrub` is built around that constraint:

1. **Byte-exact replacement.** Secrets are almost always plain ASCII tokens, so they appear verbatim in the raw bytes even inside JSON strings. agentleaks replaces exactly those bytes with `[REDACTED:rule:fingerprint]` and touches nothing else - formatting, escapes, key order and every other byte survive.
2. **Structure-aware fallback.** The rare secret that is split by JSON escape sequences (a password containing a backslash, doubly-nested JSON from captured API responses) gets its single line decoded, redacted and re-encoded.
3. **Validity gate.** Before anything is written, every modified JSONL line is re-parsed. If scrubbing would corrupt a single line, the file is left untouched and an error is reported instead.
4. **Backups and atomic writes.** Each modified file gets a timestamped `.bak` sibling first (disable with `--no-backup`), and content is written via a temp file + rename so a crash can never leave a half-written session.
5. **Dry runs.** `agentleaks scrub --dry-run` shows exactly what would change, writes nothing.

The redaction fingerprint (first 8 hex chars of the secret's SHA-256) means the same secret always redacts to the same marker - you can tell "one key leaked 40 times" from "40 different keys" even after scrubbing.

> **Scrubbing removes secrets from disk - it doesn't revoke them.** If a live key showed up in a scan, rotate it too.

## As a commit / CI gate

`scan` exits `1` when it finds anything, `0` when clean, so it drops straight into hooks. Stop agent configs with live keys from ever being committed:

```yaml
# .pre-commit-config.yaml
- repo: local
  hooks:
    - id: agentleaks
      name: agentleaks
      entry: agentleaks scan
      language: system
      files: (^|/)(\.mcp\.json|\.claude/.*|\.cursor/.*|\.aider\..*|opencode\.json)$
```

Or in any shell hook / CI step:

```
git diff --cached --name-only | agentleaks scan --stdin-paths
```

`--format json` gives machine-readable output (secrets masked unless you pass `--unmask`).

## Commands

| Command | What it does |
|---|---|
| `agentleaks scan [paths…]` | Scan agent stores (or explicit paths). Exit 1 on findings. |
| `agentleaks scrub [paths…]` | Scan, confirm, redact in place. `--dry-run`, `--yes`, `--no-backup`. |
| `agentleaks stores` | Show every known store and which exist on this machine. |
| `agentleaks rules` | List all detection rules. |

## Detection rules

45 rules covering the providers that actually show up in agent workflows: Anthropic, OpenAI, OpenRouter, GitHub (classic + fine-grained), GitLab, AWS, Google, Slack, Discord, Stripe, npm, PyPI, Hugging Face, Groq, Perplexity, xAI, DigitalOcean, Supabase, PlanetScale, Tailscale, Netlify, Doppler, Linear, Notion, Figma, Postman, Databricks, Shopify, Telegram, SendGrid, Twilio, Azure, private-key PEM blocks, JWTs, database URLs with embedded passwords, and entropy-gated generic `api_key = "…"` assignments.

Placeholders (`<YOUR_KEY>`, `sk-ant-your-key-here`, `${API_KEY}`, `xxxx…`) and already-redacted values are filtered out, so output stays high-signal and scrubbing is idempotent.

## vs. gitleaks / trufflehog

Those are excellent tools for a different job - scanning *repositories*. agentleaks is agent-native:

|  | gitleaks / trufflehog | agentleaks |
|---|---|---|
| Knows agent data stores on all 3 OSes | ✗ | ✓ |
| Remediation | report only | in-place scrub |
| Keeps session JSONL valid & resumable | - | ✓ (validity gate) |
| Skips by-design credential files | ✗ | ✓ |
| Config needed | some | zero |

Use them on your repos. Use agentleaks on your agents.

## FAQ

**Does it phone home?** No. There is no network code in the binary at all. Nothing leaves your machine - which is rather the point.

**Will scrubbing break `claude --resume`?** No. Only secret bytes are replaced, every touched line is re-parsed before writing, and if anything would corrupt the file, nothing is written.

**False positives?** Everything is masked for review first, `--dry-run` exists, and placeholder/template values are filtered automatically. If a rule misfires on real data, please open an issue with the (masked!) output.

**Why is `~/.claude/.credentials.json` skipped?** Because it's *supposed* to contain a credential. Reporting it would be noise. Scan it explicitly by path if you want.

**Limits worth knowing.** Files that aren't valid UTF-8 are scanned (lossily) but `scrub` refuses to rewrite them - redact those by hand. Encrypted PEM blocks (with `Proc-Type` headers) are detected, but only the header portion is scrubbed automatically. If a session file changes mid-scrub (a live agent writing to it), agentleaks refuses to touch it rather than risk losing appended lines - close the session and re-run.

## License

MIT
