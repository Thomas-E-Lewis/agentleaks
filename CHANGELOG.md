# Changelog

## v0.1.0 — 2026-08-17

Initial release.

- `scan`: zero-config discovery and scanning of Claude Code, Codex CLI, Gemini CLI, aider, Cursor, Windsurf, opencode and Continue data stores; 45 detection rules with entropy gating and placeholder filtering; JSONL decode pass for escape-split secrets; masked output by default; `--format json`, `--unmask`, `--stdin-paths`; exit code 1 on findings for hook/CI use.
- `scrub`: in-place, structure-preserving redaction with byte-exact replacement, a re-parse validity gate for JSONL, timestamped backups, atomic writes, `--dry-run` and confirmation prompts. Idempotent.
- `stores`, `rules`: introspection commands.
- Credential-by-design files (`~/.claude/.credentials.json`, `~/.codex/auth.json`, OAuth caches) are excluded from scans unless named explicitly.
