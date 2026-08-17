# Contributing

Thanks for helping make agent data stores less leaky. Contributions of every size are welcome.

## Getting started

```
git clone https://github.com/Thomas-E-Lewis/agentleaks
cd agentleaks
cargo test
```

CI runs `cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test` on Linux, macOS and Windows — running those three locally before pushing saves a round trip.

## Adding a detection rule

Rules live in [`src/rules.rs`](src/rules.rs). A good rule PR has:

1. The rule itself — prefer a provider-specific prefix pattern (like `sk-ant-`) over a generic one; generic patterns need an entropy gate.
2. A positive and a negative test case. **Never commit a real or realistic secret** — build fixtures at runtime by concatenation (see the existing tests), so nothing secret-shaped ever lands in the repo history and GitHub push protection stays quiet.
3. A severity: `High` for "this is a credential", `Medium` for "this deserves a look".

## Adding an agent store

Store locations live in [`src/stores.rs`](src/stores.rs). Please link documentation (or your own verified paths) for where the agent writes session data on each OS, and say whether any of its files are credential-by-design (those belong in `CREDENTIAL_FILES`, not in the scan set).

## Reporting false positives / negatives

Open an issue with the **masked** scan output (never paste a live secret — that would be somewhat against the spirit of the project). For false negatives, describe the shape of the token and where it sat.

## Security issues

Please use [GitHub private vulnerability reporting](../../security/advisories/new) rather than a public issue.
