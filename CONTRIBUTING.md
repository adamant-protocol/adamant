# Contributing to Adamant

This file collects per-environment notes for working in this repository.
As contributor concerns surface they are recorded here. Phase 1 only
carries the operational note below; broader contribution guidelines
(coding style, PR process, review expectations, signing) come later.

For project context and design discipline, see `CLAUDE.md` and the
canonical specification under `whitepaper/`.

## Build environment

### Windows: Application Control blocks `target/` (`os error 4551`)

On Windows machines running Windows Defender Application Control (WDAC)
or a managed corporate endpoint with a comparable exec-allowlist policy,
`cargo test` may compile successfully but fail to launch the resulting
test binary with:

> An Application Control policy has blocked this file. (os error 4551)

The build artifact is unsigned and the default `target/` directory is
not on the policy's allowed-execution list.

**Workaround.** Point cargo's build artifacts at a directory the policy
permits. The repository ships `.cargo/config.toml` with a commented-out
`[build] target-dir` entry — uncomment it and fill in an absolute path
that your machine allows to execute binaries (typical choices: `%TEMP%`,
`%LOCALAPPDATA%`, or a developer-specific allowlisted folder).

The setting is per-developer; do not commit a hardcoded path. The
shipped config file documents the symptom in-place so future
contributors hitting the same error can resolve it without searching.
