# Release Artifacts Guide

This document outlines the expected deliverables, naming conventions, and validation steps for every Soroban Debugger release. Maintainers should use this guide in tandem with the release checklist to ensure package quality across all distribution channels.

## 1. CLI Binaries

We distribute pre-compiled binaries for major platforms. Each release must include archives containing the `soroban-debug` executable.

### Target Platforms
- `x86_64-unknown-linux-gnu` (Linux x64)
- `aarch64-unknown-linux-gnu` (Linux ARM64)
- `x86_64-apple-darwin` (macOS x64)
- `aarch64-apple-darwin` (macOS Apple Silicon)
- `x86_64-pc-windows-msvc` (Windows x64)

### Naming Convention
Archives should be named using the format:
`soroban-debug-v<VERSION>-<TARGET>.<EXT>`

*Example:* `soroban-debug-v1.0.0-x86_64-apple-darwin.tar.gz`
*(Use `.zip` for Windows, `.tar.gz` for Unix-like systems)*

## 2. Manual Pages

Manual pages are distributed alongside the CLI and must be updated before cutting a release.

- **Generation:** Run `make regen-man` to build the latest `.1` files from the CLI source.
- **Artifacts:** The resulting `man/man1/soroban-debug*.1` files must be committed to the repository and included in the release source tarballs.
- **Validation:** CI (`make check-man`) enforces that man pages do not drift from the CLI definition.

## 3. VS Code Extension

The VS Code DAP extension must be packaged and released concurrently with the CLI to ensure protocol compatibility.

- **Packaging Command:** `npm run vscode:prepublish` followed by `vsce package` (or equivalent).
- **Artifact:** `soroban-debugger-<VERSION>.vsix`
- **Validation:** 
  - The `package.json` version must match the CLI release version.
  - The extension must pass the DAP end-to-end tests (`npm run test:dap-e2e`).
  - Manifest validation (`ajv-cli` check against `package.schema.json`) must pass.

## 4. Documentation & Examples

- **CHANGELOG.md:** Must be updated with all user-facing changes, bug fixes, and breaking changes.
- **Feature Matrix:** Verify `docs/feature-matrix.md` is up-to-date with any new CLI/Extension flags.
- **Examples Verification:** All contracts and configuration files in the `examples/` directory must be tested against the compiled release binary to ensure no regressions have broken the documented workflows.