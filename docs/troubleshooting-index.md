# Troubleshooting Index

Welcome to the Soroban Debugger troubleshooting center. If you are running into issues, find your symptom or category below to jump to the right guide.

## Quick Links

- **[FAQ](faq.md)**: Frequently asked questions covering installation, usage, differences between CLI and VS Code, and more.
- **[Remote & Timeout Troubleshooting](remote-troubleshooting.md)**: Resolving connection hangs, timeouts, protocol mismatches, and CI sandbox network restrictions.
- **[Plugin Failure Handling](plugin-failure-handling.md)**: What happens when a plugin crashes or times out, and how to read the incident reports.
- **[Source Map Health Diagnostics](source-map-health.md)**: Fixing "unverified" breakpoints and understanding missing DWARF debug info.
- **[Source-Level Debugging Limitations](source-level-debugging.md#limitations)**: Stripped binaries and path resolution issues.

## By Symptom

### Installation & Setup
- `cargo install` fails with "linker 'cc' not found": see FAQ: Installation
- "Rust 1.75 or later required": see FAQ: Installation
- Missing manual pages (`man`): see FAQ: Installation

### Running Contracts & Runtime Failures
- "No such file or directory" loading WASM: see FAQ: Running Contracts
- "Function not found": see FAQ: Running Contracts
- "Host error: Unknown error" or rust `panic!`: see FAQ: Running Contracts

### Argument Parsing
- "Type/value mismatch" for arguments: see FAQ: Argument Parsing
- JSON argument parsing fails (quoting issues): see FAQ: Argument Parsing
- Passing Address arguments: see FAQ: Argument Parsing

### Breakpoints & Source Maps
- Breakpoints don't trigger or appear as "unverified": see FAQ: Breakpoints and Source Map Diagnostics
- Setting breakpoints on specific lines vs function boundaries: see FAQ: Breakpoints

### Remote Debugging & Connections
- Initial connection hangs (`connect timed out`): see Remote Troubleshooting: Connect Timeout
- `Request timed out` during session: see Remote Troubleshooting: Request Timeout
- Connection refused: see Remote Troubleshooting: CLI Checklist
- TLS or Authentication failures: see Remote Debugging Guide

### CI & Sandboxed Environments
- `listen EPERM` or loopback bind failures: see Local and CI Sandbox Failures
- `mktemp` or temporary directory write failures: see Local and CI Sandbox Failures

### Resource Budgets & Performance
- "Warning: High CPU usage detected" or "Budget exceeded": see FAQ: Budget and the Optimization Guide

### Visual Studio Code Extension
- Feature gaps between CLI and extension: see FAQ: CLI vs VS Code
- Connecting VS Code to a remote server: see FAQ: Remote Debugging from VS Code
- Managing huge storage states in variables panel: see FAQ: Storage Filters