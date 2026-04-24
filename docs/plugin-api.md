# Plugin System API Documentation

The Soroban Debugger plugin system allows developers to extend the debugger's functionality through dynamically loaded plugins. Plugins can hook into execution events, provide custom CLI commands, and add output formatters.

## Table of Contents

1. [Overview](#overview)
2. [Plugin Architecture](#plugin-architecture)
3. [Creating a Plugin](#creating-a-plugin)
4. [Plugin Trait API](#plugin-trait-api)
5. [Execution Events](#execution-events)
6. [Plugin Manifest](#plugin-manifest)
7. [Installation and Loading](#installation-and-loading)
8. [Hot-Reload Support](#hot-reload-support)
9. [Best Practices](#best-practices)
10. [Examples](#examples)

## Overview

The plugin system is designed to be:

- **Safe**: Plugins run in the same process but with clear boundaries
- **Flexible**: Plugins can hook various execution points
- **Hot-reloadable**: Plugins can be reloaded without restarting the debugger
- **Easy to develop**: Simple trait-based API

### Key Features

- ✅ Hook into execution events (before/after function calls, instruction steps, etc.)
- ✅ Provide custom CLI commands
- ✅ Add custom output formatters
- ✅ Hot-reload without restarting
- ✅ Plugin dependencies
- ✅ Version compatibility checking

## Plugin Architecture

### Plugin Loading

Plugins are loaded from `~/.soroban-debug/plugins/` on startup. Each plugin must:

1. Be in its own subdirectory
2. Have a `plugin.toml` manifest file
3. Provide a shared library (`.so`, `.dylib`, or `.dll`)

By default, the debugger runs plugin trust checks in `warn` mode. Unsigned or untrusted plugins still load, but they emit warnings with remediation steps. In `enforce` mode, they are blocked before the shared library is loaded.

```
~/.soroban-debug/plugins/
├── my-plugin/
│   ├── plugin.toml
│   └── libmy_plugin.dylib
└── another-plugin/
    ├── plugin.toml
    └── libanother_plugin.so
```

### Plugin Lifecycle

1. **Discovery**: Debugger scans plugin directory
2. **Loading**: Dynamic library is loaded
3. **Initialization**: `initialize()` is called
4. **Execution**: Plugin receives events and handles commands
5. **Shutdown**: `shutdown()` is called when debugger exits

## Creating a Plugin

### Step 1: Create a New Rust Library

```bash
cargo new --lib my_soroban_plugin
cd my_soroban_plugin
```

### Step 2: Configure Cargo.toml

```toml
[package]
name = "my_soroban_plugin"
version = "1.0.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]  # Required for dynamic loading

[dependencies]
soroban-debugger = { path = "path/to/soroban-debugger" }
```

### Step 3: Implement the Plugin Trait

```rust
use soroban_debugger::plugin::{
    EventContext, ExecutionEvent, InspectorPlugin,
    PluginManifest, PluginResult, PluginCapabilities,
};

pub struct MyPlugin {
    manifest: PluginManifest,
}

impl MyPlugin {
    fn new() -> Self {
        Self {
            manifest: PluginManifest {
                name: "my-plugin".to_string(),
                version: "1.0.0".to_string(),
                description: "My awesome plugin".to_string(),
                author: "Your Name".to_string(),
                license: Some("MIT".to_string()),
                min_debugger_version: Some("0.1.0".to_string()),
                capabilities: PluginCapabilities {
                    hooks_execution: true,
                    provides_commands: false,
                    provides_formatters: false,
                    supports_hot_reload: false,
                },
                library: "libmy_soroban_plugin.dylib".to_string(),
                dependencies: vec![],
                signature: None,
            },
        }
    }
}

impl InspectorPlugin for MyPlugin {
    fn metadata(&self) -> PluginManifest {
        self.manifest.clone()
    }

    fn initialize(&mut self) -> PluginResult<()> {
        println!("My plugin initialized!");
        Ok(())
    }

    fn on_event(&mut self, event: &ExecutionEvent, context: &mut EventContext) -> PluginResult<()> {
        // Handle events here
        match event {
            ExecutionEvent::BeforeFunctionCall { function, .. } => {
                println!("About to call function: {}", function);
            }
            _ => {}
        }
        Ok(())
    }
}

/// Export the constructor function
#[no_mangle]
pub extern "C" fn create_plugin() -> *mut dyn InspectorPlugin {
    Box::into_raw(Box::new(MyPlugin::new()))
}
```

### Step 4: Create plugin.toml

```toml
schema_version = "1.0.0"
name = "my-plugin"
version = "1.0.0"
description = "My awesome plugin for Soroban debugger"
author = "Your Name"
license = "MIT"
min_debugger_version = "0.1.0"

[capabilities]
hooks_execution = true
provides_commands = false
provides_formatters = false
supports_hot_reload = false

library = "libmy_soroban_plugin.dylib"

dependencies = []
```

### Step 5: Build and Install

```bash
# Build the plugin
cargo build --release

# Install
mkdir -p ~/.soroban-debug/plugins/my-plugin
cp target/release/libmy_soroban_plugin.dylib ~/.soroban-debug/plugins/my-plugin/
cp plugin.toml ~/.soroban-debug/plugins/my-plugin/
```

## Plugin Trait API

### Core Methods

#### `metadata() -> PluginManifest`

Returns the plugin's metadata. Called once during plugin discovery.

```rust
fn metadata(&self) -> PluginManifest {
    self.manifest.clone()
}
```

#### `initialize(&mut self) -> PluginResult<()>`

Called once when the plugin is loaded. Use this to set up resources, open files, establish connections, etc.

```rust
fn initialize(&mut self) -> PluginResult<()> {
    // Setup code here
    Ok(())
}
```

#### `shutdown(&mut self) -> PluginResult<()>`

Called when the plugin is being unloaded. Clean up resources here.

```rust
fn shutdown(&mut self) -> PluginResult<()> {
    // Cleanup code here
    Ok(())
}
```

### Event Handling

#### `on_event(&mut self, event: &ExecutionEvent, context: &mut EventContext) -> PluginResult<()>`

Called for each execution event. The plugin can inspect and log events, modify the context for other plugins, or take any custom action.

**Parameters:**
- `event`: The execution event (see [Execution Events](#execution-events))
- `context`: Mutable context that can be shared between plugins

```rust
fn on_event(&mut self, event: &ExecutionEvent, context: &mut EventContext) -> PluginResult<()> {
    match event {
        ExecutionEvent::BeforeFunctionCall { function, args } => {
            println!("Calling {}", function);
        }
        ExecutionEvent::AfterFunctionCall { function, result, duration } => {
            println!("Finished {} in {:?}", function, duration);
        }
        _ => {}
    }
    Ok(())
}
```

### Custom Commands

#### `commands(&self) -> Vec<PluginCommand>`

Returns a list of custom CLI commands provided by this plugin.

```rust
fn commands(&self) -> Vec<PluginCommand> {
    vec![
        PluginCommand {
            name: "my-command".to_string(),
            description: "Does something awesome".to_string(),
            arguments: vec![
                ("arg1".to_string(), "First argument".to_string(), true),
            ],
        }
    ]
}
```

#### `execute_command(&mut self, command: &str, args: &[String]) -> PluginResult<String>`

Execute a custom command.

```rust
fn execute_command(&mut self, command: &str, args: &[String]) -> PluginResult<String> {
    match command {
        "my-command" => {
            // Execute command logic
            Ok("Command result".to_string())
        }
        _ => Err(PluginError::ExecutionFailed("Unknown command".to_string()))
    }
}
```

### Hot-Reload Support

#### `supports_hot_reload(&self) -> bool`

Indicates whether the plugin supports hot-reload.

```rust
fn supports_hot_reload(&self) -> bool {
    true
}
```

#### `prepare_reload(&self) -> PluginResult<Box<dyn Any + Send>>`

Called before reloading. Return state that should be preserved.

```rust
fn prepare_reload(&self) -> PluginResult<Box<dyn Any + Send>> {
    Ok(Box::new(self.internal_state.clone()))
}
```

#### `restore_from_reload(&mut self, state: Box<dyn Any + Send>) -> PluginResult<()>`

Called after reloading. Restore state from the previous version.

```rust
fn restore_from_reload(&mut self, state: Box<dyn Any + Send>) -> PluginResult<()> {
    if let Ok(saved_state) = state.downcast::<InternalState>() {
        self.internal_state = *saved_state;
        Ok(())
    } else {
        Err(PluginError::ExecutionFailed("Invalid state".to_string()))
    }
}
```

## Execution Events

Plugins can hook into various execution events:

### `BeforeFunctionCall`

Fired before a contract function is executed.

```rust
ExecutionEvent::BeforeFunctionCall {
    function: String,
    args: Option<String>,
}
```

### `AfterFunctionCall`

Fired after a contract function is executed.

```rust
ExecutionEvent::AfterFunctionCall {
    function: String,
    result: Result<String, String>,
    duration: Duration,
}
```

### `BeforeInstruction` / `AfterInstruction`

Fired before/after individual WASM instructions (when instruction debugging is enabled).

```rust
ExecutionEvent::BeforeInstruction {
    pc: u32,
    instruction: String,
}
```

### `BreakpointHit`

Fired when a breakpoint is hit.

```rust
ExecutionEvent::BreakpointHit {
    function: String,
    condition: Option<String>,
}
```

### `ExecutionPaused` / `ExecutionResumed`

Fired when execution is paused or resumed.

### `StorageAccess`

Fired when contract storage is accessed.

```rust
ExecutionEvent::StorageAccess {
    operation: StorageOperation,  // Read, Write, Delete, Has
    key: String,
    value: Option<String>,
}
```

### `DiagnosticEvent`

Fired for diagnostic events from the contract.

```rust
ExecutionEvent::DiagnosticEvent {
    contract_id: Option<String>,
    topics: Vec<String>,
    data: String,
}
```

### `Error`

Fired when an error occurs during execution.

```rust
ExecutionEvent::Error {
    message: String,
    context: Option<String>,
}
```

## Plugin Manifest

The `plugin.toml` file describes your plugin:

```toml
# Required fields
schema_version = "1.0.0"
name = "plugin-name"
version = "1.0.0"
description = "Plugin description"
author = "Author Name"
library = "libplugin.dylib"

# Optional fields
license = "MIT OR Apache-2.0"
min_debugger_version = "0.1.0"

# Capabilities
[capabilities]
hooks_execution = true          # Can hook execution events
provides_commands = true        # Provides custom CLI commands
provides_formatters = false     # Provides custom output formatters
supports_hot_reload = true      # Can be hot-reloaded

# Plugin dependencies (other plugins required)
dependencies = []

# Optional detached signatures for trusted loading
[signature]
signer = "example-signer"
public_key = "BASE64_ED25519_PUBLIC_KEY"
manifest_signature = "BASE64_SIGNATURE_OF_UNSIGNED_MANIFEST"
library_signature = "BASE64_SIGNATURE_OF_PLUGIN_LIBRARY"
```

### Trust Policy

Plugin trust policy is controlled through environment variables:

- `SOROBAN_DEBUG_PLUGIN_TRUST_MODE=off|warn|enforce`
- `SOROBAN_DEBUG_PLUGIN_ALLOWLIST=plugin-a,plugin-b`
- `SOROBAN_DEBUG_PLUGIN_DENYLIST=plugin-c`
- `SOROBAN_DEBUG_PLUGIN_ALLOWED_SIGNERS=team-release-key,abcdef1234...`

Policy behavior:

- `off`: trust checks are skipped
- `warn`: trust failures produce warnings but plugins still load
- `enforce`: denylisted, unsigned, invalidly signed, or unapproved plugins are blocked

In `enforce` mode, a plugin must either be explicitly allowlisted or provide a valid Ed25519 signature from an allowed signer.

## Installation and Loading

### Manual Installation

1. Build your plugin:
   ```bash
   cargo build --release
   ```

2. Create plugin directory:
   ```bash
   mkdir -p ~/.soroban-debug/plugins/my-plugin
   ```

3. Copy files:
   ```bash
   cp target/release/libmy_plugin.{so,dylib,dll} ~/.soroban-debug/plugins/my-plugin/
   cp plugin.toml ~/.soroban-debug/plugins/my-plugin/
   ```

### Disabling Plugins

Set the `SOROBAN_DEBUG_NO_PLUGINS` environment variable:

```bash
export SOROBAN_DEBUG_NO_PLUGINS=1
soroban-debug run --contract ./contract.wasm --function test
```

### Plugin Discovery

On startup, the debugger:

1. Scans `~/.soroban-debug/plugins/` for subdirectories
2. Looks for `plugin.toml` in each subdirectory
3. Validates the manifest
4. Evaluates trust policy, signature state, allowlist, and denylist
5. Checks version compatibility
6. Resolves dependencies
7. Loads the shared library
8. Calls `initialize()`

## Hot-Reload Support

Plugins that support hot-reload can be updated without restarting the debugger. When a plugin is reloaded, the debugger automatically detects and reports all changes, making it easy to verify that your updates were loaded correctly.

### Change Detection

The hot-reload system tracks and reports:

- **Version changes**: Old version → New version
- **Capability changes**: Which capabilities were enabled or disabled
- **Command changes**: Commands added or removed
- **Formatter changes**: Formatters added or removed
- **Dependency changes**: Dependencies added or removed

Example reload output:
```
Plugin 'example-logger' reload changes:
  Version: 1.0.0 → 1.1.0
  Capabilities:
    provides_commands: false → true
  Commands added: log-stats, clear-log
  Formatters added: json-formatter
  Dependencies added: helper-plugin
```

If no changes are detected, you'll see:
```
Plugin 'example-logger' reloaded with no changes
```

This immediate feedback helps during iterative plugin development, allowing you to:
- Verify that code changes were compiled and loaded
- Confirm that new features are properly exposed
- Catch unintended changes or regressions
- Trust that the reload succeeded as expected

### Implementing Hot-Reload

1. Set `supports_hot_reload = true` in capabilities
2. Implement `supports_hot_reload()` to return `true`
3. Implement `prepare_reload()` to save state
4. Implement `restore_from_reload()` to restore state

```rust
impl InspectorPlugin for MyPlugin {
    fn supports_hot_reload(&self) -> bool {
        true
    }

    fn prepare_reload(&self) -> PluginResult<Box<dyn Any + Send>> {
        Ok(Box::new(self.state.clone()))
    }

    fn restore_from_reload(&mut self, state: Box<dyn Any + Send>) -> PluginResult<()> {
        if let Ok(saved_state) = state.downcast::<State>() {
            self.state = *saved_state;
            Ok(())
        } else {
            Err(PluginError::ExecutionFailed("Invalid state".to_string()))
        }
    }
}
```

## Best Practices

### Error Handling

Always return proper errors:

```rust
fn on_event(&mut self, event: &ExecutionEvent, context: &mut EventContext) -> PluginResult<()> {
    self.process_event(event).map_err(|e| {
        PluginError::ExecutionFailed(format!("Failed to process event: {}", e))
    })
}
```

### Resource Management

Clean up resources in `shutdown()`:

```rust
fn shutdown(&mut self) -> PluginResult<()> {
    if let Some(file) = self.log_file.take() {
        drop(file);  // Close file
    }
    Ok(())
}
```

### Thread Safety

Plugins should be thread-safe. Use `Mutex` or `RwLock` for shared state:

```rust
pub struct MyPlugin {
    state: Arc<Mutex<State>>,
}
```

### Performance

- Keep event handlers fast
- Avoid blocking operations in event handlers
- Use async operations when possible
- Buffer I/O operations

### Logging

Use the `tracing` crate for logging:

```rust
use tracing::{info, warn, error};

fn on_event(&mut self, event: &ExecutionEvent, _context: &mut EventContext) -> PluginResult<()> {
    info!("Processing event: {:?}", event);
    Ok(())
}
```

## Examples

### Example 1: Event Logger

See the complete example in `examples/plugins/example_logger/`.

### Example 2: Performance Monitor

```rust
use std::time::{Duration, Instant};
use std::collections::HashMap;

pub struct PerformanceMonitor {
    function_times: HashMap<String, Vec<Duration>>,
}

impl InspectorPlugin for PerformanceMonitor {
    fn on_event(&mut self, event: &ExecutionEvent, _context: &mut EventContext) -> PluginResult<()> {
        if let ExecutionEvent::AfterFunctionCall { function, duration, .. } = event {
            self.function_times
                .entry(function.clone())
                .or_insert_with(Vec::new)
                .push(*duration);
        }
        Ok(())
    }

    fn commands(&self) -> Vec<PluginCommand> {
        vec![
            PluginCommand {
                name: "perf-stats".to_string(),
                description: "Show performance statistics".to_string(),
                arguments: vec![],
            }
        ]
    }

    fn execute_command(&mut self, command: &str, _args: &[String]) -> PluginResult<String> {
        if command == "perf-stats" {
            let mut output = String::new();
            for (func, times) in &self.function_times {
                let avg = times.iter().sum::<Duration>() / times.len() as u32;
                output.push_str(&format!("{}: avg {:?}, calls: {}\n", func, avg, times.len()));
            }
            Ok(output)
        } else {
            Err(PluginError::ExecutionFailed("Unknown command".to_string()))
        }
    }
}
```

### Example 3: Custom Output Formatter

```rust
impl InspectorPlugin for JsonFormatter {
    fn formatters(&self) -> Vec<OutputFormatter> {
        vec![
            OutputFormatter {
                name: "pretty-json".to_string(),
                supported_types: vec!["execution-result".to_string()],
            }
        ]
    }

    fn format_output(&self, _formatter: &str, data: &str) -> PluginResult<String> {
        let parsed: serde_json::Value = serde_json::from_str(data)
            .map_err(|e| PluginError::ExecutionFailed(e.to_string()))?;
        serde_json::to_string_pretty(&parsed)
            .map_err(|e| PluginError::ExecutionFailed(e.to_string()))
    }
}
```

## API Stability

The plugin API follows semantic versioning:

- **Major version changes**: Breaking API changes
- **Minor version changes**: New features, backward compatible
- **Patch version changes**: Bug fixes, backward compatible

Check `min_debugger_version` in your manifest to specify the minimum required debugger version.

For details on manifest file versioning, see Plugin Manifest Versioning.

## Troubleshooting

### Plugin Not Loading

- Check that `plugin.toml` is valid TOML
- Check that the `schema_version` in `plugin.toml` is compatible with the debugger version.
- Verify the library file exists and has the correct name
- Ensure the library exports `create_plugin` symbol
- If trust policy blocked the plugin, sign the manifest and library, add the plugin to the allowlist, or relax `SOROBAN_DEBUG_PLUGIN_TRUST_MODE` for local-only development
- Check debugger logs for error messages

### Hot-Reload Fails

- Verify that `supports_hot_reload` returns `true`
- Ensure state serialization/deserialization works correctly
- Check for file locks or resource conflicts

### Events Not Received

- Confirm `hooks_execution = true` in capabilities
- Verify `on_event` is implemented correctly
- Check that the event type you're expecting is actually fired

## Additional Resources

- [Example Logger Plugin](../examples/plugins/example_logger/)
- [Plugin API Reference](https://docs.rs/soroban-debugger/latest/soroban_debugger/plugin/)
- [GitHub Issues](https://github.com/Timi16/soroban-debugger/issues)
