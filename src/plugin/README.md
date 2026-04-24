# Plugin System

The Soroban Debugger now features a powerful plugin system that allows you to extend its functionality with custom inspectors, commands, and formatters.

## Quick Start

### Using Plugins

Plugins are automatically loaded from `~/.soroban-debug/plugins/` when the debugger starts.

To disable plugins:
```bash
export SOROBAN_DEBUG_NO_PLUGINS=1
```

### Creating a Plugin

1. **Create a new Rust library:**
   ```bash
   cargo new --lib my_plugin
   cd my_plugin
   ```

2. **Configure `Cargo.toml`:**
   ```toml
   [package]
   name = "my_plugin"
   version = "1.0.0"
   edition = "2021"

   [lib]
   crate-type = ["cdylib"]

   [dependencies]
   soroban-debugger = { path = "path/to/soroban-debugger" }
   ```

3. **Implement the plugin trait:**
   ```rust
   use soroban_debugger::plugin::{
       EventContext, ExecutionEvent, InspectorPlugin,
       PluginManifest, PluginResult,
   };

   pub struct MyPlugin { /* ... */ }

   impl InspectorPlugin for MyPlugin {
       fn metadata(&self) -> PluginManifest { /* ... */ }
       fn on_event(&mut self, event: &ExecutionEvent, context: &mut EventContext) -> PluginResult<()> {
           // Handle events
           Ok(())
       }
   }

   #[no_mangle]
   pub extern "C" fn create_plugin() -> *mut dyn InspectorPlugin {
       Box::into_raw(Box::new(MyPlugin::new()))
   }
   ```

4. **Create `plugin.toml`:**
   ```toml
   schema_version = "1.0.0"
   name = "my-plugin"
   version = "1.0.0"
   description = "My awesome plugin"
   author = "Your Name"
   license = "MIT"
   min_debugger_version = "0.1.0"

   [capabilities]
   hooks_execution = true
   provides_commands = false
   provides_formatters = false
   supports_hot_reload = false

   library = "libmy_plugin.dylib"
   dependencies = []
   ```

5. **Build and install:**
   ```bash
   cargo build --release
   mkdir -p ~/.soroban-debug/plugins/my-plugin
   cp target/release/libmy_plugin.{so,dylib,dll} ~/.soroban-debug/plugins/my-plugin/
   cp plugin.toml ~/.soroban-debug/plugins/my-plugin/
   ```

## Plugin Capabilities

Plugins can:

- ✅ **Hook execution events** - Monitor function calls, instruction steps, breakpoints, storage access, etc.
- ✅ **Provide custom commands** - Add new CLI commands to the debugger
- ✅ **Add output formatters** - Create custom output formats
- ✅ **Support hot-reload** - Update plugins without restarting the debugger
- ✅ **Depend on other plugins** - Build on existing plugin functionality

### Hot-Reload with Change Detection

When a plugin is hot-reloaded, the debugger automatically detects and reports changes:

- Version updates
- Capability changes (hooks, commands, formatters, hot-reload support)
- Added or removed commands
- Added or removed formatters
- Dependency changes

This makes it easy to verify that your plugin changes were loaded correctly during iterative development.

Example reload output:
```
Plugin 'example-logger' reload changes:
  Version: 1.0.0 → 1.1.0
  Capabilities:
    provides_commands: false → true
  Commands added: new-command
  Formatters added: json-formatter
```

## Execution Events

Plugins can hook into these events:

- `BeforeFunctionCall` / `AfterFunctionCall`
- `BeforeInstruction` / `AfterInstruction`
- `BreakpointHit`
- `ExecutionPaused` / `ExecutionResumed`
- `StorageAccess`
- `DiagnosticEvent`
- `Error`

## Example Plugin

See the [example logger plugin](../examples/plugins/example_logger/) for a complete working example that:

- Logs all execution events to a file
- Provides custom commands (`log-stats`, `log-path`, `clear-log`)
- Supports hot-reload

## Documentation

- [Complete Plugin API Documentation](../docs/plugin-api.md)
- [Example Plugin Source](../examples/plugins/example_logger/src/lib.rs)

## Architecture

The plugin system uses dynamic library loading (`libloading` crate) to load plugins at runtime. Each plugin:

1. Implements the `InspectorPlugin` trait
2. Exports a `create_plugin` constructor function
3. Is loaded from a subdirectory in `~/.soroban-debug/plugins/`
4. Receives events through the `on_event` callback

The `PluginRegistry` manages all loaded plugins and dispatches events to them.

## Plugin Commands and Formatters

Plugins can provide custom CLI commands via [`InspectorPlugin::commands`]. These are routed at runtime
using clap's external subcommand support, so a plugin command named `my-command` can be invoked as:

```bash
soroban-debug my-command arg1 arg2
```

Plugins can also provide output formatters via [`InspectorPlugin::formatters`]. If no plugin command matches
an external subcommand, the debugger will attempt to treat it as a formatter name and pass the remaining
arguments as the input payload:

```bash
soroban-debug my-formatter '{\"some\":\"json\"}'
```

## Security Considerations

⚠️ **Warning**: Plugins run in the same process as the debugger with full access to your system. Only install plugins from trusted sources.

## Platform Support

The plugin system supports:

- **Linux**: `.so` shared libraries
- **macOS**: `.dylib` dynamic libraries
- **Windows**: `.dll` dynamic libraries

## Contributing

We welcome plugin contributions! If you create a useful plugin, consider sharing it with the community.

## License

The plugin system is licensed under the same terms as the main debugger (MIT OR Apache-2.0).
