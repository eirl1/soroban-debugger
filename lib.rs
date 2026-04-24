use soroban_debugger::plugin::api::{
    InspectorPlugin, PluginCommand, PluginError, PluginManifest, PluginResult,
};
use soroban_debugger::plugin::events::{EventContext, ExecutionEvent};

/// The main plugin state struct.
/// You can add any custom state you need across execution events here.
pub struct StarterPlugin {
    manifest: PluginManifest,
    call_count: usize,
}

impl StarterPlugin {
    pub fn new() -> Self {
        // Return the plugin instance with baseline metadata matching plugin.toml.
        Self {
            manifest: PluginManifest {
                name: "starter-plugin".to_string(),
                version: "0.1.0".to_string(),
                description: "A starter template for building Soroban Debugger plugins".to_string(),
                author: "Your Name".to_string(),
                license: Some("MIT".to_string()),
                min_debugger_version: Some("0.1.0".to_string()),
                capabilities: soroban_debugger::plugin::manifest::PluginCapabilities {
                    hooks_execution: true,
                    provides_commands: true,
                    provides_formatters: false,
                    supports_hot_reload: false,
                },
                library: "libsoroban_debug_starter_plugin.so".to_string(),
                dependencies: vec![],
                signature: None,
            },
            call_count: 0,
        }
    }
}

impl InspectorPlugin for StarterPlugin {
    /// Returns the plugin's manifest to the debugger.
    fn metadata(&self) -> PluginManifest {
        self.manifest.clone()
    }

    /// Called once when the plugin is successfully loaded.
    fn initialize(&mut self) -> PluginResult<()> {
        tracing::info!("Starter plugin initialized!");
        Ok(())
    }

    /// Called when the plugin is being unloaded.
    fn shutdown(&mut self) -> PluginResult<()> {
        tracing::info!("Starter plugin shutting down. Total function calls observed: {}", self.call_count);
        Ok(())
    }

    /// Called for each execution event emitted by the debugger.
    fn on_event(&mut self, event: &ExecutionEvent, _context: &mut EventContext) -> PluginResult<()> {
        match event {
            ExecutionEvent::BeforeFunctionCall { function, args } => {
                tracing::info!("Starter Plugin: About to call function '{}' with args: {:?}", function, args);
                self.call_count += 1;
            }
            ExecutionEvent::AfterFunctionCall { function, result, duration } => {
                tracing::info!(
                    "Starter Plugin: Finished function '{}' in {:?}. Result: {:?}",
                    function, duration, result
                );
            }
            _ => {}
        }
        Ok(())
    }

    /// Returns a list of custom CLI commands provided by this plugin.
    fn commands(&self) -> Vec<PluginCommand> {
        vec![PluginCommand {
            name: "starter-status".to_string(),
            description: "Prints the current status of the starter plugin".to_string(),
            arguments: vec![],
        }]
    }

    /// Execute a custom command invoked by the user.
    fn execute_command(&mut self, command: &str, _args: &[String]) -> PluginResult<String> {
        match command {
            "starter-status" => {
                Ok(format!("Starter plugin is active. Function calls intercepted: {}", self.call_count))
            }
            _ => Err(PluginError::ExecutionFailed(format!("Unknown command: {}", command))),
        }
    }
}

/// Export the constructor function.
/// This is the entry point that the Soroban Debugger looks for when loading the dynamic library.
#[no_mangle]
pub extern "C" fn create_plugin() -> *mut dyn InspectorPlugin {
    Box::into_raw(Box::new(StarterPlugin::new()))
}