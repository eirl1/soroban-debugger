pub mod api;
pub mod events;
pub mod loader;
pub mod manifest;
pub mod registry;

pub use api::{
    InspectorPlugin, OutputFormatter, PluginCommand, PluginError, PluginResult,
    PLUGIN_CONSTRUCTOR_SYMBOL,
};
pub use events::{
    EventContext, ExecutionEvent, PluginInvocationKind, PluginInvocationOutcome,
    PluginTelemetryEvent, StorageOperation,
};
pub use loader::{
    LoadedPlugin, PluginLoader, PluginTrustAssessment, PluginTrustMode, PluginTrustPolicy,
};
pub use manifest::{PluginCapabilities, PluginManifest, PluginSignature, VerifiedPluginSignature};
pub use registry::{PluginRegistry, PluginStatistics};
