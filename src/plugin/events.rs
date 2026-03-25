use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Events that plugins can hook into during execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionEvent {
    /// Fired before a contract function is executed
    BeforeFunctionCall {
        function: String,
        args: Option<String>,
    },

    /// Fired after a contract function is executed
    AfterFunctionCall {
        function: String,
        result: Result<String, String>,
        duration: Duration,
    },

    /// Fired when an instruction is about to be executed
    BeforeInstruction { pc: u32, instruction: String },

    /// Fired after an instruction is executed
    AfterInstruction { pc: u32, instruction: String },

    /// Fired when a breakpoint is hit
    BreakpointHit {
        function: String,
        condition: Option<String>,
    },

    /// Fired when execution is paused
    ExecutionPaused { reason: String },

    /// Fired when execution is resumed
    ExecutionResumed,

    /// Fired when storage is accessed
    StorageAccess {
        operation: StorageOperation,
        key: String,
        value: Option<String>,
    },

    /// Fired when diagnostic events occur
    DiagnosticEvent {
        contract_id: Option<String>,
        topics: Vec<String>,
        data: String,
    },

    /// Fired when an error occurs
    Error {
        message: String,
        context: Option<String>,
    },
}

/// Types of storage operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageOperation {
    Read,
    Write,
    Delete,
    Has,
}

/// Context passed to plugin event handlers
#[derive(Debug, Clone)]
pub struct EventContext {
    /// Current call stack depth
    pub stack_depth: usize,

    /// Current program counter (if in instruction mode)
    pub program_counter: Option<u32>,

    /// Whether execution is paused
    pub is_paused: bool,

    /// Custom context data that plugins can use to store state
    pub custom_data: HashMap<String, String>,

    /// Plugin execution telemetry accumulated during this dispatch cycle
    pub plugin_telemetry: Vec<PluginTelemetryEvent>,
}

impl EventContext {
    pub fn new() -> Self {
        Self {
            stack_depth: 0,
            program_counter: None,
            is_paused: false,
            custom_data: HashMap::new(),
            plugin_telemetry: Vec::new(),
        }
    }
}

impl Default for EventContext {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PluginInvocationKind {
    Hook,
    Command,
    Formatter,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PluginInvocationOutcome {
    Success,
    Failure,
    Timeout,
    SkippedCircuitOpen,
    Panic,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginTelemetryEvent {
    pub plugin: String,
    pub kind: PluginInvocationKind,
    pub outcome: PluginInvocationOutcome,
    pub duration_ms: u128,
    pub message: String,
}
