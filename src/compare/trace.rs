//! Execution trace data structures for the compare subcommand.
//!
//! An `ExecutionTrace` captures the full execution record of a single
//! contract invocation so that two traces can be compared side-by-side
//! for regression testing.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Top-level execution trace that is serialized to / deserialized from JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTrace {
    /// Human-readable label for this trace (e.g. "v1.0 transfer test")
    #[serde(default)]
    pub label: Option<String>,

    /// Contract identifier (WASM path or contract ID)
    #[serde(default)]
    pub contract: Option<String>,

    /// Function that was invoked
    #[serde(default)]
    pub function: Option<String>,

    /// Arguments passed to the function
    #[serde(default)]
    pub args: Option<String>,

    /// Storage state after execution (key → value).
    /// Uses BTreeMap for deterministic ordering.
    #[serde(default)]
    pub storage: BTreeMap<String, serde_json::Value>,

    /// Resource budget consumed during execution
    #[serde(default)]
    pub budget: Option<BudgetTrace>,

    /// Return value of the invocation (serialized as JSON value)
    #[serde(default)]
    pub return_value: Option<serde_json::Value>,

    /// Ordered sequence of function calls observed during execution
    #[serde(default)]
    pub call_sequence: Vec<CallEntry>,

    /// Events emitted during execution
    #[serde(default)]
    pub events: Vec<EventEntry>,
}

/// Budget / resource usage captured in a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetTrace {
    pub cpu_instructions: u64,
    pub memory_bytes: u64,
    #[serde(default)]
    pub cpu_limit: Option<u64>,
    #[serde(default)]
    pub memory_limit: Option<u64>,
}

/// A single entry in the call sequence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CallEntry {
    /// Name of the function that was called
    pub function: String,
    /// Optional arguments snapshot
    #[serde(default)]
    pub args: Option<String>,
    /// Nesting depth (0 = top-level)
    #[serde(default)]
    pub depth: u32,
}

/// A single event emitted during execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventEntry {
    #[serde(default)]
    pub contract_id: Option<String>,
    #[serde(default)]
    pub topics: Vec<String>,
    #[serde(default)]
    pub data: Option<String>,
}

impl std::fmt::Display for CallEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let indent = "  ".repeat(self.depth as usize);
        if let Some(ref args) = self.args {
            write!(f, "{}{}({})", indent, self.function, args)
        } else {
            write!(f, "{}{}()", indent, self.function)
        }
    }
}

impl std::fmt::Display for EventEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let contract = self.contract_id.as_deref().unwrap_or("<unknown-contract>");
        let topics = self.topics.join(", ");
        let data = self.data.as_deref().unwrap_or("<no-data>");
        write!(f, "[{}] topics=[{}] data={}", contract, topics, data)
    }
}

impl ExecutionTrace {
    /// Load an execution trace from a JSON file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> crate::Result<Self> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path).map_err(|e| {
            crate::DebuggerError::FileError(format!("Failed to read trace file {:?}: {}", path, e))
        })?;
        let trace: ExecutionTrace = serde_json::from_str(&contents).map_err(|e| {
            crate::DebuggerError::FileError(format!("Failed to parse trace file {:?}: {}", path, e))
        })?;
        Ok(trace)
    }

    /// Serialize this trace to a pretty-printed JSON string.
    pub fn to_json(&self) -> crate::Result<String> {
        Ok(serde_json::to_string_pretty(self).map_err(|e| {
            crate::DebuggerError::FileError(format!("Failed to serialize trace: {}", e))
        })?)
    }

    pub fn manifest_path_for_trace(trace_path: &Path) -> PathBuf {
        trace_path.with_extension("manifest.json")
    }

    pub fn to_replay_artifact_manifest(
        &self,
        trace_path: &Path,
    ) -> crate::output::ReplayArtifactManifest {
        crate::output::ReplayArtifactManifest {
            schema_version: crate::output::SCHEMA_VERSION.to_string(),
            artifact_group: "replay_artifacts".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            label: self.label.clone(),
            contract: self.contract.clone(),
            function: self.function.clone(),
            files: vec![crate::output::ReplayArtifactFile {
                kind: crate::output::ReplayArtifactKind::Trace,
                path: trace_path.display().to_string(),
                description: Some("Primary execution trace used for replay".to_string()),
                compression: None,
            }],
        }
    }
}

/// Trace schema versions this debugger knows how to replay.
pub const SUPPORTED_TRACE_VERSIONS: &[u64] = &[1];

/// Validate a raw trace JSON value before replay execution (#1288).
///
/// Fails fast when the file is malformed or from an unsupported schema version:
/// it must be a JSON object, carry a supported `version` if one is present, and
/// have the minimum fields needed to replay (a non-empty `call_sequence` or a
/// `function`). See `docs/trace-compatibility.md`.
pub fn validate_trace_schema(raw: &serde_json::Value) -> crate::Result<()> {
    let obj = raw.as_object().ok_or_else(|| {
        crate::DebuggerError::InvalidArguments("trace file must be a JSON object".to_string())
    })?;

    if let Some(version) = obj.get("version") {
        let v = version.as_u64().ok_or_else(|| {
            crate::DebuggerError::InvalidArguments(
                "trace `version` must be a positive integer".to_string(),
            )
        })?;
        if !SUPPORTED_TRACE_VERSIONS.contains(&v) {
            return Err(crate::DebuggerError::InvalidArguments(format!(
                "unsupported trace schema version {}. This debugger supports {:?}. \
                 Re-capture the trace with a matching debugger version, or migrate the file.",
                v, SUPPORTED_TRACE_VERSIONS
            ))
            .into());
        }
    }

    let has_calls = obj
        .get("call_sequence")
        .and_then(|v| v.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false);
    let has_function = obj
        .get("function")
        .and_then(|v| v.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    if !has_calls && !has_function {
        return Err(crate::DebuggerError::InvalidArguments(
            "malformed trace: needs a non-empty `call_sequence` or a `function` field to replay"
                .to_string(),
        )
        .into());
    }

    Ok(())
}

#[cfg(test)]
mod trace_schema_tests {
    use super::validate_trace_schema;
    use serde_json::json;

    #[test]
    fn accepts_a_minimal_valid_trace() {
        assert!(validate_trace_schema(&json!({ "function": "transfer" })).is_ok());
        assert!(validate_trace_schema(
            &json!({ "version": 1, "call_sequence": [{ "function": "f", "depth": 0 }] })
        )
        .is_ok());
    }

    #[test]
    fn rejects_non_object() {
        assert!(validate_trace_schema(&json!([1, 2, 3])).is_err());
    }

    #[test]
    fn rejects_unsupported_version() {
        let err = validate_trace_schema(&json!({ "version": 999, "function": "f" })).unwrap_err();
        assert!(err.to_string().contains("unsupported trace schema version"));
    }

    #[test]
    fn rejects_malformed_missing_required_fields() {
        let err = validate_trace_schema(&json!({ "label": "no calls here" })).unwrap_err();
        assert!(err.to_string().contains("malformed trace"));
    }
}
