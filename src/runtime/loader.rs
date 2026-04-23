//! WASM contract loading and Soroban environment initialisation.
//!
//! This module is responsible for:
//! - Reading and validating WASM bytes.
//! - Bootstrapping a [`soroban_sdk::Env`] in debug mode.
//! - Registering the contract with the host.
//! - Loading the custom error catalogue from the contract spec.
//!
//! It intentionally has **no** knowledge of argument parsing or invocation
//! so it can be unit-tested with a minimal WASM fixture.

use crate::debugger::error_db::ErrorDatabase;
use crate::utils::wasm::{extract_wasm_artifact_metadata, WasmArtifactMetadata};
use crate::{DebuggerError, Result};
use indicatif::{ProgressBar, ProgressStyle};
use soroban_env_host::DiagnosticLevel;
use soroban_sdk::{Address, Env};
use tracing::{info, warn};

/// Output of a successful [`load_contract`] call.
pub struct LoadedContract {
    pub env: Env,
    pub contract_address: Address,
    pub error_db: ErrorDatabase,
}

pub fn inspect_contract_artifact(wasm: &[u8]) -> Result<WasmArtifactMetadata> {
    extract_wasm_artifact_metadata(wasm)
}

/// Initialise a Soroban test environment and register `wasm` as a contract.
///
/// Displays a progress bar to the terminal while work is in progress and
/// ensures it is always cleared — even if this function returns an error.
#[tracing::instrument(skip_all)]
pub fn load_contract(wasm: &[u8]) -> Result<LoadedContract> {
    info!("Initializing contract executor");

    if let Ok(artifact) = inspect_contract_artifact(wasm) {
        info!(
            build_profile_hint = %artifact.build_profile_hint,
            optimization_hint = %artifact.optimization_hint,
            has_debug_sections = artifact.has_debug_sections,
            name_section_present = artifact.name_section_present,
            module_name = artifact.module_name.as_deref().unwrap_or("<none>"),
            "Parsed WASM artifact metadata"
        );

        if !artifact.has_debug_sections {
            warn!(
                "WASM artifact does not contain DWARF debug sections; source-level debugging may fall back to WASM-only behavior"
            );
        }
    }

    let pb = ProgressBar::new(100);
    pb.set_style(
        ProgressStyle::default_bar()
            // `indicatif` 0.17+ — template uses `{wide_bar}` not `{bar}`
            .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb.set_message("Loading WASM contract...");

    // RAII guard: progress bar is always cleared, even on early return.
    struct ProgressGuard(ProgressBar);
    impl Drop for ProgressGuard {
        fn drop(&mut self) {
            self.0.finish_and_clear();
        }
    }
    let guard = ProgressGuard(pb);

    let env = Env::default();
    env.host()
        .set_diagnostic_level(DiagnosticLevel::Debug)
        .map_err(|e| {
            DebuggerError::ExecutionError(format!("Failed to set diagnostic level: {:?}", e))
        })?;

    guard.0.set_position(50);
    guard.0.set_message("Registering contract...");

    // `env.register` is the current, non-deprecated API in soroban-sdk ≥ 0.0.18.
    let contract_address = env.register(wasm, ());

    let mut error_db = ErrorDatabase::new();
    if let Err(e) = error_db.load_custom_errors_from_wasm(wasm) {
        warn!("Failed to load custom errors from spec: {}", e);
    }

    guard.0.set_position(100);
    guard.0.set_message("Contract loaded successfully");

    Ok(LoadedContract {
        env,
        contract_address,
        error_db,
    })
}
