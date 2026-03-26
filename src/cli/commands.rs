use crate::cli::args::{
    AnalyzeArgs, CompareArgs, InspectArgs, InteractiveArgs, OptimizeArgs, ProfileArgs, RemoteArgs,
    ReplArgs, ReplayArgs, RunArgs, ServerArgs, SymbolicArgs, TuiArgs, UpgradeCheckArgs, Verbosity,
};
use crate::debugger::engine::DebuggerEngine;
use crate::debugger::instruction_pointer::StepMode;
use crate::history::{check_regression, HistoryManager, RunHistory};
use crate::logging;
use crate::output::OutputConfig;
use crate::repeat::RepeatRunner;
use crate::runtime::executor::ContractExecutor;
use crate::simulator::SnapshotLoader;
use crate::ui::formatter::Formatter;
use crate::ui::tui::DebuggerUI;
use crate::{DebuggerError, Result};
use miette::WrapErr;
use std::fs;
use textplots::{Chart, Plot, Shape};

fn print_info(message: impl AsRef<str>) {
    println!("{}", Formatter::info(message));
}

fn print_success(message: impl AsRef<str>) {
    println!("{}", Formatter::success(message));
}

fn print_warning(message: impl AsRef<str>) {
    println!("{}", Formatter::warning(message));
}

/// Execute batch mode with parallel execution
fn run_batch(args: &RunArgs, batch_file: &std::path::Path) -> Result<()> {
    print_info(format!("Loading contract: {:?}", args.contract));
    logging::log_loading_contract(&args.contract.to_string_lossy());

    let wasm_bytes = fs::read(&args.contract).map_err(|e| {
        DebuggerError::WasmLoadError(format!(
            "Failed to read WASM file at {:?}: {}",
            args.contract, e
        ))
    })?;

    print_success(format!(
        "Contract loaded successfully ({} bytes)",
        wasm_bytes.len()
    ));
    logging::log_contract_loaded(wasm_bytes.len());

    print_info(format!("Loading batch file: {:?}", batch_file));
    let batch_items = crate::batch::BatchExecutor::load_batch_file(batch_file)?;
    print_success(format!("Loaded {} test cases", batch_items.len()));

    if let Some(snapshot_path) = &args.network_snapshot {
        print_info(format!("\nLoading network snapshot: {:?}", snapshot_path));
        logging::log_loading_snapshot(&snapshot_path.to_string_lossy());
        let loader = SnapshotLoader::from_file(snapshot_path)?;
        let loaded_snapshot = loader.apply_to_environment()?;
        logging::log_display(loaded_snapshot.format_summary(), logging::LogLevel::Info);
    }

    print_info(format!(
        "\nExecuting {} test cases in parallel for function: {}",
        batch_items.len(),
        args.function
    ));
    logging::log_execution_start(&args.function, None);

    let executor = crate::batch::BatchExecutor::new(wasm_bytes, args.function.clone());
    let results = executor.execute_batch(batch_items)?;
    let summary = crate::batch::BatchExecutor::summarize(&results);

    crate::batch::BatchExecutor::display_results(&results, &summary);

    if args.json
        || args
            .format
            .as_deref()
            .map(|f| f.eq_ignore_ascii_case("json"))
            .unwrap_or(false)
    {
        let output = serde_json::json!({
            "results": results,
            "summary": summary,
        });
        println!(
            "\n{}",
            serde_json::to_string_pretty(&output).map_err(|e| DebuggerError::FileError(
                format!("Failed to serialize output: {}", e)
            ))?
        );
    }

    logging::log_execution_complete(&format!("{}/{} passed", summary.passed, summary.total));

    if summary.failed > 0 || summary.errors > 0 {
        return Err(DebuggerError::ExecutionError(format!(
            "Batch execution completed with failures: {} failed, {} errors",
            summary.failed, summary.errors
        ))
        .into());
    }

    Ok(())
}

/// Execute the run command.
pub fn run(args: RunArgs, verbosity: Verbosity) -> Result<()> {
    // Handle batch execution mode
    if let Some(batch_file) = &args.batch_args {
        return run_batch(&args, batch_file);
    }

    if args.dry_run {
        return run_dry_run(&args);
    }

    print_info(format!("Loading contract: {:?}", args.contract));
    logging::log_loading_contract(&args.contract.to_string_lossy());

    let wasm_file = crate::utils::wasm::load_wasm(&args.contract)
        .with_context(|| format!("Failed to read WASM file: {:?}", args.contract))?;
    let wasm_bytes = wasm_file.bytes;
    let wasm_hash = wasm_file.sha256_hash;

    if let Some(expected) = &args.expected_hash {
        if expected.to_lowercase() != wasm_hash {
            return Err(crate::DebuggerError::ChecksumMismatch {
                expected: expected.clone(),
                actual: wasm_hash.clone(),
            }
            .into());
        }
    }

    print_success(format!(
        "Contract loaded successfully ({} bytes)",
        wasm_bytes.len()
    ));

    if args.verbose || verbosity == Verbosity::Verbose {
        print_info(format!("SHA-256: {}", wasm_hash));
        if args.expected_hash.is_some() {
            print_success("Checksum verified âœ“");
        }
    }

    logging::log_contract_loaded(wasm_bytes.len());

    if let Some(snapshot_path) = &args.network_snapshot {
        print_info(format!("\nLoading network snapshot: {:?}", snapshot_path));
        logging::log_loading_snapshot(&snapshot_path.to_string_lossy());
        let loader = SnapshotLoader::from_file(snapshot_path)?;
        let loaded_snapshot = loader.apply_to_environment()?;
        logging::log_display(loaded_snapshot.format_summary(), logging::LogLevel::Info);
    }

    let parsed_args = if let Some(args_json) = &args.args {
        Some(parse_args(args_json)?)
    } else {
        None
    };

    let mut initial_storage = if let Some(storage_json) = &args.storage {
        Some(parse_storage(storage_json)?)
    } else {
        None
    };

    // Import storage if specified
    if let Some(import_path) = &args.import_storage {
        print_info(format!("Importing storage from: {:?}", import_path));
        let imported = crate::inspector::storage::StorageState::import_from_file(import_path)?;
        print_success(format!("Imported {} storage entries", imported.len()));
        initial_storage = Some(serde_json::to_string(&imported).map_err(|e| {
            DebuggerError::StorageError(format!("Failed to serialize imported storage: {}", e))
        })?);
    }

    if let Some(n) = args.repeat {
        logging::log_repeat_execution(&args.function, n as usize);
        let runner = RepeatRunner::new(wasm_bytes, args.breakpoint, initial_storage);
        let stats = runner.run(&args.function, parsed_args.as_deref(), n)?;
        stats.display();
        return Ok(());
    }

    print_info("\nStarting debugger...");
    print_info(format!("Function: {}", args.function));
    if let Some(ref parsed) = parsed_args {
        print_info(format!("Arguments: {}", parsed));
    }
    logging::log_execution_start(&args.function, parsed_args.as_deref());

    let mut executor = ContractExecutor::new(wasm_bytes.clone())?;
    executor.set_timeout(args.timeout);

    if let Some(storage) = initial_storage {
        executor.set_initial_storage(storage)?;
    }
    if !args.mock.is_empty() {
        executor.set_mock_specs(&args.mock)?;
    }

    let mut engine = DebuggerEngine::new(executor, args.breakpoint);

    if args.instruction_debug {
        print_info("Enabling instruction-level debugging...");
        engine.enable_instruction_debug(&wasm_bytes)?;

        if args.step_instructions {
            let step_mode = parse_step_mode(&args.step_mode);
            print_info(format!(
                "Starting instruction stepping in '{}' mode",
                args.step_mode
            ));
            engine.start_instruction_stepping(step_mode)?;
            run_instruction_stepping(&mut engine, &args.function, parsed_args.as_deref())?;
            return Ok(());
        }
    }

    print_info("\n--- Execution Start ---\n");
    let storage_before = engine.executor().get_storage_snapshot()?;
    let result = engine.execute(&args.function, parsed_args.as_deref())?;
    let storage_after = engine.executor().get_storage_snapshot()?;
    print_success("\n--- Execution Complete ---\n");
    print_success(format!("Result: {:?}", result));
    logging::log_execution_complete(&result);

    // Generate test if requested
    if let Some(test_path) = &args.generate_test {
        if let Some(record) = engine.executor().last_execution() {
            print_info(format!("\nGenerating unit test: {:?}", test_path));
            let test_code = crate::codegen::TestGenerator::generate(record, &args.contract)?;
            crate::codegen::TestGenerator::write_to_file(test_path, &test_code, args.overwrite)?;
            print_success(format!(
                "Unit test generated successfully at {:?}",
                test_path
            ));
        } else {
            print_warning("No execution record found to generate test.");
        }
    }

    let storage_diff = crate::inspector::storage::StorageInspector::compute_diff(
        &storage_before,
        &storage_after,
        &args.alert_on_change,
    );
    if !storage_diff.is_empty() || !args.alert_on_change.is_empty() {
        print_info("\n--- Storage Changes ---");
        crate::inspector::storage::StorageInspector::display_diff(&storage_diff);
    }

    if let Some(export_path) = &args.export_storage {
        print_info(format!("\nExporting storage to: {:?}", export_path));
        crate::inspector::storage::StorageState::export_to_file(&storage_after, export_path)?;
    }
    let mock_calls = engine.executor().get_mock_call_log();
    if !args.mock.is_empty() {
        display_mock_call_log(&mock_calls);
    }

    // Save budget info to history
    let host = engine.executor().host();
    let budget = crate::inspector::budget::BudgetInspector::get_cpu_usage(host);
    if let Ok(manager) = HistoryManager::new() {
        let record = RunHistory {
            date: chrono::Utc::now().to_rfc3339(),
            contract_hash: args.contract.to_string_lossy().to_string(),
            function: args.function.clone(),
            cpu_used: budget.cpu_instructions,
            memory_used: budget.memory_bytes,
        };
        let _ = manager.append_record(record);
    }

    // Export storage if specified
    if let Some(export_path) = &args.export_storage {
        print_info(format!("Exporting storage to: {:?}", export_path));
        let storage_snapshot = engine.executor().get_storage_snapshot()?;
        crate::inspector::storage::StorageState::export_to_file(&storage_snapshot, export_path)?;
        print_success(format!(
            "Exported {} storage entries",
            storage_snapshot.len()
        ));
    }

    let mut json_events = None;
    if args.show_events {
        print_info("\n--- Events ---");
        let events = engine.executor().get_events()?;
        let filtered_events = if let Some(topic) = &args.filter_topic {
            crate::inspector::events::EventInspector::filter_events(&events, topic)
        } else {
            events
        };

        if filtered_events.is_empty() {
            print_warning("No events captured.");
        } else {
            for (i, event) in filtered_events.iter().enumerate() {
                print_info(format!("Event #{}:", i));
                if let Some(contract_id) = &event.contract_id {
                    logging::log_event_emitted(contract_id, event.topics.len());
                }
                print_info(format!(
                    "  Contract: {}",
                    event.contract_id.as_deref().unwrap_or("<none>")
                ));
                print_info(format!("  Topics: {:?}", event.topics));
                print_info(format!("  Data: {}", event.data));
            }
        }

        json_events = Some(filtered_events);
    }

    if !args.storage_filter.is_empty() {
        let storage_filter = crate::inspector::storage::StorageFilter::new(&args.storage_filter)
            .map_err(|e| DebuggerError::StorageError(format!("Invalid storage filter: {}", e)))?;

        print_info("\n--- Storage ---");
        let inspector = crate::inspector::StorageInspector::new();
        inspector.display_filtered(&storage_filter);
        print_info("(Storage view is currently placeholder data)");
    }

    let mut json_auth = None;
    if args.show_auth {
        let auth_tree = engine.executor().get_auth_tree()?;
        if args.json {
            let json_output = crate::inspector::auth::AuthInspector::to_json(&auth_tree)?;
            println!("{}", json_output);
        } else {
            println!("\n--- Authorizations ---");
            crate::inspector::auth::AuthInspector::display(&auth_tree);
        }
        json_auth = Some(auth_tree);
    }

    let mut json_ledger = None;
    if args.show_ledger {
        print_info("\n--- Ledger Entries ---");
        let mut ledger_inspector = crate::inspector::ledger::LedgerEntryInspector::new();
        ledger_inspector.set_ttl_warning_threshold(args.ttl_warning_threshold);

        // Extract ledger entries from storage snapshots
        // Instance entries (from the after-snapshot, representing accessed state)
        for (key, value) in &storage_after {
            let storage_type = if key.starts_with("instance:") || key.starts_with("Instance") {
                crate::inspector::ledger::StorageType::Instance
            } else if key.starts_with("temp:") || key.starts_with("Temporary") {
                crate::inspector::ledger::StorageType::Temporary
            } else {
                crate::inspector::ledger::StorageType::Persistent
            };

            let was_read = storage_before.contains_key(key);
            let was_written = storage_after.get(key) != storage_before.get(key);

            // Simulated TTL based on storage type defaults
            let ttl = match storage_type {
                crate::inspector::ledger::StorageType::Instance => 999_999,
                crate::inspector::ledger::StorageType::Persistent => 120_960,
                crate::inspector::ledger::StorageType::Temporary => 17_280,
            };

            ledger_inspector.add_entry(
                key.clone(),
                value.clone(),
                storage_type,
                ttl,
                was_read || !was_written,
                was_written,
            );
        }

        ledger_inspector.display();
        ledger_inspector.display_warnings();
        json_ledger = Some(ledger_inspector);
    }

    if args.json
        || args
            .format
            .as_deref()
            .map(|f| f.eq_ignore_ascii_case("json"))
            .unwrap_or(false)
    {
        let mut output = serde_json::json!({
            "result": result,
            "sha256": wasm_hash,
            "alerts": storage_diff.triggered_alerts,
        });

        if let Some(events) = json_events {
            output["events"] = serde_json::Value::Array(
                events
                    .into_iter()
                    .map(|event| {
                        serde_json::json!({
                            "contract_id": event.contract_id,
                            "topics": event.topics,
                            "data": event.data,
                        })
                    })
                    .collect(),
            );
        }
        if let Some(auth_tree) = json_auth {
            output["auth"] = serde_json::to_value(auth_tree).unwrap_or(serde_json::Value::Null);
        }
        if !mock_calls.is_empty() {
            output["mock_calls"] = serde_json::Value::Array(
                mock_calls
                    .iter()
                    .map(|entry| {
                        serde_json::json!({
                            "contract_id": entry.contract_id,
                            "function": entry.function,
                            "args_count": entry.args_count,
                            "mocked": entry.mocked,
                            "returned": entry.returned,
                        })
                    })
                    .collect(),
            );
        }
        if let Some(ref ledger) = json_ledger {
            output["ledger_entries"] = ledger.to_json();
        }

        println!(
            "{}",
            serde_json::to_string_pretty(&output).map_err(|e| DebuggerError::FileError(
                format!("Failed to serialize output: {}", e)
            ))?
        );
    }

    Ok(())
}

/// Execute run command in dry-run mode.
fn run_dry_run(args: &RunArgs) -> Result<()> {
    print_info(format!("[DRY RUN] Loading contract: {:?}", args.contract));

    let wasm_file = crate::utils::wasm::load_wasm(&args.contract)
        .with_context(|| format!("Failed to read WASM file: {:?}", args.contract))?;
    let wasm_bytes = wasm_file.bytes;
    let wasm_hash = wasm_file.sha256_hash;

    if let Some(expected) = &args.expected_hash {
        if expected.to_lowercase() != wasm_hash {
            return Err(crate::DebuggerError::ChecksumMismatch {
                expected: expected.clone(),
                actual: wasm_hash.clone(),
            }
            .into());
        }
    }

    print_success(format!(
        "[DRY RUN] Contract loaded successfully ({} bytes)",
        wasm_bytes.len()
    ));

    if args.verbose {
        print_info(format!("[DRY RUN] SHA-256: {}", wasm_hash));
        if args.expected_hash.is_some() {
            print_success("[DRY RUN] Checksum verified âœ“");
        }
    }

    if let Some(snapshot_path) = &args.network_snapshot {
        print_info(format!(
            "\n[DRY RUN] Loading network snapshot: {:?}",
            snapshot_path
        ));
        let loader = SnapshotLoader::from_file(snapshot_path)?;
        let loaded_snapshot = loader.apply_to_environment()?;
        print_info(format!("[DRY RUN] {}", loaded_snapshot.format_summary()));
    }

    let parsed_args = if let Some(args_json) = &args.args {
        Some(parse_args(args_json)?)
    } else {
        None
    };

    let initial_storage = if let Some(storage_json) = &args.storage {
        Some(parse_storage(storage_json)?)
    } else {
        None
    };

    let mut executor = ContractExecutor::new(wasm_bytes)?;
    if let Some(storage) = initial_storage {
        executor.set_initial_storage(storage)?;
    }
    if !args.mock.is_empty() {
        executor.set_mock_specs(&args.mock)?;
    }

    let storage_snapshot = executor.snapshot_storage()?;

    let mut engine = DebuggerEngine::new(executor, args.breakpoint.clone());

    print_info("\n[DRY RUN] --- Execution Start ---\n");
    let result = engine.execute(&args.function, parsed_args.as_deref())?;
    print_success("\n[DRY RUN] --- Execution Complete ---\n");
    print_success(format!("[DRY RUN] Result: {:?}", result));
    if !args.mock.is_empty() {
        display_mock_call_log(&engine.executor().get_mock_call_log());
    }

    if args.show_events {
        print_info("\n[DRY RUN] --- Events ---");
        let events = engine.executor().get_events()?;
        let filtered_events = if let Some(topic) = &args.filter_topic {
            crate::inspector::events::EventInspector::filter_events(&events, topic)
        } else {
            events
        };

        if filtered_events.is_empty() {
            print_warning("[DRY RUN] No events captured.");
        } else {
            for (i, event) in filtered_events.iter().enumerate() {
                print_info(format!("[DRY RUN] Event #{}:", i));
                print_info(format!(
                    "[DRY RUN]   Contract: {}",
                    event.contract_id.as_deref().unwrap_or("<none>")
                ));
                print_info(format!("[DRY RUN]   Topics: {:?}", event.topics));
                print_info(format!("[DRY RUN]   Data: {}", event.data));
            }
        }
    }

    engine.executor_mut().restore_storage(&storage_snapshot)?;
    print_success("\n[DRY RUN] Storage state restored (changes rolled back)");

    Ok(())
}

/// Execute the interactive command.
pub fn interactive(args: InteractiveArgs, _verbosity: Verbosity) -> Result<()> {
    print_info(format!(
        "Starting interactive debugger for: {:?}",
        args.contract
    ));
    logging::log_loading_contract(&args.contract.to_string_lossy());

    let wasm_file = crate::utils::wasm::load_wasm(&args.contract)
        .with_context(|| format!("Failed to read WASM file: {:?}", args.contract))?;
    let wasm_bytes = wasm_file.bytes;
    let wasm_hash = wasm_file.sha256_hash;

    if let Some(expected) = &args.expected_hash {
        if expected.to_lowercase() != wasm_hash {
            return Err(crate::DebuggerError::ChecksumMismatch {
                expected: expected.clone(),
                actual: wasm_hash.clone(),
            }
            .into());
        }
    }

    print_success(format!(
        "Contract loaded successfully ({} bytes)",
        wasm_bytes.len()
    ));

    if _verbosity == Verbosity::Verbose {
        print_info(format!("SHA-256: {}", wasm_hash));
        if args.expected_hash.is_some() {
            print_success("Checksum verified âœ“");
        }
    }

    logging::log_contract_loaded(wasm_bytes.len());

    if let Some(snapshot_path) = &args.network_snapshot {
        print_info(format!("\nLoading network snapshot: {:?}", snapshot_path));
        logging::log_loading_snapshot(&snapshot_path.to_string_lossy());
        let loader = SnapshotLoader::from_file(snapshot_path)?;
        let loaded_snapshot = loader.apply_to_environment()?;
        logging::log_display(loaded_snapshot.format_summary(), logging::LogLevel::Info);
    }

    let executor = ContractExecutor::new(wasm_bytes)?;
    let engine = DebuggerEngine::new(executor, vec![]);

    print_info("\nStarting interactive mode...");
    print_info("Type 'help' for available commands\n");
    logging::log_interactive_mode_start();

    let mut ui = DebuggerUI::new(engine)?;
    ui.run()?;

    Ok(())
}

/// Launch the full-screen TUI dashboard.
pub fn tui(args: TuiArgs, _verbosity: Verbosity) -> Result<()> {
    let wasm_bytes = fs::read(&args.contract).map_err(|e| {
        DebuggerError::WasmLoadError(format!(
            "Failed to read WASM file: {:?}. Error: {}",
            args.contract, e
        ))
    })?;

    if let Some(snapshot_path) = &args.network_snapshot {
        let loader = SnapshotLoader::from_file(snapshot_path)?;
        loader.apply_to_environment()?;
    }

    let parsed_args = if let Some(ref a) = args.args {
        Some(parse_args(a)?)
    } else {
        None
    };

    let initial_storage = if let Some(ref s) = args.storage {
        Some(parse_storage(s)?)
    } else {
        None
    };

    let mut executor = ContractExecutor::new(wasm_bytes)?;
    if let Some(storage) = initial_storage {
        executor.set_initial_storage(storage)?;
    }

    let mut engine = DebuggerEngine::new(executor, args.breakpoint);

    // Pre-execute so live data is available immediately in the dashboard
    let _ = engine.execute(&args.function, parsed_args.as_deref());

    crate::ui::run_dashboard(engine, &args.function)?;

    Ok(())
}

/// Execute the inspect command.
pub fn inspect(args: InspectArgs, _verbosity: Verbosity) -> Result<()> {
    print_info(format!("Inspecting contract: {:?}", args.contract));
    logging::log_loading_contract(&args.contract.to_string_lossy());

    let wasm_file = crate::utils::wasm::load_wasm(&args.contract)
        .with_context(|| format!("Failed to read WASM file: {:?}", args.contract))?;
    let wasm_bytes = wasm_file.bytes;
    let wasm_hash = wasm_file.sha256_hash;

    if let Some(expected) = &args.expected_hash {
        if expected.to_lowercase() != wasm_hash {
            return Err(crate::DebuggerError::ChecksumMismatch {
                expected: expected.clone(),
                actual: wasm_hash.clone(),
            }
            .into());
        }
    }

    if _verbosity == Verbosity::Verbose {
        print_info(format!("SHA-256: {}", wasm_hash));
        if args.expected_hash.is_some() {
            print_success("Checksum verified âœ“");
        }
    }

    let module_info = crate::utils::wasm::get_module_info(&wasm_bytes)?;

    println!("\n{}", "=".repeat(54));
    println!("  Soroban Contract Inspector");
    println!("{}", "=".repeat(54));
    println!("\n  File : {:?}", args.contract);
    println!("  Size : {} bytes", wasm_bytes.len());

    println!("\n{}", "-".repeat(54));
    println!("  Module Information");
    println!("{}", "-".repeat(54));
    println!("  Types      : {}", module_info.type_count);
    println!("  Functions  : {}", module_info.function_count);
    println!("  Exports    : {}", module_info.export_count);

    if args.functions {
        println!("\n{}", "-".repeat(54));
        println!("  Exported Functions");
        println!("{}", "-".repeat(54));

        let functions = crate::utils::wasm::parse_functions(&wasm_bytes)?;
        if functions.is_empty() {
            println!("  (No exported functions found)");
        } else {
            for function in functions {
                println!("  {} {}", OutputConfig::to_ascii("â€¢"), function);
            }
        }
    }

    if args.dependency_graph {
        println!("\n{}", OutputConfig::rule_line(54));
        println!("  Contract Dependency Graph");
        println!("  {}", OutputConfig::rule_line(52));

        let calls = crate::utils::wasm::parse_cross_contract_calls(&wasm_bytes)?;
        if calls.is_empty() {
            println!("  (No cross-contract call instructions detected)");
        } else {
            let contract_name = args
                .contract
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("contract")
                .to_string();

            let mut graph = crate::analyzer::graph::DependencyGraph::new();
            graph.add_node(contract_name.clone());
            for call in calls {
                graph.add_edge(contract_name.clone(), call.target);
            }

            println!("\nDOT:");
            println!("{}", graph.to_dot());
            println!("\nMermaid:");
            println!("{}", graph.to_mermaid());
        }
    }

    if args.metadata {
        println!("\n{}", "-".repeat(54));
        println!("  Contract Metadata");
        println!("{}", "-".repeat(54));

        let metadata = crate::utils::wasm::extract_contract_metadata(&wasm_bytes)?;
        if metadata.is_empty() {
            println!("  (No embedded metadata found)");
        } else {
            if let Some(version) = metadata.contract_version {
                println!("  Contract version      : {}", version);
            }
            if let Some(sdk) = metadata.sdk_version {
                println!("  Soroban SDK version   : {}", sdk);
            }
            if let Some(build_date) = metadata.build_date {
                println!("  Build date            : {}", build_date);
            }
            if let Some(author) = metadata.author {
                println!("  Author / organization : {}", author);
            }
            if let Some(desc) = metadata.description {
                println!("  Description           : {}", desc);
            }
            if let Some(impl_notes) = metadata.implementation {
                println!("  Implementation notes  : {}", impl_notes);
            }
        }
    }

    println!("\n{}", "=".repeat(54));
    Ok(())
}

/// Execute the analyze command.
pub fn analyze(args: AnalyzeArgs, _verbosity: Verbosity) -> Result<()> {
    print_info(format!("Analyzing contract: {:?}", args.contract));
    logging::log_loading_contract(&args.contract.to_string_lossy());

    let wasm_file = crate::utils::wasm::load_wasm(&args.contract)
        .with_context(|| format!("Failed to read WASM file: {:?}", args.contract))?;
    let wasm_bytes = wasm_file.bytes;

    print_success(format!(
        "Contract loaded successfully ({} bytes)",
        wasm_bytes.len()
    ));

    let mut executor = None;
    let mut trace = None;

    if let Some(function) = &args.function {
        print_info(format!(
            "\nRunning dynamic analysis for function: {}",
            function
        ));
        let mut exec = ContractExecutor::new(wasm_bytes.clone())?;
        if let Some(storage_json) = &args.storage {
            let storage = parse_storage(storage_json)?;
            exec.set_initial_storage(storage)?;
        }

        let parsed_args = if let Some(args_json) = &args.args {
            Some(parse_args(args_json)?)
        } else {
            None
        };

        // Execute function to generate trace
        let _ = exec.execute(function, parsed_args.as_deref());

        // Simple trace from diagnostic events
        let diag_events = exec.get_diagnostic_events()?;
        let tr: Vec<String> = diag_events.iter().map(|e| format!("{:?}", e)).collect();

        executor = Some(exec);
        trace = Some(tr);
    }

    let analyzer = crate::analyzer::security::SecurityAnalyzer::new();
    let report = analyzer.analyze(&wasm_bytes, executor.as_ref(), trace.as_deref())?;

    if args.format.eq_ignore_ascii_case("json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| DebuggerError::FileError(
                format!("Failed to serialize report: {}", e)
            ))?
        );
    } else {
        println!("\n{}", "=".repeat(54));
        println!("  Soroban Security Vulnerability Report");
        println!("{}", "=".repeat(54));

        if report.findings.is_empty() {
            println!("\n  âœ… No vulnerabilities detected.");
        } else {
            for finding in &report.findings {
                println!(
                    "\n  [{:?}] {} - {}",
                    finding.severity, finding.rule_id, finding.location
                );
                println!("  Description : {}", finding.description);
                println!("  Remediation : {}", finding.remediation);
            }
        }
        println!("\n{}", "=".repeat(54));
    }

    Ok(())
}

/// Parse JSON arguments with validation.
pub fn parse_args(json: &str) -> Result<String> {
    let value = serde_json::from_str::<serde_json::Value>(json).map_err(|e| {
        DebuggerError::InvalidArguments(format!(
            "Failed to parse JSON arguments: {}. Error: {}",
            json, e
        ))
    })?;

    match value {
        serde_json::Value::Array(ref arr) => {
            tracing::debug!(count = arr.len(), "Parsed array arguments");
        }
        serde_json::Value::Object(ref obj) => {
            tracing::debug!(fields = obj.len(), "Parsed object arguments");
        }
        _ => {
            tracing::debug!("Parsed single value argument");
        }
    }

    Ok(json.to_string())
}

/// Parse JSON storage.
pub fn parse_storage(json: &str) -> Result<String> {
    serde_json::from_str::<serde_json::Value>(json).map_err(|e| {
        DebuggerError::StorageError(format!(
            "Failed to parse JSON storage: {}. Error: {}",
            json, e
        ))
    })?;
    Ok(json.to_string())
}

/// Execute the optimize command.
pub fn optimize(args: OptimizeArgs, _verbosity: Verbosity) -> Result<()> {
    print_info(format!(
        "Analyzing contract for gas optimization: {:?}",
        args.contract
    ));
    logging::log_loading_contract(&args.contract.to_string_lossy());

    let wasm_file = crate::utils::wasm::load_wasm(&args.contract)
        .with_context(|| format!("Failed to read WASM file: {:?}", args.contract))?;
    let wasm_bytes = wasm_file.bytes;
    let wasm_hash = wasm_file.sha256_hash;

    if let Some(expected) = &args.expected_hash {
        if expected.to_lowercase() != wasm_hash {
            return Err(crate::DebuggerError::ChecksumMismatch {
                expected: expected.clone(),
                actual: wasm_hash.clone(),
            }
            .into());
        }
    }

    print_success(format!(
        "Contract loaded successfully ({} bytes)",
        wasm_bytes.len()
    ));

    if _verbosity == Verbosity::Verbose {
        print_info(format!("SHA-256: {}", wasm_hash));
        if args.expected_hash.is_some() {
            print_success("Checksum verified âœ“");
        }
    }

    logging::log_contract_loaded(wasm_bytes.len());

    if let Some(snapshot_path) = &args.network_snapshot {
        print_info(format!("\nLoading network snapshot: {:?}", snapshot_path));
        logging::log_loading_snapshot(&snapshot_path.to_string_lossy());
        let loader = SnapshotLoader::from_file(snapshot_path)?;
        let loaded_snapshot = loader.apply_to_environment()?;
        logging::log_display(loaded_snapshot.format_summary(), logging::LogLevel::Info);
    }

    let functions_to_analyze = if args.function.is_empty() {
        print_warning("No functions specified, analyzing all exported functions...");
        crate::utils::wasm::parse_functions(&wasm_bytes)?
    } else {
        args.function.clone()
    };

    let mut executor = ContractExecutor::new(wasm_bytes)?;
    if let Some(storage_json) = &args.storage {
        let storage = parse_storage(storage_json)?;
        executor.set_initial_storage(storage)?;
    }

    let mut optimizer = crate::profiler::analyzer::GasOptimizer::new(executor);

    print_info(format!(
        "\nAnalyzing {} function(s)...",
        functions_to_analyze.len()
    ));
    logging::log_analysis_start("gas optimization");

    for function_name in &functions_to_analyze {
        print_info(format!("  Analyzing function: {}", function_name));
        match optimizer.analyze_function(function_name, args.args.as_deref()) {
            Ok(profile) => {
                println!(
                    "    CPU: {} instructions, Memory: {} bytes, Time: {} ms",
                    profile.total_cpu, profile.total_memory, profile.wall_time_ms
                );
                print_success(format!(
                    "    CPU: {} instructions, Memory: {} bytes",
                    profile.total_cpu, profile.total_memory
                ));
            }
            Err(e) => {
                print_warning(format!(
                    "    Warning: Failed to analyze function {}: {}",
                    function_name, e
                ));
                tracing::warn!(function = function_name, error = %e, "Failed to analyze function");
            }
        }
    }
    logging::log_analysis_complete("gas optimization", functions_to_analyze.len());

    let contract_path_str = args.contract.to_string_lossy().to_string();
    let report = optimizer.generate_report(&contract_path_str);
    let markdown = optimizer.generate_markdown_report(&report);

    if let Some(output_path) = &args.output {
        fs::write(output_path, &markdown).map_err(|e| {
            DebuggerError::FileError(format!(
                "Failed to write report to {:?}: {}",
                output_path, e
            ))
        })?;
        print_success(format!(
            "\nOptimization report written to: {:?}",
            output_path
        ));
        logging::log_optimization_report(&output_path.to_string_lossy());
    } else {
        logging::log_display(&markdown, logging::LogLevel::Info);
    }

    Ok(())
}

/// âœ… Execute the profile command (hotspots + suggestions)
pub fn profile(args: ProfileArgs) -> Result<()> {
    println!("Profiling contract execution: {:?}", args.contract);

    let wasm_file = crate::utils::wasm::load_wasm(&args.contract)
        .with_context(|| format!("Failed to read WASM file: {:?}", args.contract))?;
    let wasm_bytes = wasm_file.bytes;
    let wasm_hash = wasm_file.sha256_hash;

    if let Some(expected) = &args.expected_hash {
        if expected.to_lowercase() != wasm_hash {
            return Err(crate::DebuggerError::ChecksumMismatch {
                expected: expected.clone(),
                actual: wasm_hash.clone(),
            }
            .into());
        }
    }

    println!("Contract loaded successfully ({} bytes)", wasm_bytes.len());

    // Parse args (optional)
    let parsed_args = if let Some(args_json) = &args.args {
        Some(parse_args(args_json)?)
    } else {
        None
    };

    // Create executor
    let mut executor = ContractExecutor::new(wasm_bytes)?;

    // Initial storage (optional)
    if let Some(storage_json) = &args.storage {
        let storage = parse_storage(storage_json)?;
        executor.set_initial_storage(storage)?;
    }

    // Analyze exactly one function (this command focuses on execution hotspots)
    let mut optimizer = crate::profiler::analyzer::GasOptimizer::new(executor);

    println!("\nRunning function: {}", args.function);
    if let Some(ref a) = parsed_args {
        println!("Args: {}", a);
    }

    let _profile = optimizer.analyze_function(&args.function, parsed_args.as_deref())?;

    let contract_path_str = args.contract.to_string_lossy().to_string();
    let report = optimizer.generate_report(&contract_path_str);

    // Hotspot summary first
    println!("\n{}", report.format_hotspots());

    // Then detailed suggestions (markdown format)
    let markdown = optimizer.generate_markdown_report(&report);

    if let Some(output_path) = &args.output {
        fs::write(output_path, &markdown).map_err(|e| {
            DebuggerError::FileError(format!(
                "Failed to write report to {:?}: {}",
                output_path, e
            ))
        })?;
        println!("\nProfile report written to: {:?}", output_path);
    } else {
        println!("\n{}", markdown);
    }

    Ok(())
}

/// Execute the upgrade-check command.
/// Execute the upgrade-check command
pub fn upgrade_check(args: UpgradeCheckArgs, _verbosity: Verbosity) -> Result<()> {
    print_info("Comparing contracts...");
    print_info(format!("  Old: {:?}", args.old));
    print_info(format!("  New: {:?}", args.new));
    logging::log_contract_comparison(&args.old.to_string_lossy(), &args.new.to_string_lossy());

    let old_bytes = fs::read(&args.old).map_err(|e| {
        DebuggerError::WasmLoadError(format!(
            "Failed to read old WASM file at {:?}: {}",
            args.old, e
        ))
    })?;
    let new_bytes = fs::read(&args.new).map_err(|e| {
        DebuggerError::WasmLoadError(format!(
            "Failed to read new WASM file at {:?}: {}",
            args.new, e
        ))
    })?;

    print_success(format!(
        "Loaded contracts (Old: {} bytes, New: {} bytes)",
        old_bytes.len(),
        new_bytes.len()
    ));

    print_info("Running analysis...");
    tracing::info!(
        old_size = old_bytes.len(),
        new_size = new_bytes.len(),
        "Loaded contracts for comparison"
    );

    let analyzer = crate::analyzer::upgrade::UpgradeAnalyzer::new();
    logging::log_analysis_start("contract upgrade compatibility check");
    let report = analyzer.analyze(
        &old_bytes,
        &new_bytes,
        args.function.as_deref(),
        args.args.as_deref(),
    )?;

    let markdown = analyzer.generate_markdown_report(&report);

    if let Some(output_path) = &args.output {
        fs::write(output_path, &markdown).map_err(|e| {
            DebuggerError::FileError(format!(
                "Failed to write report to {:?}: {}",
                output_path, e
            ))
        })?;
        print_success(format!(
            "\nCompatibility report written to: {:?}",
            output_path
        ));
        logging::log_optimization_report(&output_path.to_string_lossy());
    } else {
        logging::log_display(&markdown, logging::LogLevel::Info);
    }

    Ok(())
}

/// Execute the compare command.
use crate::analyzer::symbolic::SymbolicConfig;
use crate::analyzer::upgrade::{CompatibilityReport, ExecutionDiff, UpgradeAnalyzer};
use crate::analyzer::{security::SecurityAnalyzer, symbolic::SymbolicAnalyzer};
use crate::cli::args::{
    AnalyzeArgs, CompareArgs, InspectArgs, InteractiveArgs, OptimizeArgs, ProfileArgs, RemoteArgs,
    ReplArgs, ReplayArgs, RunArgs, ScenarioArgs, ServerArgs, SymbolicArgs, SymbolicProfile,
    TuiArgs, UpgradeCheckArgs, Verbosity,
};
use crate::debugger::engine::DebuggerEngine;
use crate::debugger::instruction_pointer::StepMode;
use crate::history::{HistoryManager, RunHistory};
use crate::inspector::events::{ContractEvent, EventInspector};
use crate::logging;
use crate::output::OutputWriter;
use crate::repeat::RepeatRunner;
use crate::repl::ReplConfig;
use crate::runtime::executor::ContractExecutor;
use crate::simulator::SnapshotLoader;
use crate::ui::formatter::Formatter;
use crate::ui::{run_dashboard, DebuggerUI};
use crate::{DebuggerError, Result};
use miette::WrapErr;
use std::fs;

fn print_info(message: impl AsRef<str>) {
    if !Formatter::is_quiet() {
        println!("{}", Formatter::info(message));
    }
}

fn print_success(message: impl AsRef<str>) {
    if !Formatter::is_quiet() {
        println!("{}", Formatter::success(message));
    }
}

fn print_warning(message: impl AsRef<str>) {
    if !Formatter::is_quiet() {
        println!("{}", Formatter::warning(message));
    }
}

/// Print the final contract return value â€” always shown regardless of verbosity.
fn print_result(message: impl AsRef<str>) {
    if !Formatter::is_quiet() {
        println!("{}", Formatter::success(message));
    }
}

/// Print verbose-only detail â€” only shown when --verbose is active.
fn print_verbose(message: impl AsRef<str>) {
    if Formatter::is_verbose() {
        println!("{}", Formatter::info(message));
    }
}

fn budget_trend_stats_or_err(records: &[RunHistory]) -> Result<crate::history::BudgetTrendStats> {
    crate::history::budget_trend_stats(records).ok_or_else(|| {
        DebuggerError::ExecutionError(
            "Failed to compute budget trend statistics for the selected dataset".to_string(),
        )
        .into()
    })
}

#[derive(serde::Serialize)]
struct DynamicAnalysisMetadata {
    function: String,
    args: Option<String>,
    result: Option<String>,
    trace_entries: usize,
}

#[derive(serde::Serialize)]
struct AnalyzeCommandOutput {
    findings: Vec<crate::analyzer::security::SecurityFinding>,
    dynamic_analysis: Option<DynamicAnalysisMetadata>,
    warnings: Vec<String>,
}

fn render_symbolic_report(report: &crate::analyzer::symbolic::SymbolicReport) -> String {
    let mut lines = vec![
        format!("Function: {}", report.function),
        format!("Paths explored: {}", report.paths_explored),
        format!("Panics found: {}", report.panics_found),
        format!(
            "Budget: path_cap={}, input_combination_cap={}, timeout={}s",
            report.metadata.config.max_paths,
            report.metadata.config.max_input_combinations,
            report.metadata.config.timeout_secs
        ),
        format!(
            "Input combinations: generated={}, attempted={}, distinct_paths={}",
            report.metadata.generated_input_combinations,
            report.metadata.attempted_input_combinations,
            report.metadata.distinct_paths_recorded
        ),
    ];

    if report.metadata.truncation_reasons.is_empty() {
        lines.push("Truncation: none".to_string());
    } else {
        lines.push(format!(
            "Truncation: {}",
            report.metadata.truncation_reasons.join("; ")
        ));
    }

    if report.paths.is_empty() {
        lines.push("No distinct execution paths were discovered.".to_string());
        return lines.join("\n");
    }

    lines.push(String::new());
    lines.push("Distinct paths:".to_string());

    for (idx, path) in report.paths.iter().enumerate() {
        let outcome = match (&path.return_value, &path.panic) {
            (Some(value), _) => format!("return {}", value),
            (_, Some(panic)) => format!("panic {}", panic),
            _ => "unknown".to_string(),
        };
        lines.push(format!(
            "  {}. inputs={} -> {}",
            idx + 1,
            path.inputs,
            outcome
        ));
    }

    lines.join("\n")
}

fn symbolic_profile_config(profile: SymbolicProfile) -> SymbolicConfig {
    match profile {
        SymbolicProfile::Fast => SymbolicConfig::fast(),
        SymbolicProfile::Balanced => SymbolicConfig::balanced(),
        SymbolicProfile::Deep => SymbolicConfig::deep(),
    }
}

fn symbolic_config_from_args(args: &SymbolicArgs) -> SymbolicConfig {
    let mut config = symbolic_profile_config(args.profile);
    if let Some(path_cap) = args.path_cap {
        config.max_paths = path_cap;
    }
    if let Some(input_cap) = args.input_combination_cap {
        config.max_input_combinations = input_cap;
    }
    if let Some(timeout) = args.timeout {
        config.timeout_secs = timeout;
    }
    config
}

fn render_security_report(output: &AnalyzeCommandOutput) -> String {
    let mut lines = Vec::new();

    if let Some(dynamic) = &output.dynamic_analysis {
        lines.push(format!("Dynamic analysis function: {}", dynamic.function));
        if let Some(args) = &dynamic.args {
            lines.push(format!("Dynamic analysis args: {}", args));
        }
        if let Some(result) = &dynamic.result {
            lines.push(format!("Dynamic execution result: {}", result));
        }
        lines.push(format!(
            "Dynamic trace entries captured: {}",
            dynamic.trace_entries
        ));
        lines.push(String::new());
    }

    if !output.warnings.is_empty() {
        lines.push("Warnings:".to_string());
        for warning in &output.warnings {
            lines.push(format!("  - {}", warning));
        }
        lines.push(String::new());
    }

    if output.findings.is_empty() {
        lines.push("No security findings detected.".to_string());
        return lines.join("\n");
    }

    lines.push(format!("Findings: {}", output.findings.len()));
    for (idx, finding) in output.findings.iter().enumerate() {
        lines.push(format!(
            "  {}. [{:?}] {} at {}",
            idx + 1,
            finding.severity,
            finding.rule_id,
            finding.location
        ));
        lines.push(format!("     {}", finding.description));
        if let Some(confidence) = finding.confidence {
            lines.push(format!("     Confidence: {:.0}%", confidence * 100.0));
        }
        if let Some(rationale) = &finding.rationale {
            lines.push(format!("     Rationale: {}", rationale));
        }
        lines.push(format!("     Remediation: {}", finding.remediation));
    }

    lines.join("\n")
}

/// Run instruction-level stepping mode.
fn run_instruction_stepping(
    engine: &mut DebuggerEngine,
    function: &str,
    args: Option<&str>,
) -> Result<()> {
    logging::log_display(
        "\n=== Instruction Stepping Mode ===",
        logging::LogLevel::Info,
    );
    logging::log_display(
        "Type 'help' for available commands\n",
        logging::LogLevel::Info,
    );

    display_instruction_context(engine, 3);

    loop {
        print!("(step) > ");
        std::io::Write::flush(&mut std::io::stdout())
            .map_err(|e| DebuggerError::FileError(format!("Failed to flush stdout: {}", e)))?;

        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| DebuggerError::FileError(format!("Failed to read line: {}", e)))?;

        let input = input.trim().to_lowercase();
        let cmd = input.as_str();

        let result = match cmd {
            "n" | "next" | "s" | "step" | "into" | "" => engine.step_into(),
            "o" | "over" => engine.step_over(),
            "u" | "out" => engine.step_out(),
            "b" | "block" => engine.step_block(),
            "p" | "prev" | "back" => engine.step_back(),
            "c" | "continue" => {
                logging::log_display("Continuing execution...", logging::LogLevel::Info);
                engine.continue_execution()?;
                let res = engine.execute_without_breakpoints(function, args)?;
                logging::log_display(
                    format!("Execution completed. Result: {:?}", res),
                    logging::LogLevel::Info,
                );
                break;
            }
            "i" | "info" => {
                display_instruction_info(engine);
                continue;
            }
            "ctx" | "context" => {
                display_instruction_context(engine, 5);
                continue;
            }
            "h" | "help" => {
                logging::log_display(Formatter::format_stepping_help(), logging::LogLevel::Info);
                continue;
            }
            "q" | "quit" | "exit" => {
                logging::log_display(
                    "Exiting instruction stepping mode...",
                    logging::LogLevel::Info,
                );
                break;
            }
            _ => {
                logging::log_display(
                    format!("Unknown command: {cmd}. Type 'help' for available commands."),
                    logging::LogLevel::Info,
                );
                continue;
            }
        };

        match result {
            Ok(true) => display_instruction_context(engine, 3),
            Ok(false) => {
                let msg = if matches!(cmd, "p" | "prev" | "back") {
                    "Cannot step back: no previous instruction"
                } else {
                    "Cannot step: execution finished or error occurred"
                };
                logging::log_display(msg, logging::LogLevel::Info);
            }
            Err(e) => {
                logging::log_display(format!("Error stepping: {}", e), logging::LogLevel::Info)
            }
        }
    }

    Ok(())
}

fn display_instruction_context(engine: &DebuggerEngine, context_size: usize) {
    let context = engine.get_instruction_context(context_size);
    let formatted = Formatter::format_instruction_context(&context, context_size);
    logging::log_display(formatted, logging::LogLevel::Info);
}

fn display_instruction_info(engine: &DebuggerEngine) {
    if let Ok(state) = engine.state().lock() {
        let ip = state.instruction_pointer();
        let step_mode = if ip.is_stepping() {
            Some(ip.step_mode())
        } else {
            None
        };

        logging::log_display(
            Formatter::format_instruction_pointer_state(
                ip.current_index(),
                ip.call_stack_depth(),
                step_mode,
                ip.is_stepping(),
            ),
            logging::LogLevel::Info,
        );
        logging::log_display(
            Formatter::format_instruction_stats(
                state.instructions().len(),
                ip.current_index(),
                state.step_count(),
            ),
            logging::LogLevel::Info,
        );

        if let Some(inst) = state.current_instruction() {
            logging::log_display(
                format!(
                    "Current Instruction: {} (Offset: 0x{:08x}, Local index: {}, Control flow: {})",
                    inst.name(),
                    inst.offset,
                    inst.local_index,
                    inst.is_control_flow()
                ),
                logging::LogLevel::Info,
            );
        }
    } else {
        logging::log_display("Cannot access debug state", logging::LogLevel::Info);
    }
}

/// Parse step mode from string
fn parse_step_mode(mode: &str) -> StepMode {
    match mode.to_lowercase().as_str() {
        "into" => StepMode::StepInto,
        "over" => StepMode::StepOver,
        "out" => StepMode::StepOut,
        "block" => StepMode::StepBlock,
        _ => StepMode::StepInto, // Default
    }
}

/// Display mock call log
fn display_mock_call_log(calls: &[crate::runtime::executor::MockCallEntry]) {
    if calls.is_empty() {
        return;
    }
    print_info("\n--- Mock Contract Calls ---");
    for (i, entry) in calls.iter().enumerate() {
        let status = if entry.mocked { "MOCKED" } else { "REAL" };
        print_info(format!(
            "{}. {} {} (args: {}) -> {}",
            i + 1,
            status,
            entry.function,
            entry.args_count,
            if entry.returned.is_some() {
                "returned"
            } else {
                "pending"
            }
        ));
    }
}

/// Execute batch mode with parallel execution
fn run_batch(args: &RunArgs, batch_file: &std::path::Path) -> Result<()> {
    let contract = args
        .contract
        .as_ref()
        .expect("contract is required for batch mode");
    let function = args
        .function
        .as_ref()
        .expect("function is required for batch mode");

    print_info(format!("Loading contract: {:?}", contract));
    logging::log_loading_contract(&contract.to_string_lossy());

    let wasm_bytes = fs::read(contract).map_err(|e| {
        DebuggerError::WasmLoadError(format!("Failed to read WASM file at {:?}: {}", contract, e))
    })?;

    print_success(format!(
        "Contract loaded successfully ({} bytes)",
        wasm_bytes.len()
    ));
    logging::log_contract_loaded(wasm_bytes.len());

    print_info(format!("Loading batch file: {:?}", batch_file));
    let batch_items = crate::batch::BatchExecutor::load_batch_file(batch_file)?;
    print_success(format!("Loaded {} test cases", batch_items.len()));

    if let Some(snapshot_path) = &args.network_snapshot {
        print_info(format!("\nLoading network snapshot: {:?}", snapshot_path));
        logging::log_loading_snapshot(&snapshot_path.to_string_lossy());
        let loader = SnapshotLoader::from_file(snapshot_path)?;
        let loaded_snapshot = loader.apply_to_environment()?;
        logging::log_display(loaded_snapshot.format_summary(), logging::LogLevel::Info);
    }

    print_info(format!(
        "\nExecuting {} test cases in parallel for function: {}",
        batch_items.len(),
        function
    ));
    logging::log_execution_start(function, None);

    let executor = crate::batch::BatchExecutor::new(wasm_bytes, function.clone())?;
    let results = executor.execute_batch(batch_items)?;
    let summary = crate::batch::BatchExecutor::summarize(&results);

    crate::batch::BatchExecutor::display_results(&results, &summary);

    if args.is_json_output() {
        let output = serde_json::json!({
            "results": results,
            "summary": summary,
        });
        logging::log_display(
            serde_json::to_string_pretty(&output).map_err(|e| {
                DebuggerError::FileError(format!("Failed to serialize output: {}", e))
            })?,
            logging::LogLevel::Info,
        );
    }

    logging::log_execution_complete(&format!("{}/{} passed", summary.passed, summary.total));

    if summary.failed > 0 || summary.errors > 0 {
        return Err(DebuggerError::ExecutionError(format!(
            "Batch execution completed with failures: {} failed, {} errors",
            summary.failed, summary.errors
        ))
        .into());
    }

    Ok(())
}

/// Execute the run command.
#[tracing::instrument(skip_all, fields(contract = ?args.contract, function = args.function))]
pub fn run(args: RunArgs, verbosity: Verbosity) -> Result<()> {
    // Start debug server if requested
    if args.server {
        return server(ServerArgs {
            port: args.port,
            token: args.token,
            tls_cert: args.tls_cert,
            tls_key: args.tls_key,
        });
    }

    // Initialize output writer
    let mut output_writer = OutputWriter::new(args.save_output.as_deref(), args.append)?;

    // Handle batch execution mode
    if let Some(batch_file) = &args.batch_args {
        return run_batch(&args, batch_file);
    }

    if args.dry_run {
        return run_dry_run(&args);
    }

    let contract = args
        .contract
        .as_ref()
        .expect("contract is required for run");
    let function = args
        .function
        .as_ref()
        .expect("function is required for run");

    print_info(format!("Loading contract: {:?}", contract));
    output_writer.write(&format!("Loading contract: {:?}", contract))?;
    logging::log_loading_contract(&contract.to_string_lossy());

    let wasm_file = crate::utils::wasm::load_wasm(contract)
        .with_context(|| format!("Failed to read WASM file: {:?}", contract))?;
    let wasm_bytes = wasm_file.bytes;
    let wasm_hash = wasm_file.sha256_hash;

    if let Some(expected) = &args.expected_hash {
        if expected.to_lowercase() != wasm_hash {
            return Err((crate::DebuggerError::ChecksumMismatch {
                expected: expected.clone(),
                actual: wasm_hash.clone(),
            })
            .into());
        }
    }

    print_success(format!(
        "Contract loaded successfully ({} bytes)",
        wasm_bytes.len()
    ));
    output_writer.write(&format!(
        "Contract loaded successfully ({} bytes)",
        wasm_bytes.len()
    ))?;

    if args.verbose || verbosity == Verbosity::Verbose {
        print_verbose(format!("SHA-256: {}", wasm_hash));
        output_writer.write(&format!("SHA-256: {}", wasm_hash))?;
        if args.expected_hash.is_some() {
            print_verbose("Checksum verified âœ“");
            output_writer.write("Checksum verified âœ“")?;
        }
    }

    logging::log_contract_loaded(wasm_bytes.len());

    if let Some(snapshot_path) = &args.network_snapshot {
        print_info(format!("\nLoading network snapshot: {:?}", snapshot_path));
        output_writer.write(&format!("Loading network snapshot: {:?}", snapshot_path))?;
        logging::log_loading_snapshot(&snapshot_path.to_string_lossy());
        let loader = SnapshotLoader::from_file(snapshot_path)?;
        let loaded_snapshot = loader.apply_to_environment()?;
        output_writer.write(&loaded_snapshot.format_summary())?;
        logging::log_display(loaded_snapshot.format_summary(), logging::LogLevel::Info);
    }

    let parsed_args = if let Some(args_json) = &args.args {
        Some(parse_args(args_json)?)
    } else {
        None
    };

    let mut initial_storage = if let Some(storage_json) = &args.storage {
        Some(parse_storage(storage_json)?)
    } else {
        None
    };

    // Import storage if specified
    if let Some(import_path) = &args.import_storage {
        print_info(format!("Importing storage from: {:?}", import_path));
        let imported = crate::inspector::storage::StorageState::import_from_file(import_path)?;
        print_success(format!("Imported {} storage entries", imported.len()));
        initial_storage = Some(serde_json::to_string(&imported).map_err(|e| {
            DebuggerError::StorageError(format!("Failed to serialize imported storage: {}", e))
        })?);
    }

    if let Some(n) = args.repeat {
        logging::log_repeat_execution(function, n as usize);
        let runner = RepeatRunner::new(wasm_bytes, args.breakpoint, initial_storage);
        let stats = runner.run(function, parsed_args.as_deref(), n)?;
        stats.display();
        return Ok(());
    }

    print_info("\nStarting debugger...");
    output_writer.write("Starting debugger...")?;
    print_info(format!("Function: {}", function));
    output_writer.write(&format!("Function: {}", function))?;
    if let Some(ref parsed) = parsed_args {
        print_info(format!("Arguments: {}", parsed));
        output_writer.write(&format!("Arguments: {}", parsed))?;
    }
    logging::log_execution_start(function, parsed_args.as_deref());

    let mut executor = ContractExecutor::new(wasm_bytes.clone())?;
    executor.set_timeout(args.timeout);

    if let Some(storage) = initial_storage {
        executor.set_initial_storage(storage)?;
    }
    if !args.mock.is_empty() {
        executor.set_mock_specs(&args.mock)?;
    }

    let mut engine = DebuggerEngine::new(executor, args.breakpoint.clone());

    // Server mode is handled at the beginning of the function
    // Remote mode is not yet implemented

    if args.remote.is_some() {
        return Err(DebuggerError::ExecutionError(
            "Remote mode not yet implemented in run command".to_string(),
        )
        .into());
    }

    // Execute locally with debugging
    if !args.is_json_output() {
        println!("\n--- Execution Start ---\n");
    }
    if args.instruction_debug {
        print_info("Enabling instruction-level debugging...");
        engine.enable_instruction_debug(&wasm_bytes)?;

        if args.step_instructions {
            let step_mode = parse_step_mode(&args.step_mode);
            print_info(format!(
                "Starting instruction stepping in '{}' mode",
                args.step_mode
            ));
            engine.start_instruction_stepping(step_mode)?;
            run_instruction_stepping(&mut engine, function, parsed_args.as_deref())?;
            return Ok(());
        }
    }

    print_info("\n--- Execution Start ---\n");
    output_writer.write("\n--- Execution Start ---\n")?;
    let storage_before = engine.executor().get_storage_snapshot()?;
    let result = engine.execute(function, parsed_args.as_deref())?;
    let storage_after = engine.executor().get_storage_snapshot()?;
    print_success("\n--- Execution Complete ---\n");
    output_writer.write("\n--- Execution Complete ---\n")?;
    print_result(format!("Result: {:?}", result));
    output_writer.write(&format!("Result: {:?}", result))?;
    logging::log_execution_complete(&result);

    // Generate test if requested
    if let Some(test_path) = &args.generate_test {
        if let Some(record) = engine.executor().last_execution() {
            print_info(format!("\nGenerating unit test: {:?}", test_path));
            let test_code = crate::codegen::TestGenerator::generate(record, contract)?;
            crate::codegen::TestGenerator::write_to_file(test_path, &test_code, args.overwrite)?;
            print_success(format!(
                "Unit test generated successfully at {:?}",
                test_path
            ));
        } else {
            print_warning("No execution record found to generate test.");
        }
    }

    let storage_diff = crate::inspector::storage::StorageInspector::compute_diff(
        &storage_before,
        &storage_after,
        &args.alert_on_change,
    );
    if !storage_diff.is_empty() || !args.alert_on_change.is_empty() {
        print_info("\n--- Storage Changes ---");
        crate::inspector::storage::StorageInspector::display_diff(&storage_diff);
    }

    if let Some(export_path) = &args.export_storage {
        print_info(format!("\nExporting storage to: {:?}", export_path));
        crate::inspector::storage::StorageState::export_to_file(&storage_after, export_path)?;
    }
    let mock_calls = engine.executor().get_mock_call_log();
    if !args.mock.is_empty() {
        display_mock_call_log(&mock_calls);
    }

    // Save budget info to history
    let host = engine.executor().host();
    let budget = crate::inspector::budget::BudgetInspector::get_cpu_usage(host);
    if let Ok(manager) = HistoryManager::new() {
        let record = RunHistory {
            date: chrono::Utc::now().to_rfc3339(),
            contract_hash: contract.to_string_lossy().to_string(),
            function: function.clone(),
            cpu_used: budget.cpu_instructions,
            memory_used: budget.memory_bytes,
        };
        let _ = manager.append_record(record);
    }
    let _json_memory_summary = engine.executor().last_memory_summary().cloned();

    // Export storage if specified
    if let Some(export_path) = &args.export_storage {
        print_info(format!("Exporting storage to: {:?}", export_path));
        let storage_snapshot = engine.executor().get_storage_snapshot()?;
        crate::inspector::storage::StorageState::export_to_file(&storage_snapshot, export_path)?;
        print_success(format!(
            "Exported {} storage entries",
            storage_snapshot.len()
        ));
    }

    let mut json_events = None;
    if args.show_events || !args.event_filter.is_empty() || args.filter_topic.is_some() {
        print_info("\n--- Events ---");

        // Attempt to read raw events from executor
        let raw_events = engine.executor().get_events()?;

        // Convert runtime event objects into our inspector::events::ContractEvent via serde translation.
        // This is a generic, safe conversion as long as runtime events are serializable with sensible fields.
        let converted_events: Vec<ContractEvent> =
            match serde_json::to_value(&raw_events).and_then(serde_json::from_value) {
                Ok(evts) => evts,
                Err(e) => {
                    // If conversion fails, fall back to attempting to stringify each raw event for display.
                    print_warning(format!(
                        "Failed to convert runtime events for structured display: {}",
                        e
                    ));
                    // Fallback: attempt a best-effort stringification
                    let fallback: Vec<ContractEvent> = raw_events
                        .into_iter()
                        .map(|r| ContractEvent {
                            contract_id: None,
                            topics: vec![],
                            data: format!("{:?}", r),
                        })
                        .collect();
                    fallback
                }
            };

        // Determine filter: prefer repeatable --event-filter, fallback to legacy --filter-topic
        let filter_opt = if !args.event_filter.is_empty() {
            Some(args.event_filter.join(","))
        } else {
            args.filter_topic.clone()
        };

        let filtered_events = if let Some(ref filt) = filter_opt {
            EventInspector::filter_events(&converted_events, filt)
        } else {
            converted_events.clone()
        };

        if filtered_events.is_empty() {
            print_warning("No events captured.");
        } else {
            // Display events in readable form
            let lines = EventInspector::format_events(&filtered_events);
            for line in &lines {
                print_info(line);
            }
        }

        json_events = Some(filtered_events);
    }

    if !args.storage_filter.is_empty() {
        let storage_filter = crate::inspector::storage::StorageFilter::new(&args.storage_filter)
            .map_err(|e| DebuggerError::StorageError(format!("Invalid storage filter: {}", e)))?;

        print_info("\n--- Storage ---");
        let inspector =
            crate::inspector::storage::StorageInspector::with_state(storage_after.clone());
        inspector.display_filtered(&storage_filter);
    }

    let mut json_auth = None;
    if args.show_auth {
        let auth_tree = engine.executor().get_auth_tree()?;
        if args.json {
            // JSON mode: print the auth tree inline (will also be included in
            // the combined JSON object further below).
            let json_output = crate::inspector::auth::AuthInspector::to_json(&auth_tree)?;
            logging::log_display(json_output, logging::LogLevel::Info);
        } else {
            print_info("\n--- Authorization Tree ---");
            crate::inspector::auth::AuthInspector::display_with_summary(&auth_tree);
        }
        json_auth = Some(auth_tree);
    }

    let mut json_ledger = None;
    if args.show_ledger {
        print_info("\n--- Ledger Entries ---");
        let mut ledger_inspector = crate::inspector::ledger::LedgerEntryInspector::new();
        ledger_inspector.set_ttl_warning_threshold(args.ttl_warning_threshold);

        match engine.executor_mut().finish() {
            Ok((footprint, storage)) => {
                #[allow(clippy::clone_on_copy)]
                let mut footprint_map = std::collections::HashMap::new();
                for (k, v) in &footprint.0 {
                    #[allow(clippy::clone_on_copy)]
                    footprint_map.insert(k.clone(), v.clone());
                    footprint_map.insert(k.clone(), *v);
                }

                for (key, val_opt) in &storage.map {
                    if let Some(access_type) = footprint_map.get(key) {
                        if let Some((entry, ttl)) = val_opt {
                            let key_str = format!("{:?}", **key);
                            let storage_type =
                                if key_str.contains("Temporary") || key_str.contains("temporary") {
                                    crate::inspector::ledger::StorageType::Temporary
                                } else if key_str.contains("Instance")
                                    || key_str.contains("instance")
                                    || key_str.contains("LedgerKeyContractInstance")
                                {
                                    crate::inspector::ledger::StorageType::Instance
                                } else {
                                    crate::inspector::ledger::StorageType::Persistent
                                };

                            use soroban_env_host::storage::AccessType;
                            let is_read = true; // Everything in the footprint is at least read
                            let is_write = matches!(*access_type, AccessType::ReadWrite);

                            ledger_inspector.add_entry(
                                format!("{:?}", **key),
                                format!("{:?}", **entry),
                                storage_type,
                                ttl.unwrap_or(0),
                                is_read,
                                is_write,
                            );
                        }
                    }
                }
            }
            Err(e) => {
                print_warning(format!("Failed to extract ledger footprint: {}", e));
            }
        }

        ledger_inspector.display();
        ledger_inspector.display_warnings();
        json_ledger = Some(ledger_inspector);
    }

    if args.is_json_output() {
        let mut output = serde_json::json!({
            "status": "success",
            "result": result,
            "sha256": wasm_hash,
            "budget": {
                "cpu_instructions": budget.cpu_instructions,
                "memory_bytes": budget.memory_bytes,
            },
            "storage_diff": storage_diff,
        });

        if let Some(ref events) = json_events {
            output["events"] = EventInspector::to_json_value(events);
        }
        if let Some(auth_tree) = json_auth {
            output["auth"] = crate::inspector::auth::AuthInspector::to_json_value(&auth_tree);
        }
        if !mock_calls.is_empty() {
            output["mock_calls"] = serde_json::Value::Array(
                mock_calls
                    .iter()
                    .map(|entry| {
                        serde_json::json!({
                            "contract_id": entry.contract_id,
                            "function": entry.function,
                            "args_count": entry.args_count,
                            "mocked": entry.mocked,
                            "returned": entry.returned,
                        })
                    })
                    .collect(),
            );
        }
        if let Some(ref ledger) = json_ledger {
            output["ledger_entries"] = ledger.to_json();
        }

        match serde_json::to_string_pretty(&output) {
            Ok(json) => println!("{}", json),
            Err(e) => {
                let err_output = serde_json::json!({
                    "status": "error",
                    "errors": [format!("Failed to serialize output: {}", e)]
                });
                if let Ok(err_json) = serde_json::to_string_pretty(&err_output) {
                    println!("{}", err_json);
                }
            }
        }
    }

    if let Some(trace_path) = &args.trace_output {
        print_info(format!("\nExporting execution trace to: {:?}", trace_path));

        let args_str = parsed_args
            .as_ref()
            .map(|a| serde_json::to_string(a).unwrap_or_default());

        let trace_events =
            json_events.unwrap_or_else(|| engine.executor().get_events().unwrap_or_default());

        let trace = build_execution_trace(
            function,
            contract.to_string_lossy().as_ref(),
            args_str,
            &storage_after,
            &result,
            budget,
            engine.executor(),
            &trace_events,
            usize::MAX,
        );

        if let Ok(json) = trace.to_json() {
            if let Err(e) = std::fs::write(trace_path, json) {
                print_warning(format!("Failed to write trace to {:?}: {}", trace_path, e));
            } else {
                print_success(format!("Successfully exported trace to {:?}", trace_path));
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_execution_trace(
    function: &str,
    contract_path: &str,
    args_str: Option<String>,
    storage_after: &std::collections::HashMap<String, String>,
    result: &str,
    budget: crate::inspector::budget::BudgetInfo,
    executor: &ContractExecutor,
    events: &[crate::inspector::events::ContractEvent],
    replay_until: usize,
) -> crate::compare::ExecutionTrace {
    let mut trace_storage = std::collections::BTreeMap::new();
    for (k, v) in storage_after {
        if let Ok(val) = serde_json::from_str(v) {
            trace_storage.insert(k.clone(), val);
        } else {
            trace_storage.insert(k.clone(), serde_json::Value::String(v.clone()));
        }
    }

    let return_val = serde_json::from_str(result)
        .unwrap_or_else(|_| serde_json::Value::String(result.to_string()));

    let mut call_sequence = Vec::new();
    let mut depth = 0;

    call_sequence.push(crate::compare::trace::CallEntry {
        function: function.to_string(),
        args: args_str.clone(),
        depth,
    });

    if let Ok(diag_events) = executor.get_diagnostic_events() {
        for event in diag_events {
            // Stop building trace if we hit the replay limit
            if call_sequence.len() >= replay_until {
                break;
            }

            let event_str = format!("{:?}", event);
            if event_str.contains("ContractCall")
                || (event_str.contains("call") && event.contract_id.is_some())
            {
                depth += 1;
                call_sequence.push(crate::compare::trace::CallEntry {
                    function: "nested_call".to_string(),
                    args: None,
                    depth,
                });
            } else if (event_str.contains("ContractReturn") || event_str.contains("return"))
                && depth > 0
            {
                depth -= 1;
            }
        }
    }

    let mut trace_events = Vec::new();
    for e in events {
        trace_events.push(crate::compare::trace::EventEntry {
            contract_id: e.contract_id.clone(),
            topics: e.topics.clone(),
            data: Some(e.data.clone()),
        });
    }

    crate::compare::ExecutionTrace {
        label: Some(format!("Execution of {} on {}", function, contract_path)),
        contract: Some(contract_path.to_string()),
        function: Some(function.to_string()),
        args: args_str,
        storage: trace_storage,
        budget: Some(crate::compare::trace::BudgetTrace {
            cpu_instructions: budget.cpu_instructions,
            memory_bytes: budget.memory_bytes,
            cpu_limit: None,
            memory_limit: None,
        }),
        return_value: Some(return_val),
        call_sequence,
        events: trace_events,
    }
}

/// Execute run command in dry-run mode.
fn run_dry_run(args: &RunArgs) -> Result<()> {
    let contract = args
        .contract
        .as_ref()
        .expect("contract is required for dry-run");
    print_info(format!("[DRY RUN] Loading contract: {:?}", contract));

    let wasm_file = crate::utils::wasm::load_wasm(contract)
        .with_context(|| format!("Failed to read WASM file: {:?}", contract))?;
    let wasm_bytes = wasm_file.bytes;
    let wasm_hash = wasm_file.sha256_hash;

    if let Some(expected) = &args.expected_hash {
        if expected.to_lowercase() != wasm_hash {
            return Err((crate::DebuggerError::ChecksumMismatch {
                expected: expected.clone(),
                actual: wasm_hash.clone(),
            })
            .into());
        }
    }

    print_success(format!(
        "[DRY RUN] Contract loaded successfully ({} bytes)",
        wasm_bytes.len()
    ));

    if args.verbose {
        print_verbose(format!("[DRY RUN] SHA-256: {}", wasm_hash));
        if args.expected_hash.is_some() {
            print_verbose("[DRY RUN] Checksum verified âœ“");
        }
    }

    print_info("[DRY RUN] Skipping execution");

    Ok(())
}

/// Get instruction counts from the debugger engine
#[allow(dead_code)]
fn get_instruction_counts(
    engine: &DebuggerEngine,
) -> Option<crate::runtime::executor::InstructionCounts> {
    // Try to get instruction counts from the executor
    engine.executor().get_instruction_counts().ok()
}

/// Display instruction counts per function in a formatted table
#[allow(dead_code)]
fn display_instruction_counts(counts: &crate::runtime::executor::InstructionCounts) {
    if counts.function_counts.is_empty() {
        return;
    }

    print_info("\n--- Instruction Count per Function ---");

    // Calculate percentages
    let percentages: Vec<f64> = counts
        .function_counts
        .iter()
        .map(|(_, count)| {
            if counts.total > 0 {
                ((*count as f64) / (counts.total as f64)) * 100.0
            } else {
                0.0
            }
        })
        .collect();

    // Find max widths for alignment
    let max_func_width = counts
        .function_counts
        .iter()
        .map(|(name, _)| name.len())
        .max()
        .unwrap_or(20);
    let max_count_width = counts
        .function_counts
        .iter()
        .map(|(_, count)| count.to_string().len())
        .max()
        .unwrap_or(10);

    // Print header
    let header = format!(
        "{:<width1$} | {:>width2$} | {:>width3$}",
        "Function",
        "Instructions",
        "Percentage",
        width1 = max_func_width,
        width2 = max_count_width,
        width3 = 10
    );
    print_info(&header);
    print_info("-".repeat(header.len()));

    // Print rows
    for ((func_name, count), percentage) in counts.function_counts.iter().zip(percentages.iter()) {
        let row = format!(
            "{:<width1$} | {:>width2$} | {:>7.2}%",
            func_name,
            count,
            percentage,
            width1 = max_func_width,
            width2 = max_count_width
        );
        print_info(&row);
    }
}

/// Execute the upgrade-check command
pub fn upgrade_check(args: UpgradeCheckArgs) -> Result<()> {
    println!("Loading old contract: {:?}", args.old);
    let old_wasm = fs::read(&args.old)
        .map_err(|e| miette::miette!("Failed to read old WASM file {:?}: {}", args.old, e))?;

    println!("Loading new contract: {:?}", args.new);
    let new_wasm = fs::read(&args.new)
        .map_err(|e| miette::miette!("Failed to read new WASM file {:?}: {}", args.new, e))?;

    // Optionally run test inputs against both versions
    let execution_diffs = if let Some(inputs_json) = &args.test_inputs {
        run_test_inputs(inputs_json, &old_wasm, &new_wasm)?
    } else {
        Vec::new()
    };

    let old_path = args.old.to_string_lossy().to_string();
    let new_path = args.new.to_string_lossy().to_string();

    let report =
        UpgradeAnalyzer::analyze(&old_wasm, &new_wasm, &old_path, &new_path, execution_diffs)?;

    let output = match args.output.as_str() {
        "json" => serde_json::to_string_pretty(&report)
            .map_err(|e| miette::miette!("Failed to serialize report: {}", e))?,
        _ => format_text_report(&report),
    };

    if let Some(out_file) = &args.output_file {
        fs::write(out_file, &output)
            .map_err(|e| miette::miette!("Failed to write report to {:?}: {}", out_file, e))?;
        println!("Report written to {:?}", out_file);
    } else {
        println!("{}", output);
    }

    if !report.is_compatible {
        return Err(miette::miette!(
            "Contracts are not compatible: {} breaking change(s) detected",
            report.breaking_changes.len()
        ));
    }

    Ok(())
}

/// Run test inputs against both WASM versions and collect diffs
fn run_test_inputs(
    inputs_json: &str,
    old_wasm: &[u8],
    new_wasm: &[u8],
) -> Result<Vec<ExecutionDiff>> {
    let inputs: serde_json::Map<String, serde_json::Value> = serde_json
        ::from_str(inputs_json)
        .map_err(|e|
            miette::miette!(
                "Invalid --test-inputs JSON (expected an object mapping function names to arg arrays): {}",
                e
            )
        )?;

    let mut diffs = Vec::new();

    for (func_name, args_val) in &inputs {
        let args_str = args_val.to_string();

        let old_result = invoke_wasm(old_wasm, func_name, &args_str);
        let new_result = invoke_wasm(new_wasm, func_name, &args_str);

        let outputs_match = old_result == new_result;
        diffs.push(ExecutionDiff {
            function: func_name.clone(),
            args: args_str,
            old_result,
            new_result,
            outputs_match,
        });
    }

    Ok(diffs)
}

/// Invoke a function on a WASM contract and return a string representation of the result
fn invoke_wasm(wasm: &[u8], function: &str, args: &str) -> String {
    match ContractExecutor::new(wasm.to_vec()) {
        Err(e) => format!("Err(executor: {})", e),
        Ok(executor) => {
            let mut engine = DebuggerEngine::new(executor, vec![]);
            let parsed = if args == "null" || args == "[]" {
                None
            } else {
                Some(args.to_string())
            };
            match engine.execute(function, parsed.as_deref()) {
                Ok(val) => format!("Ok({:?})", val),
                Err(e) => format!("Err({})", e),
            }
        }
    }
}

/// Format a compatibility report as human-readable text
fn format_text_report(report: &CompatibilityReport) -> String {
    let mut out = String::new();

    out.push_str("Contract Upgrade Compatibility Report\n");
    out.push_str("======================================\n");
    out.push_str(&format!("Old: {}\n", report.old_wasm_path));
    out.push_str(&format!("New: {}\n", report.new_wasm_path));
    out.push('\n');

    let status = if report.is_compatible {
        "COMPATIBLE"
    } else {
        "INCOMPATIBLE"
    };
    out.push_str(&format!("Status: {}\n", status));

    out.push('\n');
    out.push_str(&format!(
        "Breaking Changes ({}):\n",
        report.breaking_changes.len()
    ));
    if report.breaking_changes.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for change in &report.breaking_changes {
            out.push_str(&format!("  {}\n", change));
        }
    }

    out.push('\n');
    out.push_str(&format!(
        "Non-Breaking Changes ({}):\n",
        report.non_breaking_changes.len()
    ));
    if report.non_breaking_changes.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for change in &report.non_breaking_changes {
            out.push_str(&format!("  {}\n", change));
        }
    }

    if !report.execution_diffs.is_empty() {
        out.push('\n');
        out.push_str(&format!(
            "Execution Diffs ({}):\n",
            report.execution_diffs.len()
        ));
        for diff in &report.execution_diffs {
            let match_str = if diff.outputs_match {
                "MATCH"
            } else {
                "MISMATCH"
            };
            out.push_str(&format!(
                "  {} args={} OLD={} NEW={} [{}]\n",
                diff.function, diff.args, diff.old_result, diff.new_result, match_str
            ));
        }
    }

    out.push('\n');
    let old_names: Vec<&str> = report
        .old_functions
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    let new_names: Vec<&str> = report
        .new_functions
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    out.push_str(&format!(
        "Old Functions ({}): {}\n",
        old_names.len(),
        old_names.join(", ")
    ));
    out.push_str(&format!(
        "New Functions ({}): {}\n",
        new_names.len(),
        new_names.join(", ")
    ));

    out
}

/// Parse JSON arguments with validation.
pub fn parse_args(json: &str) -> Result<String> {
    let value = serde_json::from_str::<serde_json::Value>(json).map_err(|e| {
        DebuggerError::InvalidArguments(format!(
            "Failed to parse JSON arguments: {}. Error: {}",
            json, e
        ))
    })?;

    match value {
        serde_json::Value::Array(ref arr) => {
            tracing::debug!(count = arr.len(), "Parsed array arguments");
        }
        serde_json::Value::Object(ref obj) => {
            tracing::debug!(fields = obj.len(), "Parsed object arguments");
        }
        _ => {
            tracing::debug!("Parsed single value argument");
        }
    }

    Ok(json.to_string())
}

/// Parse JSON storage.
pub fn parse_storage(json: &str) -> Result<String> {
    serde_json::from_str::<serde_json::Value>(json).map_err(|e| {
        DebuggerError::StorageError(format!(
            "Failed to parse JSON storage: {}. Error: {}",
            json, e
        ))
    })?;
    Ok(json.to_string())
}

/// Execute the optimize command.
pub fn optimize(args: OptimizeArgs, _verbosity: Verbosity) -> Result<()> {
    print_info(format!(
        "Analyzing contract for gas optimization: {:?}",
        args.contract
    ));
    logging::log_loading_contract(&args.contract.to_string_lossy());

    let wasm_file = crate::utils::wasm::load_wasm(&args.contract)
        .with_context(|| format!("Failed to read WASM file: {:?}", args.contract))?;
    let wasm_bytes = wasm_file.bytes;
    let wasm_hash = wasm_file.sha256_hash;

    if let Some(expected) = &args.expected_hash {
        if expected.to_lowercase() != wasm_hash {
            return Err((crate::DebuggerError::ChecksumMismatch {
                expected: expected.clone(),
                actual: wasm_hash.clone(),
            })
            .into());
        }
    }

    print_success(format!(
        "Contract loaded successfully ({} bytes)",
        wasm_bytes.len()
    ));

    if _verbosity == Verbosity::Verbose {
        print_verbose(format!("SHA-256: {}", wasm_hash));
        if args.expected_hash.is_some() {
            print_verbose("Checksum verified âœ“");
        }
    }

    logging::log_contract_loaded(wasm_bytes.len());

    if let Some(snapshot_path) = &args.network_snapshot {
        print_info(format!("\nLoading network snapshot: {:?}", snapshot_path));
        logging::log_loading_snapshot(&snapshot_path.to_string_lossy());
        let loader = SnapshotLoader::from_file(snapshot_path)?;
        let loaded_snapshot = loader.apply_to_environment()?;
        logging::log_display(loaded_snapshot.format_summary(), logging::LogLevel::Info);
    }

    let functions_to_analyze = if args.function.is_empty() {
        print_warning("No functions specified, analyzing all exported functions...");
        crate::utils::wasm::parse_functions(&wasm_bytes)?
    } else {
        args.function.clone()
    };

    let mut executor = ContractExecutor::new(wasm_bytes)?;
    if let Some(storage_json) = &args.storage {
        let storage = parse_storage(storage_json)?;
        executor.set_initial_storage(storage)?;
    }

    let mut optimizer = crate::profiler::analyzer::GasOptimizer::new(executor);

    print_info(format!(
        "\nAnalyzing {} function(s)...",
        functions_to_analyze.len()
    ));
    logging::log_analysis_start("gas optimization");

    for function_name in &functions_to_analyze {
        print_info(format!("  Analyzing function: {}", function_name));
        match optimizer.analyze_function(function_name, args.args.as_deref()) {
            Ok(profile) => {
                logging::log_display(
                    format!(
                        "    CPU: {} instructions, Memory: {} bytes, Time: {} ms",
                        profile.total_cpu, profile.total_memory, profile.wall_time_ms
                    ),
                    logging::LogLevel::Info,
                );
                print_success(format!(
                    "    CPU: {} instructions, Memory: {} bytes",
                    profile.total_cpu, profile.total_memory
                ));
            }
            Err(e) => {
                print_warning(format!(
                    "    Warning: Failed to analyze function {}: {}",
                    function_name, e
                ));
                tracing::warn!(function = function_name, error = %e, "Failed to analyze function");
            }
        }
    }
    logging::log_analysis_complete("gas optimization", functions_to_analyze.len());

    let contract_path_str = args.contract.to_string_lossy().to_string();
    let report = optimizer.generate_report(&contract_path_str);
    let markdown = optimizer.generate_markdown_report(&report);

    if let Some(output_path) = &args.output {
        fs::write(output_path, &markdown).map_err(|e| {
            DebuggerError::FileError(format!(
                "Failed to write report to {:?}: {}",
                output_path, e
            ))
        })?;
        print_success(format!(
            "\nOptimization report written to: {:?}",
            output_path
        ));
        logging::log_optimization_report(&output_path.to_string_lossy());
    } else {
        logging::log_display(&markdown, logging::LogLevel::Info);
    }

    Ok(())
}

/// âœ… Execute the profile command (hotspots + suggestions)
pub fn profile(args: ProfileArgs) -> Result<()> {
    logging::log_display(
        format!("Profiling contract execution: {:?}", args.contract),
        logging::LogLevel::Info,
    );

    let wasm_file = crate::utils::wasm::load_wasm(&args.contract)
        .with_context(|| format!("Failed to read WASM file: {:?}", args.contract))?;
    let wasm_bytes = wasm_file.bytes;
    let wasm_hash = wasm_file.sha256_hash;

    if let Some(expected) = &args.expected_hash {
        if expected.to_lowercase() != wasm_hash {
            return Err((crate::DebuggerError::ChecksumMismatch {
                expected: expected.clone(),
                actual: wasm_hash.clone(),
            })
            .into());
        }
    }

    logging::log_display(
        format!("Contract loaded successfully ({} bytes)", wasm_bytes.len()),
        logging::LogLevel::Info,
    );

    // Parse args (optional)
    let parsed_args = if let Some(args_json) = &args.args {
        Some(parse_args(args_json)?)
    } else {
        None
    };

    // Create executor
    let mut executor = ContractExecutor::new(wasm_bytes)?;

    // Initial storage (optional)
    if let Some(storage_json) = &args.storage {
        let storage = parse_storage(storage_json)?;
        executor.set_initial_storage(storage)?;
    }

    // Analyze exactly one function (this command focuses on execution hotspots)
    let mut optimizer = crate::profiler::analyzer::GasOptimizer::new(executor);

    logging::log_display(
        format!("\nRunning function: {}", args.function),
        logging::LogLevel::Info,
    );
    if let Some(ref a) = parsed_args {
        logging::log_display(format!("Args: {}", a), logging::LogLevel::Info);
    }

    let _profile = optimizer.analyze_function(&args.function, parsed_args.as_deref())?;

    let contract_path_str = args.contract.to_string_lossy().to_string();
    let report = optimizer.generate_report(&contract_path_str);

    // Hotspot summary first
    logging::log_display(
        format!("\n{}", report.format_hotspots()),
        logging::LogLevel::Info,
    );

    // Then detailed suggestions (markdown format)
    let markdown = optimizer.generate_markdown_report(&report);

    if let Some(output_path) = &args.output {
        fs::write(output_path, &markdown).map_err(|e| {
            DebuggerError::FileError(format!(
                "Failed to write report to {:?}: {}",
                output_path, e
            ))
        })?;
        logging::log_display(
            format!("\nProfile report written to: {:?}", output_path),
            logging::LogLevel::Info,
        );
    } else {
        logging::log_display(format!("\n{}", markdown), logging::LogLevel::Info);
    }

    Ok(())
}

/// Execute the compare command.
pub fn compare(args: CompareArgs) -> Result<()> {
    print_info(format!("Loading trace A: {:?}", args.trace_a));
    let trace_a = crate::compare::ExecutionTrace::from_file(&args.trace_a)?;

    print_info(format!("Loading trace B: {:?}", args.trace_b));
    let trace_b = crate::compare::ExecutionTrace::from_file(&args.trace_b)?;

    print_info("Comparing traces...");
    let filters = crate::compare::engine::CompareFilters::new(
        args.ignore_path.clone(),
        args.ignore_field.clone(),
    )?;
    let report = crate::compare::CompareEngine::compare_with_filters(&trace_a, &trace_b, &filters);
    let rendered = crate::compare::CompareEngine::render_report(&report);

    if let Some(output_path) = &args.output {
        fs::write(output_path, &rendered).map_err(|e| {
            DebuggerError::FileError(format!(
                "Failed to write report to {:?}: {}",
                output_path, e
            ))
        })?;
        print_success(format!("Comparison report written to: {:?}", output_path));
    } else {
        println!("{}", rendered);
    }

    Ok(())
}

/// Execute the replay command.
pub fn replay(args: ReplayArgs, verbosity: Verbosity) -> Result<()> {
    print_info(format!("Loading trace file: {:?}", args.trace_file));
    let original_trace = crate::compare::ExecutionTrace::from_file(&args.trace_file)?;

    // Determine which contract to use
    let contract_path = if let Some(path) = &args.contract {
        path.clone()
    } else if let Some(contract_str) = &original_trace.contract {
        std::path::PathBuf::from(contract_str)
    } else {
        return Err(DebuggerError::ExecutionError(
            "No contract path specified and trace file does not contain contract path".to_string(),
        )
        .into());
    };

    print_info(format!("Loading contract: {:?}", contract_path));
    let wasm_bytes = fs::read(&contract_path).map_err(|e| {
        DebuggerError::WasmLoadError(format!(
            "Failed to read WASM file at {:?}: {}",
            contract_path, e
        ))
    })?;

    print_success(format!(
        "Contract loaded successfully ({} bytes)",
        wasm_bytes.len()
    ));

    // Extract function and args from trace
    let function = original_trace.function.as_ref().ok_or_else(|| {
        DebuggerError::ExecutionError("Trace file does not contain function name".to_string())
    })?;

    let args_str = original_trace.args.as_deref();

    // Determine how many steps to replay
    let replay_steps = args.replay_until.unwrap_or(usize::MAX);
    let is_partial_replay = args.replay_until.is_some();

    if is_partial_replay {
        print_info(format!("Replaying up to step {}", replay_steps));
    } else {
        print_info("Replaying full execution");
    }

    print_info(format!("Function: {}", function));
    if let Some(a) = args_str {
        print_info(format!("Arguments: {}", a));
    }

    // Set up initial storage from trace
    let initial_storage = if !original_trace.storage.is_empty() {
        let storage_json = serde_json::to_string(&original_trace.storage).map_err(|e| {
            DebuggerError::StorageError(format!("Failed to serialize trace storage: {}", e))
        })?;
        Some(storage_json)
    } else {
        None
    };

    // Execute the contract
    print_info("\n--- Replaying Execution ---\n");
    let mut executor = ContractExecutor::new(wasm_bytes)?;

    if let Some(storage) = initial_storage {
        executor.set_initial_storage(storage)?;
    }

    let mut engine = DebuggerEngine::new(executor, vec![]);

    logging::log_execution_start(function, args_str);
    let replayed_result = engine.execute(function, args_str)?;

    print_success("\n--- Replay Complete ---\n");
    print_success(format!("Replayed Result: {:?}", replayed_result));
    logging::log_execution_complete(&replayed_result);

    // Compare results
    print_info("\n--- Comparison ---");

    let original_return_str = original_trace
        .return_value
        .as_ref()
        .map(|v| serde_json::to_string(v).unwrap_or_default())
        .unwrap_or_default();

    let results_match = replayed_result.trim() == original_return_str.trim()
        || format!("\"{replayed_result}\"") == original_return_str;

    if results_match {
        print_success("âœ“ Results match! Replayed execution produced the same output.");
    } else {
        print_warning("âœ— Results differ!");
        print_info(format!("  Original: {}", original_return_str));
        print_info(format!("  Replayed: {}", replayed_result));
    }

    // Budget comparison
    if let Some(original_budget) = &original_trace.budget {
        let host = engine.executor().host();
        let replayed_budget = crate::inspector::budget::BudgetInspector::get_cpu_usage(host);

        print_info("\n--- Budget Comparison ---");
        print_info(format!(
            "  Original CPU: {} instructions",
            original_budget.cpu_instructions
        ));
        print_info(format!(
            "  Replayed CPU: {} instructions",
            replayed_budget.cpu_instructions
        ));

        let cpu_diff =
            replayed_budget.cpu_instructions as i64 - original_budget.cpu_instructions as i64;

        match cpu_diff.cmp(&0) {
            std::cmp::Ordering::Equal => {
                print_success("  CPU usage matches exactly âœ“");
            }
            std::cmp::Ordering::Greater => {
                print_warning(format!("  CPU increased by {} instructions", cpu_diff));
            }
            std::cmp::Ordering::Less => {
                print_success(format!("  CPU decreased by {} instructions", -cpu_diff));
            }
        }

        print_info(format!(
            "  Original Memory: {} bytes",
            original_budget.memory_bytes
        ));
        print_info(format!(
            "  Replayed Memory: {} bytes",
            replayed_budget.memory_bytes
        ));

        let mem_diff = replayed_budget.memory_bytes as i64 - original_budget.memory_bytes as i64;

        match mem_diff.cmp(&0) {
            std::cmp::Ordering::Equal => {
                print_success("  Memory usage matches exactly âœ“");
            }
            std::cmp::Ordering::Greater => {
                print_warning(format!("  Memory increased by {} bytes", mem_diff));
            }
            std::cmp::Ordering::Less => {
                print_success(format!("  Memory decreased by {} bytes", -mem_diff));
            }
        }
    }

    // Generate detailed report if output file specified
    if let Some(output_path) = &args.output {
        let mut report = String::new();
        report.push_str("# Execution Replay Report\n\n");
        report.push_str(&format!("**Trace File:** {:?}\n", args.trace_file));
        report.push_str(&format!("**Contract:** {:?}\n", contract_path));
        report.push_str(&format!("**Function:** {}\n", function));
        if let Some(a) = args_str {
            report.push_str(&format!("**Arguments:** {}\n", a));
        }
        report.push_str("\n## Results\n\n");
        report.push_str(&format!(
            "**Original Return Value:**\n```\n{}\n```\n\n",
            original_return_str
        ));
        report.push_str(&format!(
            "**Replayed Return Value:**\n```\n{}\n```\n\n",
            replayed_result
        ));

        if results_match {
            report.push_str("âœ“ **Results match**\n\n");
        } else {
            report.push_str("âœ— **Results differ**\n\n");
        }

        if let Some(original_budget) = &original_trace.budget {
            let host = engine.executor().host();
            let replayed_budget = crate::inspector::budget::BudgetInspector::get_cpu_usage(host);

            report.push_str("## Budget Comparison\n\n");
            report.push_str("| Metric | Original | Replayed | Difference |\n");
            report.push_str("|--------|----------|----------|------------|\n");
            report.push_str(&format!(
                "| CPU Instructions | {} | {} | {} |\n",
                original_budget.cpu_instructions,
                replayed_budget.cpu_instructions,
                replayed_budget.cpu_instructions as i64 - original_budget.cpu_instructions as i64
            ));
            report.push_str(&format!(
                "| Memory Bytes | {} | {} | {} |\n",
                original_budget.memory_bytes,
                replayed_budget.memory_bytes,
                replayed_budget.memory_bytes as i64 - original_budget.memory_bytes as i64
            ));
        }

        fs::write(output_path, &report).map_err(|e| {
            DebuggerError::FileError(format!(
                "Failed to write report to {:?}: {}",
                output_path, e
            ))
        })?;
        print_success(format!("\nReplay report written to: {:?}", output_path));
    }

    if verbosity == Verbosity::Verbose {
        print_info("\n--- Call Sequence (Original) ---");
        for (i, call) in original_trace.call_sequence.iter().enumerate() {
            let indent = "  ".repeat(call.depth as usize);
            if let Some(args) = &call.args {
                print_info(format!("{}{}. {} ({})", indent, i, call.function, args));
            } else {
                print_info(format!("{}{}. {}", indent, i, call.function));
            }

            if is_partial_replay && i >= replay_steps {
                print_warning(format!("{}... (stopped at step {})", indent, replay_steps));
                break;
            }
        }
    }

    Ok(())
}

/// Execute the symbolic command.
pub fn symbolic(args: SymbolicArgs, _verbosity: Verbosity) -> Result<()> {
    print_info(format!(
        "Starting symbolic execution analysis for contract: {:?}",
        args.contract
    ));
    let wasm_bytes = fs::read(&args.contract).map_err(|e| {
        DebuggerError::WasmLoadError(format!(
            "Failed to read WASM file {:?}: {}",
            args.contract, e
        ))
    })?;

    let analyzer = crate::analyzer::symbolic::SymbolicAnalyzer::new();
    let report = analyzer.analyze(&wasm_bytes, &args.function)?;

    print_success(format!("Paths explored: {}", report.paths_explored));
    print_success(format!("Panics found: {}", report.panics_found));

    let toml = analyzer.generate_scenario_toml(&report);
    if let Some(out) = args.output {
        fs::write(&out, toml).map_err(|e| {
            DebuggerError::FileError(format!("Failed to write toml to {:?}: {}", out, e))
        })?;
        print_success(format!("Wrote scenario to {:?}", out));
    } else {
        println!("{}", toml);
    }

    Ok(())
}

/// Run instruction-level stepping mode.
fn run_instruction_stepping(
    engine: &mut DebuggerEngine,
    function: &str,
    args: Option<&str>,
) -> Result<()> {
    println!("\n=== Instruction Stepping Mode ===");
    println!("Type 'help' for available commands\n");

    display_instruction_context(engine, 3);

    loop {
        print!("(step) > ");
        std::io::Write::flush(&mut std::io::stdout())
            .map_err(|e| DebuggerError::FileError(format!("Failed to flush stdout: {}", e)))?;

        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| DebuggerError::FileError(format!("Failed to read line: {}", e)))?;
        let input = input.trim().to_lowercase();

        match input.as_str() {
            "n" | "next" | "s" | "step" | "into" | "" => match engine.step_into() {
                Ok(true) => {
                    println!("Stepped to next instruction");
                    display_instruction_context(engine, 3);
                }
                Ok(false) => println!("Cannot step: execution finished or error occurred"),
                Err(e) => println!("Error stepping: {}", e),
            },
            "o" | "over" => match engine.step_over() {
                Ok(true) => {
                    println!("Stepped over instruction");
                    display_instruction_context(engine, 3);
                }
                Ok(false) => println!("Cannot step over: execution finished or error occurred"),
                Err(e) => println!("Error stepping: {}", e),
            },
            "u" | "out" => match engine.step_out() {
                Ok(true) => {
                    println!("Stepped out of function");
                    display_instruction_context(engine, 3);
                }
                Ok(false) => println!("Cannot step out: execution finished or error occurred"),
                Err(e) => println!("Error stepping: {}", e),
            },
            "b" | "block" => match engine.step_block() {
                Ok(true) => {
                    println!("Stepped to next basic block");
                    display_instruction_context(engine, 3);
                }
                Ok(false) => {
                    println!("Cannot step to next block: execution finished or error occurred")
                }
                Err(e) => println!("Error stepping: {}", e),
            },
            "p" | "prev" | "back" => match engine.step_back() {
                Ok(true) => {
                    println!("Stepped back to previous instruction");
                    display_instruction_context(engine, 3);
                }
                Ok(false) => println!("Cannot step back: no previous instruction"),
                Err(e) => println!("Error stepping: {}", e),
            },
            "c" | "continue" => {
                println!("Continuing execution...");
                engine.continue_execution()?;
                let result = engine.execute(function, args)?;
                println!("Execution completed. Result: {:?}", result);
                break;
            }
            "i" | "info" => display_instruction_info(engine),
            "ctx" | "context" => {
                print!("Enter context size (default 5): ");
                std::io::Write::flush(&mut std::io::stdout()).map_err(|e| {
                    DebuggerError::FileError(format!("Failed to flush stdout: {}", e))
                })?;
                let mut size_input = String::new();
                std::io::stdin()
                    .read_line(&mut size_input)
                    .map_err(|e| DebuggerError::FileError(format!("Failed to read line: {}", e)))?;
                let size = size_input.trim().parse().unwrap_or(5);
                display_instruction_context(engine, size);
            }
            "h" | "help" => println!("{}", Formatter::format_stepping_help()),
            "q" | "quit" | "exit" => {
                println!("Exiting instruction stepping mode...");
                break;
            }
            _ => {
                println!(
                    "Unknown command: {}. Type 'help' for available commands.",
                    input
                );
            }
        }
    }

    Ok(())
}

fn display_instruction_context(engine: &DebuggerEngine, context_size: usize) {
    let context = engine.get_instruction_context(context_size);
    let formatted = Formatter::format_instruction_context(&context, context_size);
    println!("{}", formatted);
}

fn display_instruction_info(engine: &DebuggerEngine) {
    if let Ok(state) = engine.state().lock() {
        let ip = state.instruction_pointer();
        let step_mode = if ip.is_stepping() {
            Some(ip.step_mode())
        } else {
            None
        };

        println!(
            "{}",
            Formatter::format_instruction_pointer_state(
                ip.current_index(),
                ip.call_stack_depth(),
                step_mode,
                ip.is_stepping(),
            )
        );

        println!(
            "{}",
            Formatter::format_instruction_stats(
                state.instructions().len(),
                ip.current_index(),
                state.step_count(),
            )
        );

        if let Some(current_inst) = state.current_instruction() {
            println!("Current Instruction Details:");
            println!("  Name: {}", current_inst.name());
            println!("  Offset: 0x{:08x}", current_inst.offset);
            println!("  Function: {}", current_inst.function_index);
            println!("  Local Index: {}", current_inst.local_index);
            println!("  Operands: {}", current_inst.operands());
            println!("  Control Flow: {}", current_inst.is_control_flow());
            println!("  Function Call: {}", current_inst.is_call());
        }
    } else {
        println!("Cannot access debug state");
    }
}

fn parse_step_mode(step_mode: &str) -> StepMode {
    match step_mode.to_lowercase().as_str() {
        "into" => StepMode::StepInto,
        "over" => StepMode::StepOver,
        "out" => StepMode::StepOut,
        "block" => StepMode::StepBlock,
        _ => StepMode::StepInto,
    }
}

fn display_mock_call_log(entries: &[crate::runtime::mocking::MockCallLogEntry]) {
    print_info("\n--- Mock Calls ---");
    if entries.is_empty() {
        print_warning("No cross-contract mock invocations captured.");
        return;
    }
    for (i, entry) in entries.iter().enumerate() {
        if entry.mocked {
            print_info(format!(
                "#{i} {}.{} args={} mocked return={}",
                entry.contract_id,
                entry.function,
                entry.args_count,
                entry.returned.as_deref().unwrap_or("<none>")
            ));
        } else {
            print_warning(format!(
                "#{i} {}.{} args={} unmocked",
                entry.contract_id, entry.function, entry.args_count
            ));
        }
    }
}

/// Show historical budget trend
pub fn show_budget_trend(contract: Option<&str>, function: Option<&str>) -> crate::Result<()> {
    let manager = HistoryManager::new()?;
    let records = manager.filter_history(contract, function)?;

    if records.is_empty() {
        print_warning("No historical budget data found.");
        return Ok(());
    }

    print_info(format!(
        "Found {} historical execution records.",
        records.len()
    ));

    let mut cpu_points = Vec::new();
    let mut mem_points = Vec::new();

    for (i, r) in records.iter().enumerate() {
        cpu_points.push((i as f32, r.cpu_used as f32));
        mem_points.push((i as f32, r.memory_used as f32));
    }

    println!("\n--- CPU Usage Trend ---");
    Chart::new(100, 40, 0.0, (records.len() - 1).max(1) as f32)
        .lineplot(&Shape::Lines(&cpu_points))
        .display();

    println!("\n--- Memory Usage Trend ---");
    Chart::new(100, 40, 0.0, (records.len() - 1).max(1) as f32)
        .lineplot(&Shape::Lines(&mem_points))
        .display();

    if let Some((cpu_reg, mem_reg)) = check_regression(&records) {
        println!();
        if cpu_reg > 0.0 {
            print_warning(format!(
                "âš ï¸ ALERT: CPU usage regression detected! Increased by {:.2}% compared to the previous run.",
                cpu_reg
            ));
        }
        if mem_reg > 0.0 {
            print_warning(format!(
                "âš ï¸ ALERT: Memory usage regression detected! Increased by {:.2}% compared to the previous run.",
                mem_reg
            ));
        }
    }

    Ok(())
}

/// Start the debug server
pub fn server(args: ServerArgs) -> Result<()> {
    use crate::server::DebugServer;

    print_info(format!("Starting debug server on port {}", args.port));

    let mut server = DebugServer::new(args.port, args.token);

    if let (Some(cert), Some(key)) = (args.tls_cert, args.tls_key) {
        server = server.with_tls(cert, key);
        print_info("TLS enabled");
    }

    print_success("Debug server started. Waiting for connections...");
    print_info("Press Ctrl+C to stop the server");

    server.start()?;

    Ok(())
}

/// Connect to remote debug server and run interactive session
pub fn remote(args: RemoteArgs, _verbosity: Verbosity) -> Result<()> {
    use crate::client::RemoteClient;

    print_info(format!(
        "Connecting to remote debug server at {}",
        args.remote
    ));

    let mut client = RemoteClient::connect(&args.remote, args.token.clone())?;
    print_success("Connected to debug server");

    // If contract and function are provided, execute directly
    if let (Some(contract), Some(function)) = (&args.contract, &args.function) {
        print_info(format!("Loading contract: {:?}", contract));
        let _size = client.load_contract(&contract.to_string_lossy())?;

        print_info(format!("Executing function: {}", function));
        match client.execute(function, args.args.as_deref()) {
            Ok(output) => {
                print_success("Execution successful");
                println!("Result: {}", output);
            }
            Err(e) => {
                print_warning(format!("Execution failed: {}", e));
                return Err(e);
            }
        }
    } else {
        // Interactive mode
        print_info("Starting interactive remote debugging session");
        print_info("Type 'help' for available commands");

        loop {
            print!("\n(remote-debug) ");
            std::io::Write::flush(&mut std::io::stdout())
                .map_err(|e| DebuggerError::FileError(format!("Failed to flush stdout: {}", e)))?;

            let mut input = String::new();
            std::io::stdin()
                .read_line(&mut input)
                .map_err(|e| DebuggerError::FileError(format!("Failed to read line: {}", e)))?;
            let command = input.trim();

            if command.is_empty() {
                continue;
            }

            let parts: Vec<&str> = command.split_whitespace().collect();
            match parts[0] {
                "load" | "l" => {
                    if parts.len() < 2 {
                        print_warning("Usage: load <contract_path>");
                    } else {
                        match client.load_contract(parts[1]) {
                            Ok(size) => print_success(format!("Contract loaded: {} bytes", size)),
                            Err(e) => print_warning(format!("Failed to load contract: {}", e)),
                        }
                    }
                }
                "exec" | "e" => {
                    if parts.len() < 2 {
                        print_warning("Usage: exec <function> [args_json]");
                    } else {
                        let args = if parts.len() > 2 {
                            Some(parts[2..].join(" "))
                        } else {
                            None
                        };
                        match client.execute(parts[1], args.as_deref()) {
                            Ok(output) => println!("Result: {}", output),
                            Err(e) => print_warning(format!("Execution failed: {}", e)),
                        }
                    }
                }
                "step" | "s" => match client.step() {
                    Ok((paused, func, count)) => {
                        println!("Step {}: function={:?}, paused={}", count, func, paused);
                    }
                    Err(e) => print_warning(format!("Step failed: {}", e)),
                },
                "continue" | "c" => match client.continue_execution() {
                    Ok(completed) => println!("Execution completed: {}", completed),
                    Err(e) => print_warning(format!("Continue failed: {}", e)),
                },
                "inspect" | "i" => match client.inspect() {
                    Ok((func, count, paused, stack)) => {
                        println!("Function: {:?}", func);
                        println!("Step count: {}", count);
                        println!("Paused: {}", paused);
                        println!("Call stack: {:?}", stack);
                    }
                    Err(e) => print_warning(format!("Inspect failed: {}", e)),
                },
                "storage" => match client.get_storage() {
                    Ok(storage) => println!("Storage: {}", storage),
                    Err(e) => print_warning(format!("Get storage failed: {}", e)),
                },
                "stack" => match client.get_stack() {
                    Ok(stack) => println!("Call stack: {:?}", stack),
                    Err(e) => print_warning(format!("Get stack failed: {}", e)),
                },
                "budget" | "b" => match client.get_budget() {
                    Ok((cpu, mem)) => {
                        println!("CPU instructions: {}", cpu);
                        println!("Memory bytes: {}", mem);
                    }
                    Err(e) => print_warning(format!("Get budget failed: {}", e)),
                },
                "break" => {
                    if parts.len() < 2 {
                        print_warning("Usage: break <function>");
                    } else {
                        match client.set_breakpoint(parts[1]) {
                            Ok(_) => print_success(format!("Breakpoint set at {}", parts[1])),
                            Err(e) => print_warning(format!("Set breakpoint failed: {}", e)),
                        }
                    }
                }
                "clear" => {
                    if parts.len() < 2 {
                        print_warning("Usage: clear <function>");
                    } else {
                        match client.clear_breakpoint(parts[1]) {
                            Ok(_) => print_success(format!("Breakpoint cleared at {}", parts[1])),
                            Err(e) => print_warning(format!("Clear breakpoint failed: {}", e)),
                        }
                    }
                }
                "list-breaks" => match client.list_breakpoints() {
                    Ok(breaks) => {
                        if breaks.is_empty() {
                            println!("No breakpoints set");
                        } else {
                            for bp in breaks {
                                println!("- {}", bp);
                            }
                        }
                    }
                    Err(e) => print_warning(format!("List breakpoints failed: {}", e)),
                },
                "ping" => match client.ping() {
                    Ok(_) => print_success("Server is responsive"),
                    Err(e) => print_warning(format!("Ping failed: {}", e)),
                },
                "help" | "h" => {
                    println!("Remote debugger commands:");
                    println!("  load <path>          Load a contract");
                    println!("  exec <func> [args]    Execute a function");
                    println!("  step | s             Step execution");
                    println!("  continue | c          Continue execution");
                    println!("  inspect | i           Inspect current state");
                    println!("  storage               Show storage state");
                    println!("  stack                 Show call stack");
                    println!("  budget | b            Show budget usage");
                    println!("  break <func>          Set breakpoint");
                    println!("  clear <func>          Clear breakpoint");
                    println!("  list-breaks           List breakpoints");
                    println!("  ping                  Ping server");
                    println!("  help | h              Show this help");
                    println!("  quit | q              Exit");
                }
                "quit" | "q" | "exit" => {
                    let _ = client.disconnect();
                    break;
                }
                _ => {
                    print_warning(format!(
                        "Unknown command: {}. Type 'help' for available commands.",
                        parts[0]
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Start interactive REPL session for contract exploration
pub async fn repl(args: ReplArgs) -> Result<()> {
    use crate::repl::{start_repl, ReplConfig};

    print_info(format!("Loading contract: {:?}", args.contract));

    // Validate contract file exists
    if !args.contract.exists() {
        return Err(DebuggerError::WasmLoadError(format!(
            "Contract file not found: {:?}",
            args.contract
        ))
        .into());
    }

    print_success(format!("Contract loaded successfully: {:?}", args.contract));

    // Construct REPL config from arguments
    let config = ReplConfig {
        contract_path: args.contract,
        network_snapshot: args.network_snapshot,
        storage: args.storage,
    };

    // Start the REPL session
    start_repl(config).await?;

    Ok(())
}

    if let Some(output_path) = &args.output {
        fs::write(output_path, &rendered).map_err(|e| {
            DebuggerError::FileError(format!(
                "Failed to write report to {:?}: {}",
                output_path, e
            ))
        })?;
        print_success(format!("Comparison report written to: {:?}", output_path));
    } else {
        logging::log_display(rendered, logging::LogLevel::Info);
    }

    Ok(())
}

/// Execute the replay command.
pub fn replay(args: ReplayArgs, verbosity: Verbosity) -> Result<()> {
    print_info(format!("Loading trace file: {:?}", args.trace_file));
    let original_trace = crate::compare::ExecutionTrace::from_file(&args.trace_file)?;

    // Determine which contract to use
    let contract_path = if let Some(path) = &args.contract {
        path.clone()
    } else if let Some(contract_str) = &original_trace.contract {
        std::path::PathBuf::from(contract_str)
    } else {
        return Err(DebuggerError::ExecutionError(
            "No contract path specified and trace file does not contain contract path".to_string(),
        )
        .into());
    };

    print_info(format!("Loading contract: {:?}", contract_path));
    let wasm_bytes = fs::read(&contract_path).map_err(|e| {
        DebuggerError::WasmLoadError(format!(
            "Failed to read WASM file at {:?}: {}",
            contract_path, e
        ))
    })?;

    print_success(format!(
        "Contract loaded successfully ({} bytes)",
        wasm_bytes.len()
    ));

    // Extract function and args from trace
    let function = original_trace.function.as_ref().ok_or_else(|| {
        DebuggerError::ExecutionError("Trace file does not contain function name".to_string())
    })?;

    let args_str = original_trace.args.as_deref();

    // Determine how many steps to replay
    let replay_steps = args.replay_until.unwrap_or(usize::MAX);
    let is_partial_replay = args.replay_until.is_some();

    if is_partial_replay {
        print_info(format!("Replaying up to step {}", replay_steps));
    } else {
        print_info("Replaying full execution");
    }

    print_info(format!("Function: {}", function));
    if let Some(a) = args_str {
        print_info(format!("Arguments: {}", a));
    }

    // Set up initial storage from trace
    let initial_storage = if !original_trace.storage.is_empty() {
        let storage_json = serde_json::to_string(&original_trace.storage).map_err(|e| {
            DebuggerError::StorageError(format!("Failed to serialize trace storage: {}", e))
        })?;
        Some(storage_json)
    } else {
        None
    };

    // Execute the contract
    print_info("\n--- Replaying Execution ---\n");
    let mut executor = ContractExecutor::new(wasm_bytes)?;

    if let Some(storage) = initial_storage {
        executor.set_initial_storage(storage)?;
    }

    let mut engine = DebuggerEngine::new(executor, vec![]);

    logging::log_execution_start(function, args_str);
    let replayed_result = engine.execute(function, args_str)?;

    print_success("\n--- Replay Complete ---\n");
    print_success(format!("Replayed Result: {:?}", replayed_result));
    logging::log_execution_complete(&replayed_result);

    // Build execution trace from the replay
    let storage_after = engine.executor().get_storage_snapshot()?;
    let trace_events = engine.executor().get_events().unwrap_or_default();
    let budget = crate::inspector::budget::BudgetInspector::get_cpu_usage(engine.executor().host());

    let replayed_trace = build_execution_trace(
        function,
        &contract_path.to_string_lossy(),
        args_str.map(|s| s.to_string()),
        &storage_after,
        &replayed_result,
        budget,
        engine.executor(),
        &trace_events,
        replay_steps,
    );

    // Truncate original_trace's call_sequence if needed to match replay_until
    let mut truncated_original = original_trace.clone();
    if truncated_original.call_sequence.len() > replay_steps {
        truncated_original.call_sequence.truncate(replay_steps);
    }

    // Compare results
    print_info("\n--- Comparison ---");
    let report = crate::compare::CompareEngine::compare(&truncated_original, &replayed_trace);
    let rendered = crate::compare::CompareEngine::render_report(&report);

    if let Some(output_path) = &args.output {
        std::fs::write(output_path, &rendered).map_err(|e| {
            DebuggerError::FileError(format!(
                "Failed to write report to {:?}: {}",
                output_path, e
            ))
        })?;
        print_success(format!("\nReplay report written to: {:?}", output_path));
    } else {
        logging::log_display(rendered, logging::LogLevel::Info);
    }

    if verbosity == Verbosity::Verbose {
        print_verbose("\n--- Call Sequence (Original) ---");
        for (i, call) in original_trace.call_sequence.iter().enumerate() {
            let indent = "  ".repeat(call.depth as usize);
            if let Some(args) = &call.args {
                print_verbose(format!("{}{}. {} ({})", indent, i, call.function, args));
            } else {
                print_verbose(format!("{}{}. {}", indent, i, call.function));
            }

            if is_partial_replay && i >= replay_steps {
                print_verbose(format!("{}... (stopped at step {})", indent, replay_steps));
                break;
            }
        }
    }

    Ok(())
}

/// Start debug server for remote connections
pub fn server(args: ServerArgs) -> Result<()> {
    print_info(format!(
        "Starting remote debug server on port {}",
        args.port
    ));
    if let Some(token) = &args.token {
        print_info("Token authentication enabled");
        if token.trim().len() < 16 {
            print_warning(
                "Remote debug token is shorter than 16 characters. Prefer at least 16 characters \
                 and ideally a random 32-byte token.",
            );
        }
    } else {
        print_info("Token authentication disabled");
    }
    if args.tls_cert.is_some() || args.tls_key.is_some() {
        print_info("TLS enabled");
    } else if args.token.is_some() {
        print_warning(
            "Token authentication is enabled without TLS. Assume traffic is plaintext unless you \
             are using a trusted private network or external TLS termination.",
        );
    }

    let server = crate::server::DebugServer::new(
        args.token.clone(),
        args.tls_cert.as_deref(),
        args.tls_key.as_deref(),
    )?;

    tokio::runtime::Runtime::new()
        .map_err(|e: std::io::Error| miette::miette!(e))
        .and_then(|rt| rt.block_on(server.run(args.port)))
}

/// Connect to remote debug server
pub fn remote(args: RemoteArgs, _verbosity: Verbosity) -> Result<()> {
    print_info(format!("Connecting to remote debugger at {}", args.remote));
    let mut client = crate::client::RemoteClient::connect(&args.remote, args.token.clone())?;

    if let Some(contract) = &args.contract {
        print_info(format!("Loading contract: {:?}", contract));
        let size = client.load_contract(&contract.to_string_lossy())?;
        print_success(format!("Contract loaded: {} bytes", size));
    }

    if let Some(function) = &args.function {
        print_info(format!("Executing function: {}", function));
        let result = client.execute(function, args.args.as_deref())?;
        print_success(format!("Result: {}", result));
        return Ok(());
    }

    client.ping()?;
    print_success("Remote debugger is reachable");
    Ok(())
}
/// Launch interactive debugger UI
pub fn interactive(args: InteractiveArgs, _verbosity: Verbosity) -> Result<()> {
    print_info(format!("Loading contract: {:?}", args.contract));
    logging::log_loading_contract(&args.contract.to_string_lossy());

    let wasm_file = crate::utils::wasm::load_wasm(&args.contract)
        .with_context(|| format!("Failed to read WASM file: {:?}", args.contract))?;
    let wasm_bytes = wasm_file.bytes;
    let wasm_hash = wasm_file.sha256_hash;

    if let Some(expected) = &args.expected_hash {
        if expected.to_lowercase() != wasm_hash {
            return Err((crate::DebuggerError::ChecksumMismatch {
                expected: expected.clone(),
                actual: wasm_hash.clone(),
            })
            .into());
        }
    }

    print_success(format!(
        "Contract loaded successfully ({} bytes)",
        wasm_bytes.len()
    ));

    if let Some(snapshot_path) = &args.network_snapshot {
        print_info(format!("Loading network snapshot: {:?}", snapshot_path));
        logging::log_loading_snapshot(&snapshot_path.to_string_lossy());
        let loader = SnapshotLoader::from_file(snapshot_path)?;
        let loaded_snapshot = loader.apply_to_environment()?;
        logging::log_display(loaded_snapshot.format_summary(), logging::LogLevel::Info);
    }

    let parsed_args = if let Some(args_json) = &args.args {
        Some(parse_args(args_json)?)
    } else {
        None
    };

    let mut initial_storage = if let Some(storage_json) = &args.storage {
        Some(parse_storage(storage_json)?)
    } else {
        None
    };

    if let Some(import_path) = &args.import_storage {
        print_info(format!("Importing storage from: {:?}", import_path));
        let imported = crate::inspector::storage::StorageState::import_from_file(import_path)?;
        print_success(format!("Imported {} storage entries", imported.len()));
        initial_storage = Some(serde_json::to_string(&imported).map_err(|e| {
            DebuggerError::StorageError(format!("Failed to serialize imported storage: {}", e))
        })?);
    }

    let mut executor = ContractExecutor::new(wasm_bytes.clone())?;
    executor.set_timeout(args.timeout);

    if let Some(storage) = initial_storage {
        executor.set_initial_storage(storage)?;
    }
    if !args.mock.is_empty() {
        executor.set_mock_specs(&args.mock)?;
    }

    let mut engine = DebuggerEngine::new(executor, args.breakpoint.clone());

    if args.instruction_debug {
        print_info("Enabling instruction-level debugging...");
        engine.enable_instruction_debug(&wasm_bytes)?;

        if args.step_instructions {
            let step_mode = parse_step_mode(&args.step_mode);
            engine.start_instruction_stepping(step_mode)?;
        }
    }

    print_info("Starting interactive session (type 'help' for commands)");
    let mut ui = DebuggerUI::new(engine)?;
    ui.queue_execution(args.function.clone(), parsed_args);
    ui.run()
}

/// Launch TUI debugger
pub fn tui(args: TuiArgs, _verbosity: Verbosity) -> Result<()> {
    print_info(format!("Loading contract: {:?}", args.contract));
    let wasm_file = crate::utils::wasm::load_wasm(&args.contract)
        .with_context(|| format!("Failed to read WASM file: {:?}", args.contract))?;
    let wasm_bytes = wasm_file.bytes;

    print_success(format!(
        "Contract loaded successfully ({} bytes)",
        wasm_bytes.len()
    ));

    if let Some(snapshot_path) = &args.network_snapshot {
        print_info(format!("Loading network snapshot: {:?}", snapshot_path));
        logging::log_loading_snapshot(&snapshot_path.to_string_lossy());
        let loader = SnapshotLoader::from_file(snapshot_path)?;
        let loaded_snapshot = loader.apply_to_environment()?;
        logging::log_display(loaded_snapshot.format_summary(), logging::LogLevel::Info);
    }

    let parsed_args = if let Some(args_json) = &args.args {
        Some(parse_args(args_json)?)
    } else {
        None
    };

    let initial_storage = if let Some(storage_json) = &args.storage {
        Some(parse_storage(storage_json)?)
    } else {
        None
    };

    let mut executor = ContractExecutor::new(wasm_bytes.clone())?;

    if let Some(storage) = initial_storage {
        executor.set_initial_storage(storage)?;
    }

    let mut engine = DebuggerEngine::new(executor, args.breakpoint.clone());
    engine.stage_execution(&args.function, parsed_args.as_deref());

    run_dashboard(engine, &args.function)
}

/// Inspect a WASM contract
pub fn inspect(args: InspectArgs, _verbosity: Verbosity) -> Result<()> {
    let bytes = fs::read(&args.contract)
        .map_err(|e| miette::miette!("Failed to read contract {:?}: {}", args.contract, e))?;
    let info = crate::utils::wasm::get_module_info(&bytes)?;
    println!("Contract: {:?}", args.contract);
    println!("Size: {} bytes", info.total_size);
    println!("Types: {}", info.type_count);
    println!("Functions: {}", info.function_count);
    println!("Exports: {}", info.export_count);
    if args.functions {
        let sigs = crate::utils::wasm::parse_function_signatures(&bytes)?;
        println!("Exported functions:");
        for sig in &sigs {
            let params: Vec<String> = sig
                .params
                .iter()
                .map(|p| format!("{}: {}", p.name, p.type_name))
                .collect();
            let ret = sig.return_type.as_deref().unwrap_or("()");
            println!("  {}({}) -> {}", sig.name, params.join(", "), ret);
        }
    }
    Ok(())
}

/// Run symbolic execution analysis
pub fn symbolic(args: SymbolicArgs, _verbosity: Verbosity) -> Result<()> {
    print_info(format!("Loading contract: {:?}", args.contract));
    let wasm_file = crate::utils::wasm::load_wasm(&args.contract)
        .with_context(|| format!("Failed to read WASM file: {:?}", args.contract))?;

    let analyzer = SymbolicAnalyzer::new();
    let config = symbolic_config_from_args(&args);
    let report = analyzer.analyze_with_config(&wasm_file.bytes, &args.function, &config)?;

    println!("{}", render_symbolic_report(&report));

    if let Some(output_path) = &args.output {
        let scenario_toml = analyzer.generate_scenario_toml(&report);
        fs::write(output_path, scenario_toml).map_err(|e| {
            DebuggerError::FileError(format!(
                "Failed to write symbolic scenario to {:?}: {}",
                output_path, e
            ))
        })?;
        print_success(format!("Scenario TOML written to: {:?}", output_path));
    }

    Ok(())
}

/// Analyze a contract
pub fn analyze(args: AnalyzeArgs, _verbosity: Verbosity) -> Result<()> {
    print_info(format!("Loading contract: {:?}", args.contract));
    let wasm_file = crate::utils::wasm::load_wasm(&args.contract)
        .with_context(|| format!("Failed to read WASM file: {:?}", args.contract))?;

    let mut dynamic_analysis = None;
    let mut warnings = Vec::new();
    let mut executor = None;
    let mut trace_entries = None;

    if let Some(function) = &args.function {
        let mut dynamic_executor = ContractExecutor::new(wasm_file.bytes.clone())?;
        dynamic_executor.enable_mock_all_auths();
        dynamic_executor.set_timeout(args.timeout);

        if let Some(storage_json) = &args.storage {
            dynamic_executor.set_initial_storage(parse_storage(storage_json)?)?;
        }

        let parsed_args = if let Some(args_json) = &args.args {
            Some(parse_args(args_json)?)
        } else {
            None
        };

        match dynamic_executor.execute(function, parsed_args.as_deref()) {
            Ok(result) => {
                let trace = dynamic_executor.get_dynamic_trace().unwrap_or_default();

                dynamic_analysis = Some(DynamicAnalysisMetadata {
                    function: function.clone(),
                    args: parsed_args.clone(),
                    result: Some(result),
                    trace_entries: trace.len(),
                });
                trace_entries = Some(trace);
                executor = Some(dynamic_executor);
            }
            Err(err) => {
                warnings.push(format!(
                    "Dynamic analysis for function '{}' failed: {}",
                    function, err
                ));
            }
        }
    }

    let analyzer = SecurityAnalyzer::new();
    let report = analyzer.analyze(
        &wasm_file.bytes,
        executor.as_ref(),
        trace_entries.as_deref(),
    )?;
    let output = AnalyzeCommandOutput {
        findings: report.findings,
        dynamic_analysis,
        warnings,
    };

    match args.format.to_lowercase().as_str() {
        "text" => println!("{}", render_security_report(&output)),
        "json" => println!(
            "{}",
            serde_json::to_string_pretty(&output).map_err(|e| {
                DebuggerError::FileError(format!("Failed to serialize analysis output: {}", e))
            })?
        ),
        other => {
            return Err(DebuggerError::InvalidArguments(format!(
                "Unsupported --format '{}'. Use 'text' or 'json'.",
                other
            ))
            .into());
        }
    }

    Ok(())
}

/// Run a scenario
pub fn scenario(args: ScenarioArgs, _verbosity: Verbosity) -> Result<()> {
    crate::scenario::run_scenario(args, _verbosity)
}

/// Launch the REPL
pub async fn repl(args: ReplArgs) -> Result<()> {
    print_info(format!("Loading contract: {:?}", args.contract));
    let wasm_file = crate::utils::wasm::load_wasm(&args.contract)
        .with_context(|| format!("Failed to read WASM file: {:?}", args.contract))?;
    crate::utils::wasm::verify_wasm_hash(&wasm_file.sha256_hash, args.expected_hash.as_ref())?;

    if args.expected_hash.is_some() {
        print_verbose("Checksum verified âœ“");
    }

    crate::repl::start_repl(ReplConfig {
        contract_path: args.contract,
        network_snapshot: args.network_snapshot,
        storage: args.storage,
    })
    .await
}

/// Show budget trend chart
pub fn show_budget_trend(
    contract: Option<&str>,
    function: Option<&str>,
    regression: crate::history::RegressionConfig,
) -> Result<()> {
    let manager = HistoryManager::new()?;
    let mut records = manager.filter_history(contract, function)?;

    crate::history::sort_records_by_date(&mut records);

    if records.is_empty() {
        if !Formatter::is_quiet() {
            println!("Budget Trend");
            println!(
                "Filters: contract={} function={}",
                contract.unwrap_or("*"),
                function.unwrap_or("*")
            );
            println!("No run history found yet.");
            println!("Tip: run `soroban-debug run ...` a few times to generate history.");
        }
        return Ok(());
    }

    let stats = budget_trend_stats_or_err(&records)?;
    let cpu_values: Vec<u64> = records.iter().map(|r| r.cpu_used).collect();
    let mem_values: Vec<u64> = records.iter().map(|r| r.memory_used).collect();

    if !Formatter::is_quiet() {
        println!("Budget Trend");
        println!(
            "Filters: contract={} function={}",
            contract.unwrap_or("*"),
            function.unwrap_or("*")
        );
        println!(
            "Regression params: threshold>{:.1}% lookback={} smoothing={}",
            regression.threshold_pct, regression.lookback, regression.smoothing_window
        );
        println!("Runs: {}   Range: {} -> {}", stats.count, stats.first_date, stats.last_date);
        println!(
            "CPU insns: last={}  avg={}  min={}  max={}",
            crate::inspector::budget::BudgetInspector::format_cpu_insns(stats.last_cpu),
            crate::inspector::budget::BudgetInspector::format_cpu_insns(stats.cpu_avg),
            crate::inspector::budget::BudgetInspector::format_cpu_insns(stats.cpu_min),
            crate::inspector::budget::BudgetInspector::format_cpu_insns(stats.cpu_max)
        );
        println!(
            "Mem bytes: last={}  avg={}  min={}  max={}",
            crate::inspector::budget::BudgetInspector::format_memory_bytes(stats.last_mem),
            crate::inspector::budget::BudgetInspector::format_memory_bytes(stats.mem_avg),
            crate::inspector::budget::BudgetInspector::format_memory_bytes(stats.mem_min),
            crate::inspector::budget::BudgetInspector::format_memory_bytes(stats.mem_max)
        );
        println!();
        println!("CPU trend: {}", Formatter::sparkline(&cpu_values, 50));
        println!("MEM trend: {}", Formatter::sparkline(&mem_values, 50));

        if let Some((cpu_reg, mem_reg)) =
            crate::history::check_regression_with_config(&records, &regression)
        {
            if cpu_reg > 0.0 || mem_reg > 0.0 {
                println!();
                println!("Regression warning (latest vs baseline):");
                if cpu_reg > 0.0 {
                    println!("  CPU increased by {:.1}%", cpu_reg);
                }
                if mem_reg > 0.0 {
                    println!("  Memory increased by {:.1}%", mem_reg);
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_trend_stats_or_err_returns_error_instead_of_panicking() {
        let empty: Vec<RunHistory> = Vec::new();
        let err = budget_trend_stats_or_err(&empty).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Failed to compute budget trend statistics"));
    }
}
