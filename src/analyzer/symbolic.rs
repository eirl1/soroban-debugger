use crate::runtime::executor::ContractExecutor;
use crate::utils::wasm::{parse_function_signatures, ContractFunctionSignature};
use crate::{DebuggerError, Result};
use serde::Serialize;
use std::cmp;
use std::collections::HashSet;
use std::fmt::Write;
use std::time::Instant;
use wasmparser::{Parser, Payload};

#[derive(Debug, Clone, Serialize)]
pub struct PathResult {
    pub inputs: String, // json array of args
    pub return_value: Option<String>,
    pub panic: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymbolicReport {
    pub function: String,
    pub paths_explored: usize,
    pub panics_found: usize,
    pub paths: Vec<PathResult>,
    pub metadata: SymbolicReportMetadata,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SymbolicConfig {
    pub max_paths: usize,
    pub max_input_combinations: usize,
    pub timeout_secs: u64,
    pub max_breadth: usize,
    pub max_depth: usize,
}

impl Default for SymbolicConfig {
    fn default() -> Self {
        Self::balanced()
    }
}

impl SymbolicConfig {
    pub const fn balanced() -> Self {
        Self {
            max_paths: 100,
            max_input_combinations: 256,
            timeout_secs: 30,
            max_breadth: 5,
            max_depth: 3,
        }
    }
    pub const fn fast() -> Self {
        Self {
            max_paths: 25,
            max_input_combinations: 64,
            timeout_secs: 5,
            max_breadth: 3,
            max_depth: 2,
        }
    }

    pub fn default_balanced() -> Self {
        Self::default()
    }

    pub const fn deep() -> Self {
        Self {
            max_paths: 500,
            max_input_combinations: 2048,
            timeout_secs: 120,
            max_breadth: 8,
            max_depth: 5,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SymbolicReportMetadata {
    pub config: SymbolicConfig,
    pub generated_input_combinations: usize,
    pub attempted_input_combinations: usize,
    pub distinct_paths_recorded: usize,
    pub truncated_by_input_cap: bool,
    pub truncated_by_path_cap: bool,
    pub truncated_by_timeout: bool,
    pub truncation_reasons: Vec<String>,
}

#[derive(Debug, Clone)]
struct GeneratedInputs {
    combinations: Vec<String>,
    truncated_by_input_cap: bool,
}

#[derive(Default)]
pub struct SymbolicAnalyzer;

impl SymbolicAnalyzer {
    pub fn new() -> Self {
        Self
    }

    fn record_outcome(
        report: &mut SymbolicReport,
        seen_inputs: &mut HashSet<String>,
        inputs: &str,
        outcome: std::result::Result<String, String>,
    ) {
        // Keep distinct paths even when outputs/errors are identical.
        // Only dedupe when the exact same input set is re-encountered.
        if !seen_inputs.insert(inputs.to_string()) {
            return;
        }

        match outcome {
            Ok(val) => report.paths.push(PathResult {
                inputs: inputs.to_string(),
                return_value: Some(val),
                panic: None,
            }),
            Err(err_str) => {
                report.panics_found += 1;
                report.paths.push(PathResult {
                    inputs: inputs.to_string(),
                    return_value: None,
                    panic: Some(err_str),
                });
            }
        }
    }

    pub fn analyze(&self, wasm: &[u8], function: &str) -> Result<SymbolicReport> {
        self.analyze_with_config(wasm, function, &SymbolicConfig::default())
    }

    pub fn analyze_with_config(
        &self,
        wasm: &[u8],
        function: &str,
        config: &SymbolicConfig,
    ) -> Result<SymbolicReport> {
        let signatures = parse_function_signatures(wasm).unwrap_or_default();
        let target_sig = signatures.into_iter().find(|s| s.name == function);

        let generated_inputs = if let Some(sig) = target_sig {
            self.generate_type_aware_inputs(&sig, config)
        } else {
            let arg_count = self.get_arg_count(wasm, function).unwrap_or(0);
            self.generate_input_combinations(arg_count, config.max_input_combinations)
        };
        let deadline = Instant::now();

        let mut report = SymbolicReport {
            function: function.to_string(),
            paths_explored: 0,
            panics_found: 0,
            paths: Vec::new(),
            metadata: SymbolicReportMetadata {
                config: config.clone(),
                generated_input_combinations: generated_inputs.combinations.len(),
                attempted_input_combinations: 0,
                distinct_paths_recorded: 0,
                truncated_by_input_cap: generated_inputs.truncated_by_input_cap,
                truncated_by_path_cap: false,
                truncated_by_timeout: false,
                truncation_reasons: Vec::new(),
            },
        };

        let mut seen_inputs = HashSet::new();

        for args_json in &generated_inputs.combinations {
            if report.paths_explored >= config.max_paths {
                report.metadata.truncated_by_path_cap = true;
                break;
            }

            if config.timeout_secs > 0 && deadline.elapsed().as_secs() >= config.timeout_secs {
                report.metadata.truncated_by_timeout = true;
                break;
            }

            let executor_res = std::panic::catch_unwind(|| {
                if let Ok(mut executor) = ContractExecutor::new(wasm.to_vec()) {
                    executor.set_timeout(config.timeout_secs);
                    executor.execute(function, Some(args_json))
                } else {
                    Err(crate::DebuggerError::ExecutionError("Init fail".into()).into())
                }
            });

            match executor_res {
                Ok(Ok(val)) => {
                    Self::record_outcome(&mut report, &mut seen_inputs, args_json, Ok(val));
                }
                Ok(Err(err)) => {
                    Self::record_outcome(
                        &mut report,
                        &mut seen_inputs,
                        args_json,
                        Err(err.to_string()),
                    );
                }
                Err(_) => {
                    Self::record_outcome(
                        &mut report,
                        &mut seen_inputs,
                        args_json,
                        Err("Host Panic".to_string()),
                    );
                }
            }
            report.paths_explored += 1;
        }

        report.metadata.attempted_input_combinations = report.paths_explored;
        report.metadata.distinct_paths_recorded = report.paths.len();
        if report.metadata.truncated_by_input_cap {
            report.metadata.truncation_reasons.push(format!(
                "input combination cap reached at {} generated combinations",
                config.max_input_combinations
            ));
        }
        if report.metadata.truncated_by_path_cap {
            report.metadata.truncation_reasons.push(format!(
                "path exploration cap reached at {} attempted inputs",
                config.max_paths
            ));
        }
        if report.metadata.truncated_by_timeout {
            report.metadata.truncation_reasons.push(format!(
                "symbolic analysis timed out after {} seconds",
                config.timeout_secs
            ));
        }

        Ok(report)
    }

    fn get_arg_count(&self, wasm: &[u8], target: &str) -> Result<usize> {
        let parser = Parser::new(0);
        let mut type_definitions = Vec::new();
        let mut function_types = Vec::new();
        let mut exports = Vec::new();
        let mut imported_func_count: u32 = 0;

        for payload in parser.parse_all(wasm) {
            match payload
                .map_err(|e| DebuggerError::WasmLoadError(format!("Failed to parse WASM: {}", e)))?
            {
                Payload::ImportSection(reader) => {
                    for import in reader {
                        let import = import.map_err(|e| {
                            DebuggerError::WasmLoadError(format!(
                                "Failed to read import section: {}",
                                e
                            ))
                        })?;
                        if matches!(import.ty, wasmparser::TypeRef::Func(_)) {
                            imported_func_count += 1;
                        }
                    }
                }
                Payload::TypeSection(reader) => {
                    for rec_group in reader {
                        let rec_group = rec_group.map_err(|e| {
                            DebuggerError::WasmLoadError(format!(
                                "Failed to read type section: {}",
                                e
                            ))
                        })?;
                        for ty in rec_group.types() {
                            if let wasmparser::CompositeType::Func(func_type) = &ty.composite_type {
                                type_definitions.push(func_type.clone());
                            }
                        }
                    }
                }
                Payload::FunctionSection(reader) => {
                    for type_idx in reader {
                        function_types.push(type_idx.map_err(|e| {
                            DebuggerError::WasmLoadError(format!(
                                "Failed to read function section: {}",
                                e
                            ))
                        })?);
                    }
                }
                Payload::ExportSection(reader) => {
                    for export in reader {
                        let export = export.map_err(|e| {
                            DebuggerError::WasmLoadError(format!(
                                "Failed to read export section: {}",
                                e
                            ))
                        })?;
                        if let wasmparser::ExternalKind::Func = export.kind {
                            exports.push((export.name.to_string(), export.index));
                        }
                    }
                }
                _ => {}
            }
        }

        for (name, func_idx) in exports {
            if name == target {
                if func_idx < imported_func_count {
                    continue;
                }
                let local_idx = (func_idx - imported_func_count) as usize;
                if let Some(&type_idx) = function_types.get(local_idx) {
                    if let Some(func_type) = type_definitions.get(type_idx as usize) {
                        return Ok(func_type.params().len());
                    }
                }
            }
        }

        Err(
            DebuggerError::InvalidFunction(format!("Function '{}' not found in exports", target))
                .into(),
        )
    }

    fn generate_type_aware_inputs(
        &self,
        sig: &ContractFunctionSignature,
        config: &SymbolicConfig,
    ) -> GeneratedInputs {
        let mut parameter_seeds = Vec::new();

        for param in &sig.params {
            let seeds = self.generate_seeds_for_type(&param.type_name, config, 0);
            parameter_seeds.push(seeds);
        }

        if parameter_seeds.is_empty() {
            return GeneratedInputs {
                combinations: vec!["[]".to_string()],
                truncated_by_input_cap: false,
            };
        }

        let mut combinations = Vec::new();
        let mut indices = vec![0; parameter_seeds.len()];
        let mut truncated = false;

        loop {
            let mut args = Vec::new();
            for (i, p_idx) in indices.iter().enumerate() {
                args.push(parameter_seeds[i][*p_idx].clone());
            }
            combinations.push(format!("[{}]", args.join(", ")));

            if combinations.len() >= config.max_input_combinations {
                truncated = true;
                break;
            }

            let mut carry = true;
            for i in (0..indices.len()).rev() {
                if indices[i] + 1 < parameter_seeds[i].len() {
                    indices[i] += 1;
                    for item in indices.iter_mut().skip(i + 1) {
                        *item = 0;
                    }
                    carry = false;
                    break;
                }
            }

            if carry {
                break;
            }
        }

        GeneratedInputs {
            combinations,
            truncated_by_input_cap: truncated,
        }
    }

    fn generate_seeds_for_type(
        &self,
        type_name: &str,
        config: &SymbolicConfig,
        depth: usize,
    ) -> Vec<String> {
        if depth > config.max_depth {
            return vec!["null".to_string()];
        }

        let limit = config.max_breadth;

        match type_name {
            "U32" | "I32" | "U64" | "I64" | "U128" | "I128" | "Val" => {
                let base = ["0", "1", "-1", "42", "2147483647", "-2147483648", "1000000"];
                base.into_iter()
                    .take(limit)
                    .map(|s| s.to_string())
                    .collect()
            }
            "Bool" => vec!["true".to_string(), "false".to_string()],
            "Void" => vec!["null".to_string()],
            "String" | "Symbol" => {
                let base = [
                    "\"\"",
                    "\"a\"",
                    "\"hello\"",
                    "\"long_string_example\"",
                    "\"#!*\"",
                ];
                base.into_iter()
                    .take(limit)
                    .map(|s| s.to_string())
                    .collect()
            }
            "Address" => {
                let base = [
                    "\"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF\"",
                    "\"CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB4H\"",
                    "\"GD5DJ3B6A2KHSXLYJZ3IGR7Q5UMVJ5J4GQTKTQYQDQXJQJ5YQZQKQZQ\"",
                ];
                base.into_iter()
                    .take(limit)
                    .map(|s| s.to_string())
                    .collect()
            }
            "Bytes" | "BytesN" => {
                let base = ["\"0x\"", "\"0x00\"", "\"0xffffffff\"", "\"base64:AQID\""];
                base.into_iter()
                    .take(limit)
                    .map(|s| s.to_string())
                    .collect()
            }
            t if t.starts_with("Option<") => {
                let inner = &t[7..t.len() - 1];
                let mut seeds = vec!["null".to_string()];
                seeds.extend(self.generate_seeds_for_type(inner, config, depth + 1));
                seeds.into_iter().take(limit).collect()
            }
            t if t.starts_with("Vec<") => {
                let inner = &t[4..t.len() - 1];
                let inner_seeds = self.generate_seeds_for_type(inner, config, depth + 1);
                let mut seeds = vec!["[]".to_string()];
                if !inner_seeds.is_empty() {
                    seeds.push(format!("[{}]", inner_seeds[0]));
                    if inner_seeds.len() > 1 {
                        seeds.push(format!("[{}, {}]", inner_seeds[0], inner_seeds[1]));
                    }
                }
                seeds.into_iter().take(limit).collect()
            }
            t if t.starts_with("Map<") => {
                // Simplified Map generation: focus on empty and single entry
                vec!["{}".to_string()]
            }
            t if t.starts_with("Tuple<") => {
                let inner_part = &t[6..t.len() - 1];
                let parts: Vec<&str> = inner_part.split(',').map(|s| s.trim()).collect();
                let mut tuple_elements = Vec::new();
                for part in parts {
                    let s = self.generate_seeds_for_type(part, config, depth + 1);
                    tuple_elements.push(s.first().cloned().unwrap_or("null".to_string()));
                }
                vec![format!("[{}]", tuple_elements.join(", "))]
            }
            _ => vec!["0".to_string()], // Fallback for UDTs or unknown types
        }
    }

    fn generate_input_combinations(&self, arg_count: usize, max_cases: usize) -> GeneratedInputs {
        let numeric_seeds = ["0", "1", "-1", "42", "2147483647", "-2147483648"];

        if max_cases == 0 {
            return GeneratedInputs {
                combinations: Vec::new(),
                truncated_by_input_cap: true,
            };
        }

        let mut combinations = Vec::new();
        if arg_count == 0 {
            combinations.push("[]".to_string());
            return GeneratedInputs {
                combinations,
                truncated_by_input_cap: false,
            };
        }

        let narrowed = &numeric_seeds[..cmp::min(numeric_seeds.len(), 4)];
        let mut current = vec![0usize; arg_count];
        loop {
            let args = current
                .iter()
                .map(|&idx| narrowed[idx])
                .collect::<Vec<_>>()
                .join(", ");
            combinations.push(format!("[{}]", args));

            if combinations.len() >= max_cases {
                return GeneratedInputs {
                    combinations,
                    truncated_by_input_cap: true,
                };
            }

            let mut carry = true;
            for pos in (0..arg_count).rev() {
                if current[pos] + 1 < narrowed.len() {
                    current[pos] += 1;
                    for slot in current.iter_mut().skip(pos + 1) {
                        *slot = 0;
                    }
                    carry = false;
                    break;
                }
            }
            if carry {
                break;
            }
        }
        GeneratedInputs {
            combinations,
            truncated_by_input_cap: false,
        }
    }

    pub fn generate_scenario_toml(&self, report: &SymbolicReport) -> String {
        let mut toml = String::new();
        writeln!(toml, "# Generated Symbolic Execution Scenarios").unwrap();
        writeln!(toml, "function = {}", toml_basic_string(&report.function)).unwrap();
        writeln!(toml, "paths_explored = {}", report.paths_explored).unwrap();
        writeln!(toml, "panics_found = {}\n", report.panics_found).unwrap();
        writeln!(toml, "[metadata]").unwrap();
        writeln!(toml, "max_paths = {}", report.metadata.config.max_paths).unwrap();
        writeln!(
            toml,
            "max_input_combinations = {}",
            report.metadata.config.max_input_combinations
        )
        .unwrap();
        writeln!(
            toml,
            "timeout_secs = {}",
            report.metadata.config.timeout_secs
        )
        .unwrap();
        writeln!(
            toml,
            "generated_input_combinations = {}",
            report.metadata.generated_input_combinations
        )
        .unwrap();
        writeln!(
            toml,
            "attempted_input_combinations = {}",
            report.metadata.attempted_input_combinations
        )
        .unwrap();
        writeln!(
            toml,
            "distinct_paths_recorded = {}",
            report.metadata.distinct_paths_recorded
        )
        .unwrap();
        writeln!(
            toml,
            "truncated_by_input_cap = {}",
            report.metadata.truncated_by_input_cap
        )
        .unwrap();
        writeln!(
            toml,
            "truncated_by_path_cap = {}",
            report.metadata.truncated_by_path_cap
        )
        .unwrap();
        writeln!(
            toml,
            "truncated_by_timeout = {}",
            report.metadata.truncated_by_timeout
        )
        .unwrap();
        if !report.metadata.truncation_reasons.is_empty() {
            writeln!(toml, "truncation_reasons = [").unwrap();
            for reason in &report.metadata.truncation_reasons {
                writeln!(toml, "  {},", toml_basic_string(reason)).unwrap();
            }
            writeln!(toml, "]").unwrap();
        }
        writeln!(toml).unwrap();

        for (i, path) in report.paths.iter().enumerate() {
            writeln!(toml, "[[scenario]]").unwrap();
            writeln!(toml, "id = {}", i).unwrap();
            writeln!(toml, "inputs = {}", toml_basic_string(&path.inputs)).unwrap();

            if let Some(ref val) = path.return_value {
                writeln!(toml, "expected_return = {}", toml_basic_string(val)).unwrap();
            }
            if let Some(ref panic) = path.panic {
                writeln!(toml, "panic = {}", toml_basic_string(panic)).unwrap();
            }
            writeln!(toml).unwrap();
        }

        toml
    }
}

fn toml_basic_string(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t");
    format!("\"{}\"", escaped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::wasm::FunctionParam;

    fn push_u32_leb(mut value: u32, out: &mut Vec<u8>) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    fn push_name(name: &str, out: &mut Vec<u8>) {
        push_u32_leb(name.len() as u32, out);
        out.extend_from_slice(name.as_bytes());
    }

    fn append_section(module: &mut Vec<u8>, section_id: u8, section_data: &[u8]) {
        module.push(section_id);
        push_u32_leb(section_data.len() as u32, module);
        module.extend_from_slice(section_data);
    }

    fn wasm_with_import_and_exported_local() -> Vec<u8> {
        let mut module = Vec::new();
        module.extend_from_slice(&[0x00, 0x61, 0x73, 0x6d]);
        module.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);

        // Type section: type 0 = () -> (), type 1 = (i64, i64) -> ()
        let mut types = Vec::new();
        push_u32_leb(2, &mut types);
        types.push(0x60);
        push_u32_leb(0, &mut types);
        push_u32_leb(0, &mut types);
        types.push(0x60);
        push_u32_leb(2, &mut types);
        types.push(0x7e);
        types.push(0x7e);
        push_u32_leb(0, &mut types);
        append_section(&mut module, 1, &types);

        // Import section: one imported function using type 0
        let mut imports = Vec::new();
        push_u32_leb(1, &mut imports);
        push_name("env", &mut imports);
        push_name("imported", &mut imports);
        imports.push(0x00);
        push_u32_leb(0, &mut imports);
        append_section(&mut module, 2, &imports);

        // Function section: one local function using type 1
        let mut functions = Vec::new();
        push_u32_leb(1, &mut functions);
        push_u32_leb(1, &mut functions);
        append_section(&mut module, 3, &functions);

        // Export section: export local function at global index 1
        let mut exports = Vec::new();
        push_u32_leb(1, &mut exports);
        push_name("entry", &mut exports);
        exports.push(0x00);
        push_u32_leb(1, &mut exports);
        append_section(&mut module, 7, &exports);

        // Code section: one empty function body
        let mut code = Vec::new();
        push_u32_leb(1, &mut code);
        let body = vec![0x00, 0x0b];
        push_u32_leb(body.len() as u32, &mut code);
        code.extend_from_slice(&body);
        append_section(&mut module, 10, &code);

        module
    }

    #[test]
    fn distinct_inputs_with_same_output_are_not_deduped() {
        let mut report = SymbolicReport {
            function: "f".to_string(),
            paths_explored: 0,
            panics_found: 0,
            paths: Vec::new(),
            metadata: SymbolicReportMetadata {
                config: SymbolicConfig::default(),
                generated_input_combinations: 0,
                attempted_input_combinations: 0,
                distinct_paths_recorded: 0,
                truncated_by_input_cap: false,
                truncated_by_path_cap: false,
                truncated_by_timeout: false,
                truncation_reasons: Vec::new(),
            },
        };
        let mut seen_inputs = HashSet::new();

        SymbolicAnalyzer::record_outcome(&mut report, &mut seen_inputs, "[0]", Ok("1".into()));
        SymbolicAnalyzer::record_outcome(&mut report, &mut seen_inputs, "[1]", Ok("1".into()));

        assert_eq!(report.paths.len(), 2);
        assert_eq!(report.panics_found, 0);
        assert_eq!(report.paths[0].return_value.as_deref(), Some("1"));
        assert_eq!(report.paths[1].return_value.as_deref(), Some("1"));
    }

    #[test]
    fn identical_inputs_are_deduped() {
        let mut report = SymbolicReport {
            function: "f".to_string(),
            paths_explored: 0,
            panics_found: 0,
            paths: Vec::new(),
            metadata: SymbolicReportMetadata {
                config: SymbolicConfig::default(),
                generated_input_combinations: 0,
                attempted_input_combinations: 0,
                distinct_paths_recorded: 0,
                truncated_by_input_cap: false,
                truncated_by_path_cap: false,
                truncated_by_timeout: false,
                truncation_reasons: Vec::new(),
            },
        };
        let mut seen_inputs = HashSet::new();

        SymbolicAnalyzer::record_outcome(&mut report, &mut seen_inputs, "[0]", Ok("1".into()));
        SymbolicAnalyzer::record_outcome(&mut report, &mut seen_inputs, "[0]", Ok("1".into()));

        assert_eq!(report.paths.len(), 1);
    }

    #[test]
    fn get_arg_count_accounts_for_imported_function_offset() {
        let wasm = wasm_with_import_and_exported_local();
        let analyzer = SymbolicAnalyzer::new();

        let arg_count = analyzer
            .get_arg_count(&wasm, "entry")
            .expect("entry export should resolve");

        assert_eq!(arg_count, 2);
    }

    #[test]
    fn generate_input_combinations_marks_truncation_when_cap_hit() {
        let analyzer = SymbolicAnalyzer::new();

        let generated = analyzer.generate_input_combinations(2, 5);

        assert_eq!(generated.combinations.len(), 5);
        assert!(generated.truncated_by_input_cap);
    }

    #[test]
    fn analyze_with_config_records_path_cap_metadata() {
        let analyzer = SymbolicAnalyzer::new();
        let wasm = wasm_with_import_and_exported_local();
        let config = SymbolicConfig {
            max_paths: 3,
            max_input_combinations: 16,
            timeout_secs: 30,
            max_breadth: 5,
            max_depth: 3,
        };

        let report = analyzer
            .analyze_with_config(&wasm, "entry", &config)
            .expect("symbolic analysis should complete");

        assert_eq!(report.paths_explored, 3);
        assert!(report.metadata.truncated_by_path_cap);
        assert_eq!(report.metadata.generated_input_combinations, 16);
        assert_eq!(report.metadata.attempted_input_combinations, 3);
    }

    #[test]
    fn generate_scenario_toml_includes_metadata_block() {
        let analyzer = SymbolicAnalyzer::new();
        let report = SymbolicReport {
            function: "f".to_string(),
            paths_explored: 1,
            panics_found: 0,
            paths: vec![PathResult {
                inputs: "[0]".to_string(),
                return_value: Some("1".to_string()),
                panic: None,
            }],
            metadata: SymbolicReportMetadata {
                config: SymbolicConfig::fast(),
                generated_input_combinations: 10,
                attempted_input_combinations: 1,
                distinct_paths_recorded: 1,
                truncated_by_input_cap: true,
                truncated_by_path_cap: false,
                truncated_by_timeout: false,
                truncation_reasons: vec![
                    "input combination cap reached at 64 generated combinations".to_string(),
                ],
            },
        };

        let toml = analyzer.generate_scenario_toml(&report);
        assert!(toml.contains("[metadata]"));
        assert!(toml.contains("max_paths = 25"));
        assert!(toml.contains("truncated_by_input_cap = true"));
    }

    #[test]
    fn test_generate_seeds_for_primitive_types() {
        let analyzer = SymbolicAnalyzer::new();
        let config = SymbolicConfig::fast();

        let u32_seeds = analyzer.generate_seeds_for_type("U32", &config, 0);
        assert_eq!(u32_seeds, vec!["0", "1", "-1"]); // max_breadth = 3 in fast config

        let bool_seeds = analyzer.generate_seeds_for_type("Bool", &config, 0);
        assert_eq!(bool_seeds, vec!["true", "false"]);
    }

    #[test]
    fn test_generate_seeds_for_option_type() {
        let analyzer = SymbolicAnalyzer::new();
        let config = SymbolicConfig::fast();

        let option_seeds = analyzer.generate_seeds_for_type("Option<U32>", &config, 0);
        assert_eq!(option_seeds, vec!["null", "0", "1"]); // limit = 3
    }

    #[test]
    #[ignore = "Stubbed until inferno dependency is resolved"]
    fn test_flame_graph_generation_from_report() {
        let analyzer = SymbolicAnalyzer::new();
        let config = SymbolicConfig::fast();
    }

    #[test]
    fn test_generate_seeds_for_vec_type() {
        let analyzer = SymbolicAnalyzer::new();
        let config = SymbolicConfig::fast();

        let vec_seeds = analyzer.generate_seeds_for_type("Vec<U32>", &config, 0);
        assert!(vec_seeds.contains(&"[]".to_string()));
        assert!(vec_seeds.contains(&"[0]".to_string()));
    }

    #[test]
    fn test_generate_type_aware_inputs_combines_correctly() {
        let analyzer = SymbolicAnalyzer::new();
        let config = SymbolicConfig::fast();
        let sig = ContractFunctionSignature {
            name: "test".to_string(),
            params: vec![
                FunctionParam {
                    name: "a".to_string(),
                    type_name: "Bool".to_string(),
                },
                FunctionParam {
                    name: "b".to_string(),
                    type_name: "Void".to_string(),
                },
            ],
            return_type: None,
        };

        let generated = analyzer.generate_type_aware_inputs(&sig, &config);
        assert_eq!(generated.combinations.len(), 2);
        assert!(generated.combinations.contains(&"[true, null]".to_string()));
        assert!(generated
            .combinations
            .contains(&"[false, null]".to_string()));
    }
}
