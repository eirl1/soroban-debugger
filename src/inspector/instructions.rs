use crate::inspector::budget::BudgetInspector;
use serde::{Deserialize, Serialize};
use soroban_env_host::Host;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionInstructionCount {
    pub function_name: String,
    pub instruction_count: u64,
    pub call_count: u32,
}

#[derive(Debug, Clone)]
pub struct InstructionCounter {
    function_counts: HashMap<String, FunctionInstructionCount>,
    function_stack: Vec<(String, u64)>,
}

impl InstructionCounter {
    pub fn new() -> Self {
        Self {
            function_counts: HashMap::new(),
            function_stack: Vec::new(),
        }
    }

    pub fn start_function(&mut self, function_name: &str, host: &Host) {
        let budget = BudgetInspector::get_cpu_usage(host);
        self.function_stack
            .push((function_name.to_string(), budget.cpu_instructions));
    }

    pub fn end_function(&mut self, host: &Host) {
        if let Some((function_name, start_instructions)) = self.function_stack.pop() {
            let budget = BudgetInspector::get_cpu_usage(host);
            let end_instructions = budget.cpu_instructions;
            let instruction_delta = end_instructions.saturating_sub(start_instructions);

            let count = self
                .function_counts
                .entry(function_name.clone())
                .or_insert_with(|| FunctionInstructionCount {
                    function_name: function_name.clone(),
                    instruction_count: 0,
                    call_count: 0,
                });

            count.instruction_count = count.instruction_count.saturating_add(instruction_delta);
            count.call_count += 1;
        }
    }

    pub fn get_counts(&self) -> Vec<FunctionInstructionCount> {
        let mut counts: Vec<FunctionInstructionCount> =
            self.function_counts.values().cloned().collect();
        counts.sort_by_key(|b| std::cmp::Reverse(b.instruction_count));
        counts
    }

    pub fn get_total_instructions(&self) -> u64 {
        self.function_counts
            .values()
            .map(|c| c.instruction_count)
            .sum()
    }

    pub fn display(&self) {
        let counts = self.get_counts();

        if counts.is_empty() {
            crate::logging::log_display(
                "\n=== Instruction Counts ===",
                crate::logging::LogLevel::Info,
            );
            crate::logging::log_display(
                "No function calls recorded.",
                crate::logging::LogLevel::Info,
            );
            return;
        }

        crate::logging::log_display(
            "\n=== Instruction Counts per Function ===",
            crate::logging::LogLevel::Info,
        );
        crate::logging::log_display(
            format!("{:<30} {:>15} {:>10}", "Function", "Instructions", "Calls"),
            crate::logging::LogLevel::Info,
        );
        crate::logging::log_display("-".repeat(60), crate::logging::LogLevel::Info);

        for count in &counts {
            crate::logging::log_display(
                format!(
                    "{:<30} {:>15} {:>10}",
                    count.function_name, count.instruction_count, count.call_count
                ),
                crate::logging::LogLevel::Info,
            );
        }

        let total = self.get_total_instructions();
        crate::logging::log_display("-".repeat(60), crate::logging::LogLevel::Info);
        crate::logging::log_display(
            format!("{:<30} {:>15}", "Total", total),
            crate::logging::LogLevel::Info,
        );
        crate::logging::log_display("", crate::logging::LogLevel::Info);
    }
}

impl Default for InstructionCounter {
    fn default() -> Self {
        Self::new()
    }
}
