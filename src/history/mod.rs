use crate::{DebuggerError, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunHistory {
    pub date: String,
    pub contract_hash: String,
    pub function: String,
    pub cpu_used: u64,
    pub memory_used: u64,
}

pub struct HistoryManager {
    file_path: PathBuf,
}

impl HistoryManager {
    /// Create a new HistoryManager using the default `~/.soroban-debug/history.json` path.
    pub fn new() -> Result<Self> {
        let home_dir = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map_err(|_| {
                DebuggerError::FileError("Could not determine home directory".to_string())
            })?;
        let debug_dir = PathBuf::from(home_dir).join(".soroban-debug");
        if !debug_dir.exists() {
            fs::create_dir_all(&debug_dir).map_err(|e| {
                DebuggerError::FileError(format!(
                    "Failed to create debug directory {:?}: {}",
                    debug_dir, e
                ))
            })?;
        }
        Ok(Self {
            file_path: debug_dir.join("history.json"),
        })
    }

    /// Create a new HistoryManager overriding the base path (for tests).
    pub fn with_path(path: PathBuf) -> Self {
        Self { file_path: path }
    }

    /// Read historical data using highly optimized BufReader.
    pub fn load_history(&self) -> Result<Vec<RunHistory>> {
        if !self.file_path.exists() {
            return Ok(Vec::new());
        }
        let file = File::open(&self.file_path).map_err(|e| {
            DebuggerError::FileError(format!(
                "Failed to open history file {:?}: {}",
                self.file_path, e
            ))
        })?;
        let reader = BufReader::new(file);
        let history: Vec<RunHistory> =
            serde_json::from_reader(reader).unwrap_or_else(|_| Vec::new());
        Ok(history)
    }

    /// Append a new record optimizing with BufWriter.
    pub fn append_record(&self, record: RunHistory) -> Result<()> {
        let mut history = self.load_history()?;
        history.push(record);
        let file = File::create(&self.file_path).map_err(|e| {
            DebuggerError::FileError(format!(
                "Failed to create history file {:?}: {}",
                self.file_path, e
            ))
        })?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, &history).map_err(|e| {
            DebuggerError::FileError(format!(
                "Failed to write history file {:?}: {}",
                self.file_path, e
            ))
        })?;
        Ok(())
    }

    /// Filter historical data based on optional parameters.
    pub fn filter_history(
        &self,
        contract_hash: Option<&str>,
        function: Option<&str>,
    ) -> Result<Vec<RunHistory>> {
        let history = self.load_history()?;
        let filtered = history
            .into_iter()
            .filter(|r| {
                let match_contract = match contract_hash {
                    Some(c) => r.contract_hash == c,
                    None => true,
                };
                let match_function = match function {
                    Some(f) => r.function == f,
                    None => true,
                };
                match_contract && match_function
            })
            .collect();
        Ok(filtered)
    }
}

/// Calculate the delta between the last two runs. Returns percentage increase if >10%.
pub fn check_regression(records: &[RunHistory]) -> Option<(f64, f64)> {
    if records.len() < 2 {
        return None;
    }
    let latest = &records[records.len() - 1];
    let previous = &records[records.len() - 2];

    let mut regression_cpu = 0.0;
    let mut regression_mem = 0.0;

    if previous.cpu_used > 0 && latest.cpu_used > previous.cpu_used {
        let diff = (latest.cpu_used - previous.cpu_used) as f64;
        let p = (diff / previous.cpu_used as f64) * 100.0;
        if p > 10.0 {
            regression_cpu = p;
        }
    }

    if previous.memory_used > 0 && latest.memory_used > previous.memory_used {
        let diff = (latest.memory_used - previous.memory_used) as f64;
        let p = (diff / previous.memory_used as f64) * 100.0;
        if p > 10.0 {
            regression_mem = p;
        }
    }

    if regression_cpu > 0.0 || regression_mem > 0.0 {
        Some((regression_cpu, regression_mem))
    } else {
        None
    }
}

#[derive(Debug, Clone)]
pub struct BudgetTrendStats {
    pub count: usize,
    pub first_date: String,
    pub last_date: String,
    pub cpu_min: u64,
    pub cpu_avg: u64,
    pub cpu_max: u64,
    pub mem_min: u64,
    pub mem_avg: u64,
    pub mem_max: u64,
    pub last_cpu: u64,
    pub last_mem: u64,
}

pub fn budget_trend_stats(records: &[RunHistory]) -> Option<BudgetTrendStats> {
    if records.is_empty() {
        return None;
    }

    let mut cpu_min = u64::MAX;
    let mut cpu_max = 0u64;
    let mut mem_min = u64::MAX;
    let mut mem_max = 0u64;
    let mut cpu_sum: u128 = 0;
    let mut mem_sum: u128 = 0;

    for r in records {
        cpu_min = cpu_min.min(r.cpu_used);
        cpu_max = cpu_max.max(r.cpu_used);
        mem_min = mem_min.min(r.memory_used);
        mem_max = mem_max.max(r.memory_used);
        cpu_sum = cpu_sum.saturating_add(r.cpu_used as u128);
        mem_sum = mem_sum.saturating_add(r.memory_used as u128);
    }

    let count = records.len();
    let last = &records[count - 1];

    Some(BudgetTrendStats {
        count,
        first_date: records[0].date.clone(),
        last_date: last.date.clone(),
        cpu_min,
        cpu_avg: (cpu_sum / count as u128) as u64,
        cpu_max,
        mem_min,
        mem_avg: (mem_sum / count as u128) as u64,
        mem_max,
        last_cpu: last.cpu_used,
        last_mem: last.memory_used,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_regression_detection() {
        let p1 = RunHistory {
            date: "prev".into(),
            contract_hash: "hash".into(),
            function: "func".into(),
            cpu_used: 1000,
            memory_used: 1000,
        };
        let p2 = RunHistory {
            date: "latest".into(),
            contract_hash: "hash".into(),
            function: "func".into(),
            cpu_used: 1150,    // 15% increase
            memory_used: 1050, // 5% increase
        };

        let records = vec![p1, p2];
        let regression = check_regression(&records);
        assert!(regression.is_some());
        let (cpu, mem) = regression.unwrap();
        assert_eq!(cpu, 15.0);
        assert_eq!(mem, 0.0);
    }

    #[test]
    fn test_persistence_logic() {
        let temp = NamedTempFile::new().unwrap();
        let manager = HistoryManager::with_path(temp.path().to_path_buf());

        let record = RunHistory {
            date: "date".into(),
            contract_hash: "hash".into(),
            function: "func".into(),
            cpu_used: 1234,
            memory_used: 5678,
        };

        manager.append_record(record).unwrap();
        let history = manager.load_history().unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].cpu_used, 1234);
    }

    #[test]
    fn budget_trend_stats_empty_returns_none() {
        assert!(budget_trend_stats(&[]).is_none());
    }

    #[test]
    fn budget_trend_stats_computes_min_max_avg_last() {
        let records = vec![
            RunHistory {
                date: "2026-01-01T00:00:00Z".into(),
                contract_hash: "a".into(),
                function: "f".into(),
                cpu_used: 10,
                memory_used: 100,
            },
            RunHistory {
                date: "2026-01-02T00:00:00Z".into(),
                contract_hash: "a".into(),
                function: "f".into(),
                cpu_used: 30,
                memory_used: 200,
            },
            RunHistory {
                date: "2026-01-03T00:00:00Z".into(),
                contract_hash: "a".into(),
                function: "f".into(),
                cpu_used: 20,
                memory_used: 150,
            },
        ];

        let stats = budget_trend_stats(&records).unwrap();
        assert_eq!(stats.count, 3);
        assert_eq!(stats.cpu_min, 10);
        assert_eq!(stats.cpu_max, 30);
        assert_eq!(stats.cpu_avg, 20);
        assert_eq!(stats.mem_min, 100);
        assert_eq!(stats.mem_max, 200);
        assert_eq!(stats.mem_avg, 150);
        assert_eq!(stats.last_cpu, 20);
        assert_eq!(stats.last_mem, 150);
        assert_eq!(stats.first_date, "2026-01-01T00:00:00Z");
        assert_eq!(stats.last_date, "2026-01-03T00:00:00Z");
    }
}
