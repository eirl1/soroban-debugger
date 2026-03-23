use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn base_cmd(home: &std::path::Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_soroban-debug"));
    cmd.env("NO_COLOR", "1");
    cmd.env("NO_BANNER", "1");
    cmd.env("HOME", home);
    cmd.env("USERPROFILE", home);
    cmd
}

fn write_history(home: &std::path::Path, json: &str) {
    let dir = home.join(".soroban-debug");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("history.json"), json).unwrap();
}

#[test]
fn budget_trend_empty_history_is_graceful() {
    let temp = TempDir::new().unwrap();

    base_cmd(temp.path())
        .arg("--budget-trend")
        .assert()
        .success()
        .stdout(predicate::str::contains("Budget Trend"))
        .stdout(predicate::str::contains("No run history found yet"));
}

#[test]
fn budget_trend_filters_change_dataset() {
    let temp = TempDir::new().unwrap();
    write_history(
        temp.path(),
        r#"
[
  {
    "date": "2026-01-01T00:00:00Z",
    "contract_hash": "contractA",
    "function": "f1",
    "cpu_used": 100,
    "memory_used": 1000
  },
  {
    "date": "2026-01-02T00:00:00Z",
    "contract_hash": "contractA",
    "function": "f2",
    "cpu_used": 200,
    "memory_used": 2000
  },
  {
    "date": "2026-01-03T00:00:00Z",
    "contract_hash": "contractB",
    "function": "f1",
    "cpu_used": 300,
    "memory_used": 3000
  }
]
"#,
    );

    base_cmd(temp.path())
        .arg("--budget-trend")
        .assert()
        .success()
        .stdout(predicate::str::contains("Runs: 3"));

    base_cmd(temp.path())
        .args(["--budget-trend", "--trend-contract", "contractA"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Runs: 2"));

    base_cmd(temp.path())
        .args(["--budget-trend", "--trend-function", "f2"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Runs: 1"));

    base_cmd(temp.path())
        .args([
            "--budget-trend",
            "--trend-contract",
            "does-not-exist",
            "--trend-function",
            "also-missing",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("No run history found yet"));
}
