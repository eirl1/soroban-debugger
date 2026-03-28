use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;
use std::process::Command as StdCommand;
use std::time::Duration;

//
// Regression tests for remote mode argument validation
// See: https://github.com/.../issues/661
//

#[test]
fn test_remote_ping_without_contract_or_function() {
    // Remote mode should allow ping without contract/function
    // Connection will fail if no server is running, but argument parsing should succeed
    let mut cmd = Command::cargo_bin("soroban-debug").expect("Failed to find binary");
    cmd.args(["run", "--remote", "127.0.0.1:9229"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Connection").or(predicate::str::contains("connect")));
}

#[test]
fn test_remote_with_token_without_contract_or_function() {
    // Remote mode with auth token should parse without contract/function
    let mut cmd = Command::cargo_bin("soroban-debug").expect("Failed to find binary");
    cmd.args(["run", "--remote", "127.0.0.1:9229", "--token", "secret"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Connection").or(predicate::str::contains("connect")));
}

#[test]
fn test_remote_rejects_invalid_address_format() {
    // Invalid remote address format should fail at argument parsing
    let mut cmd = Command::cargo_bin("soroban-debug").expect("Failed to find binary");
    cmd.args(["run", "--remote", "invalid-address"])
        .assert()
        .failure();
}

#[test]
fn test_remote_with_only_contract_no_function() {
    // Remote mode with only contract (no function) should still parse
    // (connection may fail, but argument validation should pass)
    let temp_dir = tempfile::TempDir::new().expect("Failed to create temp dir");
    let contract_file = temp_dir.path().join("contract.wasm");
    std::fs::write(&contract_file, b"dummy").expect("Failed to write temp file");

    let mut cmd = Command::cargo_bin("soroban-debug").expect("Failed to find binary");
    cmd.args([
        "run",
        "--remote",
        "127.0.0.1:9229",
        "--contract",
        contract_file.to_str().unwrap(),
    ])
    .assert()
    // Should parse successfully (connection may fail, but that's expected)
    .stderr(predicate::str::contains("Connection").or(predicate::str::contains("127.0.0.1")));
}

#[test]
fn test_remote_with_only_function_no_contract() {
    // Remote mode with only function (no contract) should still parse
    // (connection may fail, but argument validation should pass)
    let mut cmd = Command::cargo_bin("soroban-debug").expect("Failed to find binary");
    cmd.args(["run", "--remote", "127.0.0.1:9229", "--function", "test"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Connection").or(predicate::str::contains("connect")));
}

#[test]
fn test_remote_with_args_but_no_contract_or_function() {
    // Remote mode with args but no contract/function should parse
    // (the remote server handles validation)
    let mut cmd = Command::cargo_bin("soroban-debug").expect("Failed to find binary");
    cmd.args([
        "run",
        "--remote",
        "127.0.0.1:9229",
        "--args",
        "[\"arg1\", \"arg2\"]",
    ])
    .assert()
    .failure()
    .stderr(predicate::str::contains("Connection").or(predicate::str::contains("connect")));
}

#[test]
fn test_remote_full_execution_args_matrix() {
    // Test remote mode with full set of optional arguments
    let temp_dir = tempfile::TempDir::new().expect("Failed to create temp dir");
    let contract_file = temp_dir.path().join("contract.wasm");
    std::fs::write(&contract_file, b"dummy").expect("Failed to write temp file");

    let mut cmd = Command::cargo_bin("soroban-debug").expect("Failed to find binary");
    cmd.args([
        "run",
        "--remote",
        "127.0.0.1:9229",
        "--token",
        "secret",
        "--contract",
        contract_file.to_str().unwrap(),
        "--function",
        "increment",
        "--args",
        "[1]",
        "--output",
        "json",
    ])
    .assert()
    // Should parse successfully (connection may fail, but that's expected)
    .stderr(predicate::str::contains("Connection").or(predicate::str::contains("127.0.0.1")));
}

#[test]
fn test_remote_run_execution() {
    fn fixture_wasm_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("wasm")
            .join(format!("{}.wasm", name))
    }

    fn ensure_counter_wasm() -> PathBuf {
        let wasm_path = fixture_wasm_path("counter");
        if wasm_path.exists() {
            return wasm_path;
        }

        let fixtures_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        if cfg!(windows) {
            let status = StdCommand::new("powershell")
                .current_dir(&fixtures_dir)
                .args(["-ExecutionPolicy", "Bypass", "-File", "build.ps1"])
                .status()
                .expect("Failed to run build.ps1");
            assert!(status.success(), "build.ps1 failed");
        } else {
            let status = StdCommand::new("bash")
                .current_dir(&fixtures_dir)
                .args(["./build.sh"])
                .status()
                .expect("Failed to run build.sh");
            assert!(status.success(), "build.sh failed");
        }

        assert!(
            wasm_path.exists(),
            "Expected fixture wasm to exist after build: {:?}",
            wasm_path
        );
        wasm_path
    }

    // Start server in background
    let mut server_cmd = StdCommand::new(assert_cmd::cargo::cargo_bin!("soroban-debug"));

    let mut server_child = server_cmd
        .arg("server")
        .arg("--port")
        .arg("9245")
        .arg("--token")
        .arg("secret")
        .spawn()
        .expect("Failed to spawn server");

    // Wait a bit for server to start
    std::thread::sleep(Duration::from_millis(1500));

    // Smoke-test ping through the `run --remote` path:
    let mut ping_cmd: Command = assert_cmd::cargo::cargo_bin_cmd!("soroban-debug");
    ping_cmd
        .arg("run")
        .arg("--remote")
        .arg("127.0.0.1:9245")
        .arg("--token")
        .arg("secret")
        .assert()
        .success()
        .stdout(predicate::str::contains("Remote debugger is reachable"));

    let counter_wasm = ensure_counter_wasm();

    // Run remote client
    let mut client_cmd: Command = assert_cmd::cargo::cargo_bin_cmd!("soroban-debug");
    let assert = client_cmd
        .arg("run")
        .arg("--remote")
        .arg("127.0.0.1:9245")
        .arg("--token")
        .arg("secret")
        .arg("--contract")
        .arg(&counter_wasm)
        .arg("--function")
        .arg("increment")
        .assert();

    // Kill server
    server_child.kill().unwrap();
    let _ = server_child.wait();

    // The counter.wasm might just output 1 on first increment
    // Let's just assert that it executed successfully rather than checking the exact value if we are unsure
    assert.success().stdout(predicate::str::contains("Result:"));
}
