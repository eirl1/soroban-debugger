#![allow(dead_code)]

use soroban_debugger::server::DebugServer;
use std::path::Path;

#[test]
fn test_server_creation_without_token() {
    let server = DebugServer::new("127.0.0.1".to_string(), None, None, None, None, Vec::new());
    assert!(server.is_ok(), "Server should be creatable without token");
}

#[test]
fn test_server_creation_with_token() {
    let token = "valid-test-token-1234567890".to_string();
    let server = DebugServer::new(
        "127.0.0.1".to_string(),
        Some(token.clone()),
        None,
        None,
        None,
        Vec::new(),
    )
    .expect("Failed to create server with token");

    let _ = server;
}

#[test]
fn test_server_rejects_partial_tls_configuration() {
    let fake_cert = Path::new("tests/fixtures/cert.pem");
    match DebugServer::new(
        "127.0.0.1".to_string(),
        None,
        Some(fake_cert),
        None,
        None,
        Vec::new(),
    ) {
        Ok(_) => panic!("expected TLS unsupported error"),
        Err(err) => {
            assert!(
                err.to_string()
                    .contains("TLS requires both certificate and key paths"),
                "expected partial TLS validation error"
            );
        }
    }
}

#[test]
fn test_server_accepts_both_tls_paths_for_loading() {
    let fake_cert = Path::new("tests/fixtures/cert.pem");
    let fake_key = Path::new("tests/fixtures/key.pem");
    let err = DebugServer::new(
        "127.0.0.1".to_string(),
        None,
        Some(fake_cert),
        Some(fake_key),
        None,
        Vec::new(),
    )
    .expect_err("expected missing fixture files to fail during TLS load");

    assert!(
        !err.to_string()
            .contains("TLS requires both certificate and key paths"),
        "expected TLS load attempt instead of partial-args validation error"
    );
}
