#![cfg(feature = "network-tests")]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;
use std::path::PathBuf;

fn get_free_port() -> Option<u16> {
    match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => Some(
            listener
                .local_addr()
                .expect("Failed to read local address")
                .port(),
        ),
        Err(_) => None,
    }
}

fn spawn_server(port: u16, token: &str) -> std::process::Child {
    std::process::Command::new(env!("CARGO_BIN_EXE_soroban-debug"))
        .args(["server", "--port", &port.to_string(), "--token", token])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn soroban-debug server")
}

fn connect_with_retry(port: u16) -> std::io::Result<TcpStream> {
    let addr = format!("127.0.0.1:{}", port);
    for _ in 0..10 {
        if let Ok(stream) = TcpStream::connect(&addr) {
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            return Ok(stream);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "Failed to connect"))
}

#[test]
fn test_reconnect_preserves_state() {
    let Some(port) = get_free_port() else { return; };
    let token = "test-token";
    let mut server = spawn_server(port, token);

    let result: std::result::Result<(), Box<dyn std::error::Error>> = (|| {
        let wasm_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/wasm/counter.wasm");
        
        let mut stream = connect_with_retry(port)?;
        let mut reader = BufReader::new(stream.try_clone()?);

        // 1. Handshake
        let handshake = "{\"id\":1,\"request\":{\"type\":\"Handshake\",\"client_name\":\"test\",\"client_version\":\"1.0\",\"protocol_min\":1,\"protocol_max\":1}}\n";
        stream.write_all(handshake.as_bytes())?;
        
        let mut response = String::new();
        reader.read_line(&mut response)?;
        let ack: serde_json::Value = serde_json::from_str(&response)?;
        let session_id = ack["response"]["session_id"].as_str().expect("Missing session_id in HandshakeAck").to_string();

        // 2. Authenticate
        let auth = format!("{{\"id\":2,\"request\":{{\"type\":\"Authenticate\",\"token\":\"{}\"}}}}\n", token);
        stream.write_all(auth.as_bytes())?;
        response.clear();
        reader.read_line(&mut response)?;

        // 3. Load Contract
        let load = format!("{{\"id\":3,\"request\":{{\"type\":\"LoadContract\",\"contract_path\":\"{}\"}}}}\n", wasm_path.to_str().unwrap());
        stream.write_all(load.as_bytes())?;
        response.clear();
        reader.read_line(&mut response)?;

        // 4. Set Breakpoint
        let bp = "{\"id\":4,\"request\":{\"type\":\"SetBreakpoint\",\"id\":\"bp1\",\"function\":\"increment\"}}\n";
        stream.write_all(bp.as_bytes())?;
        response.clear();
        reader.read_line(&mut response)?;

        // 5. Simulate Disconnect (drop current stream)
        drop(stream);
        drop(reader);
        std::thread::sleep(Duration::from_millis(100));

        // 6. Connect again and Reconnect
        let mut stream2 = connect_with_retry(port)?;
        let mut reader2 = BufReader::new(stream2.try_clone()?);

        // Handshake on new connection
        stream2.write_all(handshake.as_bytes())?;
        response.clear();
        reader2.read_line(&mut response)?;

        // Authenticate on new connection
        stream2.write_all(auth.as_bytes())?;
        response.clear();
        reader2.read_line(&mut response)?;

        // Send Reconnect request
        let reconnect = format!("{{\"id\":5,\"request\":{{\"type\":\"Reconnect\",\"session_id\":\"{}\"}}}}\n", session_id);
        stream2.write_all(reconnect.as_bytes())?;
        response.clear();
        reader2.read_line(&mut response)?;

        let reconnect_ack: serde_json::Value = serde_json::from_str(&response)?;
        assert_eq!(reconnect_ack["response"]["type"], "ReconnectAck");
        assert_eq!(reconnect_ack["response"]["session_id"], session_id);
        
        // Verify breakpoints are still there
        let list_bp = "{\"id\":6,\"request\":{\"type\":\"ListBreakpoints\"}}\n";
        stream2.write_all(list_bp.as_bytes())?;
        response.clear();
        reader2.read_line(&mut response)?;
        let bp_list: serde_json::Value = serde_json::from_str(&response)?;
        let breakpoints = bp_list["response"]["breakpoints"].as_array().unwrap();
        assert!(breakpoints.iter().any(|b| b["id"] == "bp1" && b["function"] == "increment"));

        Ok(())
    })();

    let _ = server.kill();
    let _ = server.wait();
    result.expect("Reconnection test failed");
}
