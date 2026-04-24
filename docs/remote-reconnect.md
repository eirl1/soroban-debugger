# Remote Debugging Reconnection

This document describes the reconnection protocol and server-side session persistence mechanism in `soroban-debugger`.

## Overview

Remote debugging sessions can be interrupted by network fluctuations or client restarts. To prevent losing debugging progress (such as execution state, breakpoints, and storage modifications), the debugger server supports session reconnection.

When a client reconnects within the configured grace period, it can re-attach to the existing `DebuggerEngine` and resume debugging from exactly where it left off.

## Protocol Flow

### 1. Initial Handshake

During the initial connection, the client sends a `Handshake` request. The server responds with a `HandshakeAck` containing a unique `session_id`.

```json
{
  "id": 1,
  "response": {
    "type": "HandshakeAck",
    "session_id": "550e8400-e29b-41d4-a716-446655440000",
    ...
  }
}
```

The client should persist this `session_id` for the duration of the debugging task.

### 2. Connection Interruption

If the TCP connection is lost, the server does *not* immediately destroy the `DebuggerEngine`. Instead, it "parks" the session and starts a grace period timer (default: 300 seconds).

### 3. Reconnection

To re-attach, the client establishes a new TCP connection and sends a `Reconnect` request containing the previously received `session_id`.

```json
{
  "id": 2,
  "request": {
    "type": "Reconnect",
    "session_id": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

### 4. Reconnection Acknowledgment

If the session is still active, the server responds with a `ReconnectAck` containing the current state of the debugger.

```json
{
  "id": 2,
  "response": {
    "type": "ReconnectAck",
    "session_id": "550e8400-e29b-41d4-a716-446655440000",
    "paused": true,
    "current_function": "hello",
    "breakpoints": ["bp1", "bp2"],
    "step_count": 42
  }
}
```

If the session has expired or the ID is invalid, the server returns a `SessionExpired` response:

```json
{
  "id": 2,
  "response": {
    "type": "SessionExpired",
    "message": "Session has expired after 300 seconds of inactivity."
  }
}
```

## Server Configuration

The session grace period can be configured via the `SESSION_GRACE_PERIOD_SECS` constant in `src/server/debug_server.rs`.

## Client Implementation Details

The `RemoteClient` handles reconnection automatically when an idempotent request fails due to a network error. It will attempt to establish a new connection and send the `Reconnect` request transparently.

Developers using the `RemoteClient` as a library can also use `reconnect_to_session(session_id)` to manually resume a session from a different process or after a full client restart.
