# Scenario Cookbook

This cookbook provides reusable patterns and "recipes" for common Soroban contract testing scenarios using the `scenario` command and TOML files.

---

## 🏗️ Basic Setup & Initialization

Most scenarios start with initializing a contract or setting up an admin.

```toml
[[steps]]
name = "Initialize Contract"
function = "initialize"
args = '["GD5DJ3B6A2KHSXLYJZ3IGR7Q5UMVJ5J4GQTKTQYQDQXJQJ5YQZQKQZQ", "My Token", "MTK"]'
expected_return = "()"
```

---

## 🔄 Capturing & Reusing Variables

Use the `capture` field to save a return value and `{{var_name}}` to use it in later steps. This is essential for testing dynamically generated values like IDs or total supplies.

```toml
[[steps]]
name = "Mint Tokens"
function = "mint"
args = '["Alice", 1000]'
capture = "new_balance"

[[steps]]
name = "Verify Balance"
function = "get_balance"
args = '["Alice"]'
# Reuses the captured value from the previous step
expected_return = "{{new_balance}}"

[[steps]]
name = "Transfer Captured Amount"
function = "transfer"
args = '["Alice", "Bob", {{new_balance}}]'
```

---

## 💾 Storage Assertions

Verify that internal contract state is updated correctly.

```toml
[[steps]]
name = "Set User Role"
function = "set_role"
args = '["Alice", 1]' # 1 for Admin

[steps.expected_storage]
# Key matches the contract's storage key format
"Role:Alice" = "1"
"TotalAdmins" = "1"
```

---

## 📢 Expected Events

Assert that specific events are emitted during execution.

```toml
[[steps]]
name = "Transfer with Event"
function = "transfer"
args = '["Alice", "Bob", 100]'

# The events must match exactly in order
expected_events = [
    { topics = ["transfer"], data = '["Alice", "Bob", 100]' }
]
```

---

## ⏱️ Timeout Overrides

For heavy steps (e.g., complex loops or large storage migrations), override the default timeout.

```toml
[defaults]
timeout_secs = 10

[[steps]]
name = "Lightweight Step"
function = "ping"

[[steps]]
name = "Heavy Migration"
function = "migrate_all_users"
# Disable timeout for this specific step
timeout_secs = 0 
```

---

## 🛑 Testing Failures (Panics & Errors)

Verify that your contract fails as expected under certain conditions.

```toml
[[steps]]
name = "Transfer Insufficient Funds"
function = "transfer"
args = '["Alice", "Bob", 1000000]'
# Assert the execution fails with a specific error message
expected_error = "InsufficientBalance"

[[steps]]
name = "Invalid Admin Call"
function = "admin_only"
args = '["NonAdmin"]'
# Assert the contract panics
expected_panic = "not authorized"
```

---

## 📊 Budget Constraints

Ensure your contract stays within resource limits.

```toml
[[steps]]
name = "Efficient Operation"
function = "add"
args = "[1, 2]"

[steps.budget_limits]
max_cpu_instructions = 10000
max_memory_bytes = 1024
```
