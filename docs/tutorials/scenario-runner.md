# Scenario Runner Tutorial

The Soroban Debugger's scenario runner allows you to write integration-test-style scenarios for Soroban contracts directly in TOML — no Rust test code required. This tutorial will walk you through the complete TOML format, provide a worked example, and show you how to run scenarios and interpret the output.

For practical recipes and reusable patterns, check out the [Scenario Cookbook](../scenario-cookbook.md).

## Overview

The scenario runner executes a sequence of contract function calls defined in a TOML file, validating both return values and storage state at each step. This approach offers several advantages:

- **No Rust code required**: Write tests in simple TOML syntax
- **Integration-style testing**: Test contract behavior across multiple steps
- **Storage validation**: Verify contract state changes
- **Clear output**: Easy-to-read pass/fail results

## TOML Format Reference

### Root Structure

```toml
[defaults]
timeout_secs = 30

[[steps]]
# Step 1 configuration

[[steps]]
# Step 2 configuration
```

### Step Fields

Each step in a scenario supports the following fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | String | Optional | Human-readable name for the step (defaults to function name) |
| `function` | String | Required | Name of the contract function to call |
| `args` | String | Optional | JSON array of arguments to pass to the function |
| `timeout_secs` | Integer | Optional | Per-step execution timeout override in seconds. `0` disables the timeout |
| `expected_return` | String | Optional | Expected return value (string comparison) |
| `expected_storage` | Table | Optional | Map of storage keys to expected values |

### Timeout Defaults and Overrides

You can define a scenario-wide default timeout in a top-level `[defaults]` table and then
override it for individual steps with `timeout_secs`.

Timeout precedence is:

1. Step `timeout_secs`
2. Scenario `[defaults].timeout_secs`
3. CLI `scenario --timeout`
4. Built-in default of 30 seconds

Use `0` at either the default or step level to disable timeout enforcement.

### Storage Assertions

The `expected_storage` field uses TOML table syntax:

```toml
[steps.expected_storage]
"StorageKey" = "ExpectedValue"
"AnotherKey" = "AnotherExpectedValue"
```

**Note**: Storage keys and values are compared as strings after trimming whitespace.

## Complete Worked Example

Let's create a comprehensive 5-step scenario for the SimpleToken contract. This scenario will test initialization, minting, transfers, and balance queries.

### Step 1: Contract Initialization

First, we initialize the token with an admin address, name, and symbol:

```toml
[[steps]]
name = "Initialize Token"
function = "initialize"
args = '["GD5DJ3B6A2KHSXLYJZ3IGR7Q5UMVJ5J4GQTKTQYQDQXJQJ5YQZQKQZQ", "My Token", "MTK"]'
expected_return = "()"
```

### Step 2: Mint Tokens to User

Next, we mint 1000 tokens to a user address:

```toml
[[steps]]
name = "Mint Tokens to User"
function = "mint"
args = '["GD726E62Z6XU6KD5J2EPOHG5NQZ5K5I5J5QZQZQZQZQZQZQZQZQZQZQ", 1000]'
expected_return = "()"
```

### Step 3: Check User Balance

Verify the user received the tokens:

```toml
[[steps]]
name = "Check User Balance"
function = "balance"
args = '["GD726E62Z6XU6KD5J2EPOHG5NQZ5K5I5J5QZQZQZQZQZQZQZQZQZQZQ"]'
expected_return = "1000"
```

### Step 4: Transfer Tokens

Transfer 300 tokens from the user to another recipient:

```toml
[[steps]]
name = "Transfer Tokens"
function = "transfer"
args = '["GD726E62Z6XU6KD5J2EPOHG5NQZ5K5I5J5QZQZQZQZQZQZQZQZQZQZQ", "GD826E62Z6XU6KD5J2EPOHG5NQZ5K5I5J5QZQZQZQZQZQZQZQZQZQZQ", 300]'
expected_return = "()"
```

### Step 5: Verify Final State

Check both users' balances and total supply:

```toml
[[steps]]
name = "Verify Final State"
function = "balance"
args = '["GD726E62Z6XU6KD5J2EPOHG5NQZ5K5I5J5QZQZQZQZQZQZQZQZQZQZQ"]'
expected_return = "700"

[steps.expected_storage]
"TotalSupply" = "1000"
```

## Complete Scenario File

Here's the complete `scenario.toml` file:

```toml
# Simple Token Integration Test Scenario
# This scenario tests the complete lifecycle of a token contract

[[steps]]
name = "Initialize Token"
function = "initialize"
args = '["GD5DJ3B6A2KHSXLYJZ3IGR7Q5UMVJ5J4GQTKTQYQDQXJQJ5YQZQKQZQ", "My Token", "MTK"]'
expected_return = "()"

[[steps]]
name = "Mint Tokens to User"
function = "mint"
args = '["GD726E62Z6XU6KD5J2EPOHG5NQZ5K5I5J5QZQZQZQZQZQZQZQZQZQZQ", 1000]'
expected_return = "()"

[[steps]]
name = "Check User Balance"
function = "balance"
args = '["GD726E62Z6XU6KD5J2EPOHG5NQZ5K5I5J5QZQZQZQZQZQZQZQZQZQZQ"]'
expected_return = "1000"

[[steps]]
name = "Transfer Tokens"
function = "transfer"
args = '["GD726E62Z6XU6KD5J2EPOHG5NQZ5K5I5J5QZQZQZQZQZQZQZQZQZQZQ", "GD826E62Z6XU6KD5J2EPOHG5NQZ5K5I5J5QZQZQZQZQZQZQZQZQZQZQ", 300]'
expected_return = "()"

[[steps]]
name = "Verify Final State"
function = "balance"
args = '["GD726E62Z6XU6KD5J2EPOHG5NQZ5K5I5J5QZQZQZQZQZQZQZQZQZQZQ"]'
expected_return = "700"

[steps.expected_storage]
"TotalSupply" = "1000"
```

## Running Scenarios

### Command Syntax

```bash
soroban-debugger scenario --contract <WASM_FILE> --scenario <TOML_FILE>
```

### Example

```bash
soroban-debugger scenario \
  --contract examples/contracts/simple-token/target/wasm32-unknown-unknown/release/simple_token.wasm \
  --scenario scenario.toml
```

### With Initial Storage

You can also provide initial storage state:

```bash
soroban-debugger scenario \
  --contract contract.wasm \
  --scenario scenario.toml \
  --storage '{"Admin": "GD5DJ3B6A2KHSXLYJZ3IGR7Q5UMVJ5J4GQTKTQYQDQXJQJ5YQZQKQZQ"}'
```

## Output Interpretation

### Successful Execution

When all steps pass, you'll see output like:

```
ℹ️ Loading scenario file: "scenario.toml"
ℹ️ Loading contract: "simple_token.wasm"
✅ Running 5 scenario steps...

ℹ️ Step 1: Initialize Token
  Result: ()
  ✅ Return value assertion passed
✅ Step 1 passed.

ℹ️ Step 2: Mint Tokens to User
  Result: ()
  ✅ Return value assertion passed
✅ Step 2 passed.

ℹ️ Step 3: Check User Balance
  Result: 1000
  ✅ Return value assertion passed
✅ Step 3 passed.

ℹ️ Step 4: Transfer Tokens
  Result: ()
  ✅ Return value assertion passed
✅ Step 4 passed.

ℹ️ Step 5: Verify Final State
  Result: 700
  ✅ Return value assertion passed
  ✅ Storage assertion passed for key 'TotalSupply'
✅ Step 5 passed.

✅ All scenario steps passed successfully!
```

### Failed Execution

When a step fails, execution stops and you'll see detailed error information:

```
ℹ️ Step 3: Check User Balance
  Result: 500
  ❌ Return value assertion failed! Expected '1000', got '500'
⚠️ Step 3 failed.
```

### Storage Assertion Failures

Storage assertion failures show the key and mismatched values:

```
ℹ️ Step 5: Verify Final State
  Result: 700
  ✅ Return value assertion passed
  ❌ Storage assertion failed for key 'TotalSupply'! Expected '1000', got '700'
⚠️ Step 5 failed.
```

## Advanced Features

### Complex Arguments

Arguments can be any valid JSON:

```toml
[[steps]]
name = "Complex Function Call"
function = "complex_function"
args = '[{"address": "GD5DJ3B6A2KHSXLYJZ3IGR7Q5UMVJ5J4GQTKTQYQDQXJQJ5YQZQKQZQ", "amount": 1000}, "metadata", true]'
```

### Multiple Storage Assertions

You can assert multiple storage keys in a single step:

```toml
[[steps]]
name = "Check Multiple Storage Values"
function = "some_function"
expected_return = "success"

[steps.expected_storage]
"Balance:GD5DJ3B6A2KHSXLYJZ3IGR7Q5UMVJ5J4GQTKTQYQDQXJQJ5YQZQKQZQ" = "1000"
"TotalSupply" = "1000"
"Admin" = "GD5DJ3B6A2KHSXLYJZ3IGR7Q5UMVJ5J4GQTKTQYQDQXJQJ5YQZQKQZQ"
```

### No Assertions

Steps can be used without any assertions (just for setup):

```toml
[[steps]]
name = "Setup Step"
function = "initialize"
args = '["admin", "Token", "TKN"]'
```

## Best Practices

1. **Descriptive Names**: Use clear, descriptive step names for better debugging
2. **Incremental Testing**: Test one feature per step when possible
3. **Storage Validation**: Use storage assertions to verify state changes
4. **Error Cases**: Create separate scenarios for error conditions
5. **Address Generation**: Use consistent test addresses across scenarios

## Common Patterns

### Testing Error Conditions

```toml
[[steps]]
name = "Test Zero Amount Transfer"
function = "transfer"
args = '["from", "to", 0]'
# This should fail with ZeroAmount error
```

### State Verification

```toml
[[steps]]
name = "Verify Contract State"
function = "total_supply"
expected_return = "1000"

[steps.expected_storage]
"Admin" = "GD5DJ3B6A2KHSXLYJZ3IGR7Q5UMVJ5J4GQTKTQYQDQXJQJ5YQZQKQZQ"
"Name" = "Test Token"
```

### Multi-step Workflows

```toml
[[steps]]
name = "Setup: Initialize"
function = "initialize"
args = '["admin", "Token", "TKN"]'

[[steps]]
name = "Setup: Mint to User A"
function = "mint"
args = '["user_a", 1000]'

[[steps]]
name = "Setup: Mint to User B"
function = "mint"
args = '["user_b", 500]'

[[steps]]
name = "Test: Transfer A to B"
function = "transfer"
args = '["user_a", "user_b", 200]'

[[steps]]
name = "Verify: Final Balances"
function = "balance"
args = '["user_a"]'
expected_return = "800"

[steps.expected_storage]
"Balance:user_b" = "700"
"TotalSupply" = "1500"
```

## Troubleshooting

### Common Issues

1. **JSON Parsing Errors**: Ensure args are valid JSON strings
2. **Storage Key Format**: Storage keys must match exactly what the contract uses
3. **Return Value Format**: Return values are compared as strings
4. **Address Format**: Use valid Soroban address strings

### Debugging Tips

- Run scenarios with verbose logging for more details
- Check individual steps by commenting out later steps
- Use storage assertions to understand contract state
- Verify function names and argument types match the contract

## Symbolic Analysis

The symbolic analyzer helps you identify edge cases and improve branch coverage by automatically generating valid, type-aware inputs for your contract functions.

### Key Benefits

- **Type-Aware Generation**: Automatically generates valid seeds for `Address`, `Option`, `Vec`, `Map`, `Tuple`, and primitive types.
- **Coverage Exploration**: Systematically explores function branches to find panics or unexpected behavior.
- **Deterministic**: Produces reproducible test scenarios.

### Command Usage

```bash
soroban-debugger symbolic --contract <WASM_FILE> --function <FUNCTION_NAME> [OPTIONS]
```

### Strategy Knobs

| Option | Default | Description |
|--------|---------|-------------|
| `--max-breadth` | 5 | Maximum number of seeds per primitive type |
| `--max-depth` | 3 | Maximum recursion depth for nested types |
| `--input-combination-cap` | 100 | Maximum number of input combinations to generate |
| `--path-cap` | 100 | Maximum number of generated inputs to execute |
| `--profile` | `balanced` | Preset budget (fast, balanced, deep) |

### Example

Generate up to 50 test cases for a `transfer` function with complex nested types:

```bash
soroban-debugger symbolic \
  --contract token.wasm \
  --function transfer \
  --max-breadth 10 \
  --max-depth 4 \
  --input-combination-cap 50
```

## Conclusion

The combination of the scenario runner and symbolic analyzer provides a comprehensive toolkit for testing and hardening Soroban contracts. Use the symbolic analyzer to discover edge cases, and then capture those as permanent integration tests in TOML scenarios.
