# Analyzer Suppressions

The Soroban Debugger's security analyzer allows you to suppress specific findings that are deemed false positives or accepted risks for your project.

## Suppression File Format

Suppressions are defined in a TOML file. The default configuration file `.soroban-debug.toml` can point to your suppressions file:

```toml
[output]
suppressions_file = "suppressions.toml"
```

### Format

```toml
[[suppressions]]
rule_id = "missing-auth"
contract_path = "test_data/contracts"
location = "Dynamic trace"
reason = "Intentional risk in test environments"
```

- `rule_id`: ID of the rule being suppressed
- `contract_path`: Substring of the contract path
- `location`: Optional substring matching the location of the finding
- `reason`: Justification for ignoring the finding
