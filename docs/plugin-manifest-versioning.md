# Plugin Manifest Versioning

The Soroban Debugger plugin system uses two distinct versioning schemes to ensure compatibility and provide clear migration paths:

1.  **Manifest Schema Version (`schema_version`)**: Governs the structure and supported fields of the `plugin.toml` manifest file itself.
2.  **Plugin API Version**: Governs the Rust trait (`InspectorPlugin`), events, and other interfaces that a plugin's shared library uses to communicate with the debugger at runtime.

This document focuses on the **manifest schema version**.

## `schema_version` in `plugin.toml`

Every `plugin.toml` file should declare the version of the manifest schema it conforms to. This field is essential for the debugger to correctly parse the manifest and understand its capabilities.

```toml
# plugin.toml

schema_version = "1.0.0"
name = "my-plugin"
version = "1.0.0"
# ... other fields
```

### Versioning Scheme

The `schema_version` follows **Semantic Versioning (SemVer)**. The debugger uses the **major version** to determine compatibility.

- **Major Version (`1`.x.x)**: A change in the major version indicates a breaking change in the manifest format. For example, if the debugger supports schema `1.2.0`, it can load plugins with manifests versioned `1.0.0`, `1.1.0`, or `1.2.0`. It will reject a manifest with version `2.0.0`.
- **Minor and Patch Versions (x.`0`.`0`)**: These are for non-breaking additions or clarifications to the schema.

### Compatibility and Error Handling

When the debugger loads a plugin, it first reads `plugin.toml` and checks the `schema_version`:

- **Match**: If the major version of the plugin's `schema_version` matches the major version supported by the debugger, loading proceeds.
- **Mismatch**: If the major versions do not match, the debugger will refuse to load the plugin and will emit an error message explaining the incompatibility.

  Example error:
  ```
  Invalid manifest: Unsupported manifest schema version. Found '2.0.0', but this debugger supports schema version '1.0.0'. Please update the plugin or the debugger.
  ```

This explicit check ensures that you get a clear error message about manifest-level incompatibilities before the debugger even attempts to load the plugin's dynamic library.

### Distinguishing from Runtime API Version

The `schema_version` is completely separate from the runtime Plugin API version.

- **Manifest Schema Failure**: Occurs early, during manifest parsing. The error message will mention `schema_version`.
- **Runtime API Failure**: Occurs later, when the dynamic library is loaded and the plugin is initialized. The error message will mention `PluginError::VersionMismatch` and refer to the runtime API version, which is a different check.

This separation helps plugin authors and users quickly diagnose whether an issue stems from an outdated `plugin.toml` file or an incompatible compiled plugin library.

### Backward Compatibility

For manifests created before the `schema_version` field was introduced, the debugger will assume a compatible version (`1.x.x`) to ensure older plugins continue to work without modification. However, all new plugins should explicitly include the `schema_version` field.