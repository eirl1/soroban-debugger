use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

/// Current version of the plugin manifest schema.
/// Follows semantic versioning. Breaking changes will increment the major version.
pub const MANIFEST_SCHEMA_VERSION: &str = "1.0.0";

/// Manifest describing a plugin and its capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// The version of the manifest schema itself.
    #[serde(default)]
    pub schema_version: String,

    /// Plugin name
    pub name: String,

    /// Plugin version (semantic versioning)
    pub version: String,

    /// Plugin description
    pub description: String,

    /// Plugin author
    pub author: String,

    /// Plugin license
    pub license: Option<String>,

    /// Minimum debugger version required
    pub min_debugger_version: Option<String>,

    /// Plugin capabilities
    pub capabilities: PluginCapabilities,

    /// Path to the plugin library (relative to manifest)
    pub library: String,

    /// Plugin dependencies (other plugins this plugin requires)
    pub dependencies: Vec<String>,

    /// Optional trust and signature metadata for the plugin package
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<PluginSignature>,
}

/// Capabilities that a plugin can provide
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PluginCapabilities {
    /// Whether the plugin hooks execution events
    pub hooks_execution: bool,

    /// Whether the plugin provides custom CLI commands
    pub provides_commands: bool,

    /// Whether the plugin provides custom output formatters
    pub provides_formatters: bool,

    /// Whether the plugin supports hot-reload
    pub supports_hot_reload: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginSignature {
    /// Human-readable signer identity for policy decisions and diagnostics
    pub signer: String,

    /// Ed25519 public key encoded as base64
    pub public_key: String,

    /// Detached Ed25519 signature over the manifest payload encoded as base64
    pub manifest_signature: String,

    /// Detached Ed25519 signature over the plugin library bytes encoded as base64
    pub library_signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPluginSignature {
    pub signer: String,
    pub fingerprint: String,
}

impl PluginManifest {
    /// Load a manifest from a TOML file
    pub fn from_file(path: &PathBuf) -> Result<Self, String> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read manifest file: {}", e))?;

        toml::from_str(&contents).map_err(|e| format!("Failed to parse manifest: {}", e))
    }

    /// Validate the manifest
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version.is_empty() {
            // For backward compatibility with manifests that don't have this field yet.
            // We can warn here if we want, but for now, let's treat it as compatible with "1.0.0".
        } else {
            if !self.is_valid_semver(&self.schema_version) {
                return Err(format!(
                    "Invalid manifest schema version: {}",
                    self.schema_version
                ));
            }

            // Check for major version compatibility.
            let manifest_major = self.schema_version.split('.').next().unwrap_or("0");
            let supported_major = MANIFEST_SCHEMA_VERSION.split('.').next().unwrap_or("1");
            if manifest_major != supported_major {
                return Err(format!(
                    "Unsupported manifest schema version. Found '{}', but this debugger supports schema version '{}'. Please update the plugin or the debugger.",
                    self.schema_version, MANIFEST_SCHEMA_VERSION
                ));
            }
        }

        if self.name.is_empty() {
            return Err("Plugin name cannot be empty".to_string());
        }

        if self.version.is_empty() {
            return Err("Plugin version cannot be empty".to_string());
        }

        if self.library.is_empty() {
            return Err("Plugin library path cannot be empty".to_string());
        }

        // Validate semantic versioning
        if !self.is_valid_semver(&self.version) {
            return Err(format!("Invalid semantic version: {}", self.version));
        }

        if let Some(ref min_version) = self.min_debugger_version {
            if !self.is_valid_semver(min_version) {
                return Err(format!("Invalid minimum debugger version: {}", min_version));
            }
        }

        if let Some(signature) = &self.signature {
            if signature.signer.trim().is_empty() {
                return Err(
                    "Plugin signer cannot be empty when signature metadata is present".to_string(),
                );
            }
            if signature.public_key.trim().is_empty() {
                return Err("Plugin signature public_key cannot be empty".to_string());
            }
            if signature.manifest_signature.trim().is_empty() {
                return Err("Plugin manifest_signature cannot be empty".to_string());
            }
            if signature.library_signature.trim().is_empty() {
                return Err("Plugin library_signature cannot be empty".to_string());
            }
        }

        Ok(())
    }

    pub fn canonical_manifest_payload(&self) -> Result<Vec<u8>, String> {
        let mut unsigned = self.clone();
        unsigned.signature = None;
        toml::to_string(&unsigned)
            .map(|value| value.into_bytes())
            .map_err(|e| format!("Failed to canonicalize manifest for signing: {}", e))
    }

    pub fn verify_signatures(
        &self,
        library_bytes: &[u8],
    ) -> Result<VerifiedPluginSignature, String> {
        let signature = self
            .signature
            .as_ref()
            .ok_or_else(|| "Plugin manifest is unsigned".to_string())?;

        let public_key_bytes = BASE64_STANDARD
            .decode(signature.public_key.as_bytes())
            .map_err(|e| format!("Invalid plugin public key encoding: {}", e))?;
        let public_key_array: [u8; 32] = public_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "Plugin public key must decode to 32 bytes".to_string())?;
        let verifying_key = VerifyingKey::from_bytes(&public_key_array)
            .map_err(|e| format!("Invalid plugin public key: {}", e))?;

        let manifest_sig_bytes = BASE64_STANDARD
            .decode(signature.manifest_signature.as_bytes())
            .map_err(|e| format!("Invalid manifest signature encoding: {}", e))?;
        let library_sig_bytes = BASE64_STANDARD
            .decode(signature.library_signature.as_bytes())
            .map_err(|e| format!("Invalid library signature encoding: {}", e))?;
        let manifest_sig = Signature::from_slice(&manifest_sig_bytes)
            .map_err(|e| format!("Invalid manifest signature bytes: {}", e))?;
        let library_sig = Signature::from_slice(&library_sig_bytes)
            .map_err(|e| format!("Invalid library signature bytes: {}", e))?;

        verifying_key
            .verify(&self.canonical_manifest_payload()?, &manifest_sig)
            .map_err(|e| format!("Manifest signature verification failed: {}", e))?;
        verifying_key
            .verify(library_bytes, &library_sig)
            .map_err(|e| format!("Library signature verification failed: {}", e))?;

        Ok(VerifiedPluginSignature {
            signer: signature.signer.clone(),
            fingerprint: self.signature_fingerprint()?,
        })
    }

    pub fn signature_fingerprint(&self) -> Result<String, String> {
        let signature = self
            .signature
            .as_ref()
            .ok_or_else(|| "Plugin manifest is unsigned".to_string())?;
        let public_key_bytes = BASE64_STANDARD
            .decode(signature.public_key.as_bytes())
            .map_err(|e| format!("Invalid plugin public key encoding: {}", e))?;
        let fingerprint = hex::encode(Sha256::digest(public_key_bytes));
        Ok(fingerprint)
    }

    fn is_valid_semver(&self, version: &str) -> bool {
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() != 3 {
            return false;
        }

        parts.iter().all(|p| p.parse::<u32>().is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn test_valid_semver() {
        let manifest = PluginManifest {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            description: "test".to_string(),
            author: "test".to_string(),
            license: None,
            min_debugger_version: Some("0.1.0".to_string()),
            capabilities: PluginCapabilities::default(),
            library: "test.so".to_string(),
            dependencies: vec![],
            signature: None,
        };

        assert!(manifest.validate().is_ok());
    }

    #[test]
    fn test_invalid_semver() {
        let manifest = PluginManifest {
            name: "test".to_string(),
            version: "1.0".to_string(),
            description: "test".to_string(),
            author: "test".to_string(),
            license: None,
            min_debugger_version: None,
            capabilities: PluginCapabilities::default(),
            library: "test.so".to_string(),
            dependencies: vec![],
            signature: None,
        };

        assert!(manifest.validate().is_err());
    }

    #[test]
    fn verify_signatures_accepts_valid_manifest_and_library_signatures() {
        let mut manifest = PluginManifest {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            description: "test".to_string(),
            author: "test".to_string(),
            license: None,
            min_debugger_version: Some("0.1.0".to_string()),
            capabilities: PluginCapabilities::default(),
            library: "test.so".to_string(),
            dependencies: vec![],
            signature: None,
        };
        let library_bytes = b"fake plugin library";
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();

        let manifest_payload = manifest.canonical_manifest_payload().unwrap();
        let manifest_signature = signing_key.sign(&manifest_payload);
        let library_signature = signing_key.sign(library_bytes);

        manifest.signature = Some(PluginSignature {
            signer: "test-signer".to_string(),
            public_key: BASE64_STANDARD.encode(verifying_key.to_bytes()),
            manifest_signature: BASE64_STANDARD.encode(manifest_signature.to_bytes()),
            library_signature: BASE64_STANDARD.encode(library_signature.to_bytes()),
        });

        let verified = manifest.verify_signatures(library_bytes).unwrap();
        assert_eq!(verified.signer, "test-signer");
        assert!(!verified.fingerprint.is_empty());
    }

    #[test]
    fn verify_signatures_rejects_tampered_library_bytes() {
        let mut manifest = PluginManifest {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            description: "test".to_string(),
            author: "test".to_string(),
            license: None,
            min_debugger_version: Some("0.1.0".to_string()),
            capabilities: PluginCapabilities::default(),
            library: "test.so".to_string(),
            dependencies: vec![],
            signature: None,
        };
        let signing_key = SigningKey::from_bytes(&[8u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let manifest_payload = manifest.canonical_manifest_payload().unwrap();
        let manifest_signature = signing_key.sign(&manifest_payload);
        let library_signature = signing_key.sign(b"expected library");

        manifest.signature = Some(PluginSignature {
            signer: "test-signer".to_string(),
            public_key: BASE64_STANDARD.encode(verifying_key.to_bytes()),
            manifest_signature: BASE64_STANDARD.encode(manifest_signature.to_bytes()),
            library_signature: BASE64_STANDARD.encode(library_signature.to_bytes()),
        });

        let err = manifest.verify_signatures(b"tampered library").unwrap_err();
        assert!(err.contains("Library signature verification failed"));
    }
}
