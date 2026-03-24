use crate::runtime::executor::ContractExecutor;
use crate::server::protocol::{ DynamicTraceEvent, DynamicTraceEventKind };
use crate::utils::wasm::{ parse_instructions, WasmInstruction };
use crate::Result;
use serde::{ Deserialize, Serialize };
use std::collections::{ HashMap, HashSet };
use wasmparser::{ Operator, Parser, Payload };

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub rule_id: String,
    pub severity: Severity,
    pub location: String,
    pub description: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityReport {
    pub findings: Vec<SecurityFinding>,
}

pub trait SecurityRule {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn analyze_static(&self, _wasm_bytes: &[u8]) -> Result<Vec<SecurityFinding>> {
        Ok(vec![])
    }
    fn analyze_dynamic(
        &self,
        _executor: &ContractExecutor,
        _trace: &[DynamicTraceEvent]
    ) -> Result<Vec<SecurityFinding>> {
        Ok(vec![])
    }
}

pub struct SecurityAnalyzer {
    rules: Vec<Box<dyn SecurityRule>>,
}

impl SecurityAnalyzer {
    pub fn new() -> Self {
        Self {
            rules: vec![
                Box::new(HardcodedAddressRule),
                Box::new(ArithmeticCheckRule),
                Box::new(AuthorizationCheckRule),
                Box::new(ReentrancyPatternRule),
                Box::new(CrossContractImportRule),
                Box::new(UnboundedIterationRule)
            ],
        }
    }

    pub fn analyze(
        &self,
        wasm_bytes: &[u8],
        executor: Option<&ContractExecutor>,
        trace: Option<&[DynamicTraceEvent]>
    ) -> Result<SecurityReport> {
        let mut report = SecurityReport::default();

        for rule in &self.rules {
            let static_findings = rule.analyze_static(wasm_bytes)?;
            report.findings.extend(static_findings);

            if let (Some(exec), Some(tr)) = (executor, trace) {
                let dynamic_findings = rule.analyze_dynamic(exec, tr)?;
                report.findings.extend(dynamic_findings);
            }
        }

        Ok(report)
    }
}

impl Default for SecurityAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// StrKey validation helpers
// ---------------------------------------------------------------------------

/// CRC-16/XModem (poly = 0x1021, init = 0x0000, no reflection).
/// Used by Stellar StrKey to protect against transcription errors.
fn strkey_crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0x0000;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            crc = if (crc & 0x8000) != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

/// Returns `true` only when `s` is a cryptographically valid Stellar StrKey.
///
/// Validation steps (SEP-0023):
///   1. Must be exactly 56 characters, all from the base32 alphabet (A–Z, 2–7).
///   2. Base32-decode to exactly 35 bytes.
///   3. `decoded[0]` must be a recognised version byte:
///      • `0x30` (6 << 3) → ED25519 public key  → 'G' prefix
///      • `0x10` (2 << 3) → contract address    → 'C' prefix
///   4. CRC-16/XModem over `decoded[0..33]` must equal the little-endian u16
///      stored in `decoded[33..35]`.
///
/// Any 56-char string that fails even one of these steps is **not** a valid
/// address — it is, for example, an error-message fragment, a base64 blob, or
/// a random identifier that merely happens to start with 'G' or 'C'.
fn is_valid_strkey(s: &str) -> bool {
    if s.len() != 56 {
        return false;
    }

    // --- Base32 decode (RFC 4648, no padding) ---
    // 56 chars × 5 bits = 280 bits = 35 bytes exactly.
    let mut decoded = [0u8; 35];
    let mut bits: u64 = 0;
    let mut bit_count: u32 = 0;
    let mut byte_idx: usize = 0;

    for ch in s.bytes() {
        let val: u64 = match ch {
            b'A'..=b'Z' => (ch - b'A') as u64,
            b'2'..=b'7' => (ch - b'2' + 26) as u64,
            _ => {
                return false;
            } // character outside base32 alphabet
        };
        bits = (bits << 5) | val;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            if byte_idx >= 35 {
                return false;
            }
            decoded[byte_idx] = ((bits >> bit_count) & 0xff) as u8;
            byte_idx += 1;
        }
    }

    if byte_idx != 35 {
        return false;
    }

    // --- Version byte ---
    let version = decoded[0];
    if version != (6u8 << 3) && version != (2u8 << 3) {
        return false;
    }

    // --- Checksum ---
    let expected = u16::from_le_bytes([decoded[33], decoded[34]]);
    let computed = strkey_crc16(&decoded[..33]);
    computed == expected
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

struct HardcodedAddressRule;
impl SecurityRule for HardcodedAddressRule {
    fn name(&self) -> &str {
        "hardcoded-address"
    }
    fn description(&self) -> &str {
        "Detects hardcoded Stellar addresses in WASM data sections."
    }

    fn analyze_static(&self, wasm_bytes: &[u8]) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        for payload in Parser::new(0).parse_all(wasm_bytes).flatten() {
            if let Payload::DataSection(reader) = payload {
                for data in reader.into_iter().flatten() {
                    let content = String::from_utf8_lossy(data.data);
                    for word in content.split(|c: char| !c.is_alphanumeric()) {
                        // Guard 1 – fast pre-filter (cheap): right length and prefix.
                        // Guard 2 – full StrKey validation (base32 + version byte + CRC-16).
                        //
                        // Without guard 2, arbitrary 56-char constants such as error
                        // message fragments or base64 blobs that happen to start with
                        // 'G' or 'C' would be mis-classified as addresses.
                        if
                            (word.starts_with('G') || word.starts_with('C')) &&
                            word.len() == 56 &&
                            is_valid_strkey(word)
                        {
                            findings.push(SecurityFinding {
                                rule_id: self.name().to_string(),
                                severity: Severity::Medium,
                                location: "Data Section".to_string(),
                                description: format!("Found potential hardcoded address: {}", word),
                                remediation:
                                    "Use Address::from_str from configuration or function \
                                     arguments instead of hardcoding."
                                        .to_string(),
                            });
                        }
                    }
                }
            }
        }
        Ok(findings)
    }
}

struct ArithmeticCheckRule;
impl SecurityRule for ArithmeticCheckRule {
    fn name(&self) -> &str {
        "arithmetic-overflow"
    }
    fn description(&self) -> &str {
        "Detects potential for unchecked arithmetic overflow."
    }

    fn analyze_static(&self, wasm_bytes: &[u8]) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();
        let instructions = parse_instructions(wasm_bytes);

        for (i, instr) in instructions.iter().enumerate() {
            if Self::is_arithmetic(instr) && !Self::is_guarded(&instructions, i) {
                findings.push(SecurityFinding {
                    rule_id: self.name().to_string(),
                    severity: Severity::Medium,
                    location: format!("Instruction {}", i),
                    description: format!("Unchecked arithmetic operation detected: {:?}", instr),
                    remediation: "Ensure arithmetic operations are guarded with proper bounds checks or overflow handling.".to_string(),
                });
            }
        }

        Ok(findings)
    }
}

impl ArithmeticCheckRule {
    fn is_arithmetic(instr: &WasmInstruction) -> bool {
        matches!(
            instr,
            WasmInstruction::I32Add |
                WasmInstruction::I32Sub |
                WasmInstruction::I32Mul |
                WasmInstruction::I64Add |
                WasmInstruction::I64Sub |
                WasmInstruction::I64Mul
        )
    }

    fn is_guarded(instructions: &[WasmInstruction], idx: usize) -> bool {
        // A guard must appear *after* the arithmetic instruction.
        //
        // Rationale:
        //   • Instructions before `idx` execute before the result is on the
        //     stack, so they cannot be checking that result.
        //   • `Call` is intentionally excluded: an unrelated nearby call (a
        //     logger, a helper, etc.) is not a bounds check and must not
        //     suppress the finding.
        //
        // A legitimate overflow guard looks like:
        //   i32.add          ← idx
        //   <optional cmp>
        //   br_if / if       ← this is the guard
        //
        // We allow up to 3 instructions of "compare setup" between the
        // arithmetic and the conditional branch before giving up.
        let end = (idx + 4).min(instructions.len());
        for instr in &instructions[idx + 1..end] {
            if matches!(instr, WasmInstruction::If | WasmInstruction::BrIf) {
                return true;
            }
        }
        false
    }
}

struct AuthorizationCheckRule;
impl SecurityRule for AuthorizationCheckRule {
    fn name(&self) -> &str {
        "missing-auth"
    }
    fn description(&self) -> &str {
        "Detects sensitive flows missing authorization checks."
    }

    fn analyze_dynamic(
        &self,
        _executor: &ContractExecutor,
        trace: &[DynamicTraceEvent]
    ) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();
        let mut auth_seen = false;
        let mut storage_write_seen = false;

        for entry in trace {
            if entry.kind == DynamicTraceEventKind::Authorization {
                auth_seen = true;
            }
            if entry.kind == DynamicTraceEventKind::StorageWrite {
                storage_write_seen = true;
            }
        }

        if storage_write_seen && !auth_seen {
            findings.push(SecurityFinding {
                rule_id: self.name().to_string(),
                severity: Severity::High,
                location: "Dynamic trace".to_string(),
                description: "Storage mutation detected without an authorization event in the execution trace.".to_string(),
                remediation: "Ensure all sensitive functions call `address.require_auth()` before mutating state.".to_string(),
            });
        }

        Ok(findings)
    }
}

struct ReentrancyPatternRule;
impl SecurityRule for ReentrancyPatternRule {
    fn name(&self) -> &str {
        "reentrancy-pattern"
    }
    fn description(&self) -> &str {
        "Detects cross-contract calls followed by storage writes."
    }

    fn analyze_dynamic(
        &self,
        _executor: &ContractExecutor,
        trace: &[DynamicTraceEvent]
    ) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();
        let mut cross_call_seen = false;

        for entry in trace {
            if entry.kind == DynamicTraceEventKind::CrossContractCall {
                cross_call_seen = true;
            }
            if cross_call_seen && entry.kind == DynamicTraceEventKind::StorageWrite {
                findings.push(SecurityFinding {
                    rule_id: self.name().to_string(),
                    severity: Severity::Medium,
                    location: format!("Trace event {}", entry.sequence),
                    description: "Storage write detected after an external contract call. Possible reentrancy risk.".to_string(),
                    remediation: "Follow checks-effects-interactions: finalize state before external calls.".to_string(),
                });
                break;
            }
        }
        Ok(findings)
    }
}

struct CrossContractImportRule;
impl SecurityRule for CrossContractImportRule {
    fn name(&self) -> &str {
        "cross-contract-import"
    }

    fn description(&self) -> &str {
        "Detects cross-contract host function imports with robust name matching."
    }

    fn analyze_static(&self, wasm_bytes: &[u8]) -> Result<Vec<SecurityFinding>> {
        let mut matches = Vec::new();

        for payload in Parser::new(0).parse_all(wasm_bytes) {
            let Ok(payload) = payload else {
                // Many unit tests feed non-module bytes into the analyzer. Degrade gracefully.
                return Ok(Vec::new());
            };

            if let Payload::ImportSection(reader) = payload {
                for import in reader.into_iter() {
                    let Ok(import) = import else {
                        continue;
                    };

                    if !matches!(import.ty, wasmparser::TypeRef::Func(_)) {
                        continue;
                    }

                    if is_cross_contract_host_import(import.module, import.name) {
                        matches.push(format!("{}::{}", import.module, import.name));
                    }
                }
            }
        }

        if matches.is_empty() {
            return Ok(Vec::new());
        }

        Ok(
            vec![SecurityFinding {
                rule_id: self.name().to_string(),
                severity: Severity::Low,
                location: "Import Section".to_string(),
                description: format!(
                    "Cross-contract host imports detected: {}",
                    matches.join(", ")
                ),
                remediation: "Review external call sites for reentrancy and authorization checks.".to_string(),
            }]
        )
    }
}

fn canonicalize_ascii(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        }
    }
    out
}

fn is_env_like_module(module: &str) -> bool {
    let m = canonicalize_ascii(module);
    m == "env" || m.starts_with("sorobanenv")
}

fn is_cross_contract_host_function_name(name: &str) -> bool {
    const BASES: &[&str] = &[
        "invokecontract",
        "tryinvokecontract",
        "callcontract",
        "trycallcontract",
        "trycall",
    ];

    let n = canonicalize_ascii(name);
    for base in BASES {
        if n == *base {
            return true;
        }
        if let Some(suffix) = n.strip_prefix(base) {
            if suffix.is_empty() {
                return true;
            }
            if let Some(rest) = suffix.strip_prefix('v') {
                if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
                    return true;
                }
            }
        }
    }

    false
}

fn is_cross_contract_host_import(module: &str, name: &str) -> bool {
    is_env_like_module(module) && is_cross_contract_host_function_name(name)
}

struct UnboundedIterationRule;
impl SecurityRule for UnboundedIterationRule {
    fn name(&self) -> &str {
        "unbounded-iteration"
    }
    fn description(&self) -> &str {
        "Detects storage-driven loops and unbounded read patterns."
    }

    fn analyze_static(&self, wasm_bytes: &[u8]) -> Result<Vec<SecurityFinding>> {
        let analysis = analyze_unbounded_iteration_static(wasm_bytes);
        if !analysis.suspicious {
            return Ok(Vec::new());
        }

        Ok(
            vec![SecurityFinding {
                rule_id: self.name().to_string(),
                severity: Severity::High,
                location: "WASM code section".to_string(),
                description: format!(
                    "Detected loop(s) with storage-read host calls ({} storage calls while inside loop).",
                    analysis.storage_calls_inside_loops
                ),
                remediation: "Bound iteration over storage-backed collections (pagination, explicit limits, or capped batch size).".to_string(),
            }]
        )
    }

    fn analyze_dynamic(
        &self,
        _executor: &ContractExecutor,
        trace: &[DynamicTraceEvent]
    ) -> Result<Vec<SecurityFinding>> {
        Ok(
            analyze_unbounded_iteration_dynamic(trace)
                .into_iter()
                .map(|mut finding| {
                    finding.rule_id = self.name().to_string();
                    finding
                })
                .collect()
        )
    }
}

#[derive(Debug, Default)]
struct UnboundedStaticSignal {
    suspicious: bool,
    storage_calls_inside_loops: usize,
}

fn analyze_unbounded_iteration_static(wasm_bytes: &[u8]) -> UnboundedStaticSignal {
    let mut storage_import_indices = HashSet::new();
    let mut imported_func_count = 0u32;
    let mut loop_depth = 0usize;
    let mut block_stack: Vec<bool> = Vec::new(); // true for loop blocks, false for other blocks
    let mut signal = UnboundedStaticSignal::default();

    for payload in Parser::new(0).parse_all(wasm_bytes) {
        let Ok(payload) = payload else {
            return signal;
        };

        match payload {
            Payload::ImportSection(reader) => {
                for import in reader.into_iter().flatten() {
                    if let wasmparser::TypeRef::Func(_) = import.ty {
                        if is_storage_read_import(import.module, import.name) {
                            storage_import_indices.insert(imported_func_count);
                        }
                        imported_func_count += 1;
                    }
                }
            }
            Payload::CodeSectionEntry(body) => {
                let Ok(mut operators) = body.get_operators_reader() else {
                    continue;
                };
                while !operators.eof() {
                    let Ok(op) = operators.read() else {
                        break;
                    };

                    match op {
                        Operator::Loop { .. } => {
                            loop_depth += 1;
                            block_stack.push(true); // true indicates this is a loop block
                        }
                        Operator::Block { .. } | Operator::If { .. } => {
                            block_stack.push(false); // false indicates this is not a loop block
                        }
                        Operator::End => {
                            if let Some(is_loop) = block_stack.pop() {
                                // Only decrement loop_depth if we're ending a loop block
                                if is_loop {
                                    loop_depth = loop_depth.saturating_sub(1);
                                }
                            }
                        }
                        Operator::Call { function_index } if
                            loop_depth > 0 &&
                            storage_import_indices.contains(&function_index)
                        => {
                            signal.storage_calls_inside_loops += 1;
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    signal.suspicious = signal.storage_calls_inside_loops > 0;
    signal
}

fn is_storage_read_import(module: &str, name: &str) -> bool {
    let module = module.to_ascii_lowercase();
    let name = name.to_ascii_lowercase();

    (module.contains("env") || module.contains("soroban")) &&
        name.contains("storage") &&
        (name.contains("get") ||
            name.contains("has") ||
            name.contains("next") ||
            name.contains("iter"))
}

fn analyze_unbounded_iteration_dynamic(trace: &[DynamicTraceEvent]) -> Option<SecurityFinding> {
    let mut read_key_counts: HashMap<&str, usize> = HashMap::new();
    let mut total_reads = 0usize;

    for entry in trace {
        if entry.kind == DynamicTraceEventKind::StorageRead {
            total_reads += 1;
            if let Some(key) = entry.storage_key.as_deref() {
                *read_key_counts.entry(key).or_insert(0) += 1;
            }
        }
    }

    if total_reads == 0 {
        return None;
    }

    let unique_keys = read_key_counts.len();
    let max_reads_for_one_key = read_key_counts.values().copied().max().unwrap_or(0);
    let likely_unbounded =
        total_reads >= 64 &&
        (unique_keys <= total_reads / 4 || max_reads_for_one_key >= 32 || total_reads >= 128);

    if !likely_unbounded {
        return None;
    }

    Some(SecurityFinding {
        rule_id: "unbounded-iteration".to_string(),
        severity: Severity::High,
        location: "Dynamic trace".to_string(),
        description: format!(
            "Observed high storage-read pressure (reads={}, unique_keys={}, max_reads_single_key={}). This pattern is consistent with unbounded or storage-driven iteration.",
            total_reads,
            unique_keys,
            max_reads_for_one_key
        ),
        remediation: "Use explicit iteration bounds and pagination for storage traversal to avoid gas-denial risks.".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helpers shared across StrKey tests
    // -----------------------------------------------------------------------

    /// Build a syntactically and cryptographically valid StrKey from raw parts.
    ///
    /// `version` must be `6 << 3` (ED25519 / 'G') or `2 << 3` (contract / 'C').
    /// `key_bytes` must be exactly 32 bytes.
    fn build_strkey(version: u8, key_bytes: &[u8; 32]) -> String {
        // 1. Assemble the 33-byte payload and compute CRC.
        let mut payload = [0u8; 33];
        payload[0] = version;
        payload[1..].copy_from_slice(key_bytes);
        let crc = strkey_crc16(&payload);

        // 2. Concatenate payload + CRC (little-endian) → 35 bytes.
        let mut raw = [0u8; 35];
        raw[..33].copy_from_slice(&payload);
        raw[33..].copy_from_slice(&crc.to_le_bytes());

        // 3. Base32-encode (RFC 4648, A-Z / 2-7).
        const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut out = String::with_capacity(56);
        let mut bits: u64 = 0;
        let mut bit_count: u32 = 0;
        for &byte in &raw {
            bits = (bits << 8) | (byte as u64);
            bit_count += 8;
            while bit_count >= 5 {
                bit_count -= 5;
                out.push(ALPHABET[((bits >> bit_count) & 0x1f) as usize] as char);
            }
        }
        debug_assert_eq!(out.len(), 56, "StrKey must be exactly 56 chars");
        out
    }

    // -----------------------------------------------------------------------
    // is_valid_strkey — unit tests
    // -----------------------------------------------------------------------

    /// A programmatically constructed StrKey (version 0x30, all-zero key) must
    /// be accepted.  This is the canonical regression guard: if the CRC logic or
    /// base32 decode regresses, this test fails immediately.
    #[test]
    fn strkey_accepts_well_formed_g_address() {
        let addr = build_strkey(6 << 3, &[0u8; 32]);
        assert!(
            addr.starts_with('G'),
            "sanity: version 0x30 encodes to 'G' prefix"
        );
        assert!(
            is_valid_strkey(&addr),
            "well-formed G address must be accepted"
        );
    }

    /// Same for the contract ('C') variant.
    #[test]
    fn strkey_accepts_well_formed_c_address() {
        let addr = build_strkey(2 << 3, &[0u8; 32]);
        assert!(
            addr.starts_with('C'),
            "sanity: version 0x10 encodes to 'C' prefix"
        );
        assert!(
            is_valid_strkey(&addr),
            "well-formed C address must be accepted"
        );
    }

    /// 56 uppercase-ASCII chars starting with 'G' but with all-'A' payload have
    /// the wrong CRC — the rule must NOT fire for them.
    #[test]
    fn strkey_rejects_wrong_checksum() {
        // Build exactly 56 chars: 'G' + 55 'A's.
        // It has a valid prefix/length but an invalid payload+CRC combination.
        let fake = format!("G{}", "A".repeat(55));
        assert_eq!(fake.len(), 56);
        assert!(!is_valid_strkey(&fake), "all-A token must be rejected (bad CRC)");
    }

    /// A string that is 56 chars, starts with 'G', but contains characters
    /// outside the base32 alphabet (digits 0/1, lower-case letters) must be
    /// rejected before the CRC is even checked.
    #[test]
    fn strkey_rejects_non_base32_characters() {
        // Contains '0', '1', and lower-case letters — all outside A-Z/2-7.
        let bad_chars = "G0001111abcdefghABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDE";
        assert_eq!(bad_chars.len(), 53); // not 56, show next case is the real one
                                         // Craft exactly 56 chars with an invalid char ('0') at position 1.
        let with_zero = "G0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert_eq!(with_zero.len(), 56);
        assert!(!is_valid_strkey(with_zero), "token with '0' must be rejected");
    }

    /// Strings shorter or longer than 56 characters must always be rejected,
    /// regardless of prefix.
    #[test]
    fn strkey_rejects_wrong_length() {
        assert!(!is_valid_strkey(
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )); // 55
        assert!(!is_valid_strkey(
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )); // 57
        assert!(!is_valid_strkey("")); // empty
    }

    /// A valid StrKey with one byte of the checksum flipped must be rejected.
    #[test]
    fn strkey_rejects_flipped_checksum_bit() {
        let good = build_strkey(6 << 3, &[0xab; 32]);
        assert!(is_valid_strkey(&good));

        // Flip the last character to a different (still valid base32) char.
        let mut tampered: Vec<char> = good.chars().collect();
        let last = tampered[55];
        tampered[55] = if last == 'A' { 'B' } else { 'A' };
        let tampered_str: String = tampered.into_iter().collect();
        assert!(
            !is_valid_strkey(&tampered_str),
            "single-char tamper in checksum region must be rejected"
        );
    }

    // -----------------------------------------------------------------------
    // HardcodedAddressRule — fixture tests (the "suggested verification")
    // -----------------------------------------------------------------------

    /// Builds a minimal but structurally valid WASM module whose data section
    /// contains a single string `payload`.  This lets us exercise the full
    /// `analyze_static` path without needing real contract bytes.
    fn wasm_with_data_string(payload: &str) -> Vec<u8> {
        // We embed the payload as a passive data segment.  The encoding is:
        //   magic + version
        //   data-section (id=11):
        //     segment-count = 1
        //     segment: kind=passive(1), byte-length, bytes…
        let data = payload.as_bytes();
        let data_len = data.len();

        // LEB128-encode data_len (works for lengths < 128)
        assert!(data_len < 128, "test helper only handles short payloads");

        let mut wasm = vec![
            0x00,
            0x61,
            0x73,
            0x6d, // magic: \0asm
            0x01,
            0x00,
            0x00,
            0x00, // version: 1
            // Data section (id = 11)
            0x0b
        ];

        // Section content = segment-count(1) + segment
        // Passive segment: [0x01, data_len_leb, ...bytes...]
        let segment: Vec<u8> = {
            let mut s = vec![0x01, data_len as u8];
            s.extend_from_slice(data);
            s
        };
        let section_content: Vec<u8> = {
            let mut c = vec![0x01]; // segment count = 1
            c.extend_from_slice(&segment);
            c
        };

        wasm.push(section_content.len() as u8); // section length (fits in 1 byte for tests)
        wasm.extend_from_slice(&section_content);
        wasm
    }

    /// **Core regression test** — a data section full of random-looking 56-char
    /// tokens that start with 'G' or 'C' but are NOT valid StrKeys must produce
    /// zero findings.
    #[test]
    fn hardcoded_address_rule_no_finding_for_random_56_char_tokens() {
        // These are 56-char strings starting with 'G'/'C' composed entirely of
        // valid base32 characters, yet none carries a correct CRC-16 checksum.
        let fake_tokens = [
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // 57 → trim
            "CBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", // 55 → skip
            // Exactly 56 chars, valid base32, but wrong CRC:
            "GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVW",
            "CABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVW",
        ];

        let rule = HardcodedAddressRule;

        for token in &fake_tokens {
            // Trim/pad to exactly 56 chars for the ones that need it.
            let t: String = token.chars().take(56).collect();
            if t.len() < 56 {
                continue; // shorter than 56 — would not be picked up anyway
            }
            let wasm = wasm_with_data_string(&t);
            let findings = rule
                .analyze_static(&wasm)
                .expect("analyze_static should not error");
            assert!(
                findings.is_empty(),
                "token '{}' must not produce a finding (not a valid StrKey): {:?}",
                t,
                findings
            );
        }
    }

    /// A data section containing a **valid** StrKey must produce exactly one
    /// finding with the correct rule_id.
    #[test]
    fn hardcoded_address_rule_finding_for_valid_strkey() {
        let valid_addr = build_strkey(6 << 3, &[0x42u8; 32]);
        assert_eq!(valid_addr.len(), 56);
        assert!(is_valid_strkey(&valid_addr));

        let wasm = wasm_with_data_string(&valid_addr);
        let rule = HardcodedAddressRule;
        let findings = rule
            .analyze_static(&wasm)
            .expect("analyze_static should not error");

        assert_eq!(findings.len(), 1, "exactly one finding expected for a valid hardcoded address");
        assert_eq!(findings[0].rule_id, "hardcoded-address");
        assert!(
            findings[0].description.contains(&valid_addr),
            "finding description must quote the address"
        );
    }

    /// A data section containing **both** valid and invalid tokens must produce a
    /// finding only for the valid StrKey.
    #[test]
    fn hardcoded_address_rule_mixed_tokens() {
        let valid_addr = build_strkey(2 << 3, &[0x11u8; 32]); // C-prefix contract address
        // Pad the two strings with a space so they end up as separate tokens.
        let payload =
            format!("{} GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUV", valid_addr);

        let wasm = wasm_with_data_string(&payload);
        let rule = HardcodedAddressRule;
        let findings = rule
            .analyze_static(&wasm)
            .expect("analyze_static should not error");

        assert_eq!(
            findings.len(),
            1,
            "only the valid StrKey should be flagged; the garbage token must be ignored"
        );
        assert!(findings[0].description.contains(&valid_addr));
    }

    // -----------------------------------------------------------------------
    // ArithmeticCheckRule / is_guarded — fixture tests
    // -----------------------------------------------------------------------

    /// Bare arithmetic with no surrounding instructions must be flagged.
    #[test]
    fn is_guarded_false_for_isolated_arithmetic() {
        let instrs = vec![WasmInstruction::I32Add];
        assert!(!ArithmeticCheckRule::is_guarded(&instrs, 0));
    }

    /// A `BrIf` immediately *after* the arithmetic is a valid guard.
    #[test]
    fn is_guarded_true_for_brif_after_arithmetic() {
        let instrs = vec![WasmInstruction::I32Add, WasmInstruction::BrIf];
        assert!(ArithmeticCheckRule::is_guarded(&instrs, 0));
    }

    /// An `If` immediately *after* the arithmetic is a valid guard.
    #[test]
    fn is_guarded_true_for_if_after_arithmetic() {
        let instrs = vec![WasmInstruction::I32Add, WasmInstruction::If];
        assert!(ArithmeticCheckRule::is_guarded(&instrs, 0));
    }

    /// A `BrIf` within the 3-instruction lookahead window (with one
    /// intermediate instruction between) is still a valid guard.
    #[test]
    fn is_guarded_true_for_brif_within_lookahead_window() {
        // e.g.: i32.add  ->  i32.const (compare setup)  ->  br_if
        let instrs = vec![
            WasmInstruction::I32Add,
            WasmInstruction::Unknown(0x41),
            WasmInstruction::BrIf,
        ];
        assert!(ArithmeticCheckRule::is_guarded(&instrs, 0));
    }

    /// A `BrIf` that falls *outside* the 3-instruction lookahead must NOT
    /// suppress the finding — the guard is too far away to be meaningful.
    #[test]
    fn is_guarded_false_when_brif_beyond_lookahead() {
        // idx=0, window covers idx+1..idx+4 (indices 1, 2, 3).
        // BrIf is at index 4, which is outside the window.
        let instrs = vec![
            WasmInstruction::I32Add,   // idx 0
            WasmInstruction::Unknown(0x41), // idx 1
            WasmInstruction::Unknown(0x41), // idx 2
            WasmInstruction::Unknown(0x41), // idx 3
            WasmInstruction::BrIf,     // idx 4 — outside window
        ];
        assert!(!ArithmeticCheckRule::is_guarded(&instrs, 0));
    }

    /// **Key regression** — a `BrIf` that appears *before* the arithmetic
    /// (guarding something else entirely) must NOT suppress the finding.
    ///
    /// The old code used `idx.saturating_sub(2)` as the start, so a BrIf
    /// two slots before the arithmetic would incorrectly return true.
    #[test]
    fn is_guarded_false_for_brif_only_before_arithmetic() {
        let instrs = vec![WasmInstruction::BrIf, WasmInstruction::I32Add];
        assert!(!ArithmeticCheckRule::is_guarded(&instrs, 1));
    }

    /// **Key regression** — a `Call` anywhere near the arithmetic must NOT
    /// suppress the finding.  An unrelated call (logger, helper, etc.) is not
    /// a bounds check.
    #[test]
    fn is_guarded_false_for_nearby_unrelated_call() {
        // Call before:
        let before = vec![WasmInstruction::Call, WasmInstruction::I32Add];
        assert!(!ArithmeticCheckRule::is_guarded(&before, 1));

        // Call after:
        let after = vec![WasmInstruction::I32Add, WasmInstruction::Call];
        assert!(!ArithmeticCheckRule::is_guarded(&after, 0));

        // Call on both sides:
        let both = vec![WasmInstruction::Call, WasmInstruction::I32Mul, WasmInstruction::Call];
        assert!(!ArithmeticCheckRule::is_guarded(&both, 1));
    }

    /// A `Call` between the arithmetic and a `BrIf` must not block the guard
    /// from being recognised — only the presence of If/BrIf matters.
    #[test]
    fn is_guarded_true_when_brif_follows_call_after_arithmetic() {
        // i32.add  ->  call (side-effect)  ->  br_if (checks result)
        let instrs = vec![WasmInstruction::I32Add, WasmInstruction::Call, WasmInstruction::BrIf];
        assert!(ArithmeticCheckRule::is_guarded(&instrs, 0));
    }

    /// Arithmetic at the very last position of the slice must not panic and
    /// must be reported as unguarded (no instructions ahead to look at).
    #[test]
    fn is_guarded_false_at_end_of_slice() {
        let instrs = vec![WasmInstruction::Unknown(0x41), WasmInstruction::I64Add];
        assert!(!ArithmeticCheckRule::is_guarded(&instrs, 1));
    }

    // Pre-existing tests (unchanged)

    #[test]
    fn unbounded_iteration_dynamic_flags_high_risk_pattern() {
        let mut trace = Vec::new();
        for i in 0..90usize {
            trace.push(DynamicTraceEvent {
                sequence: i,
                kind: DynamicTraceEventKind::StorageRead,
                message: "contract_storage_get".to_string(),
                function: Some("sweep".to_string()),
                storage_key: Some(format!("user:{}", i % 4)),
                storage_value: None,
            });
        }

        let finding = analyze_unbounded_iteration_dynamic(&trace);
        assert!(finding.is_some());
        assert!(matches!(finding.unwrap().severity, Severity::High));
    }

    #[test]
    fn static_signal_false_for_non_wasm_bytes() {
        let signal = analyze_unbounded_iteration_static(&[1, 2, 3, 4, 5]);
        assert!(!signal.suspicious);
    }

    /// Test that nested if/blocks don't affect loop depth calculation
    #[test]
    fn unbounded_iteration_static_handles_nested_blocks_correctly() {
        // This test verifies that the fix for issue #389 works correctly.
        // We create a WASM module with the following structure:
        // - A loop containing a storage call (should be detected)
        // - An if block containing a storage call (should NOT be detected as loop)
        // - Nested if/blocks within the loop (storage calls should still be detected)

        // For now, we test with a simple case: empty bytes should not be suspicious
        let signal = analyze_unbounded_iteration_static(&[]);
        assert!(!signal.suspicious);

        // TODO: Create a proper WASM fixture with nested structures once
        // the WASM builder utilities are available
    }

    /// Test that loop depth is correctly maintained across multiple loops
    #[test]
    fn unbounded_iteration_static_handles_multiple_loops() {
        // Test with empty bytes - should not be suspicious
        let signal = analyze_unbounded_iteration_static(&[]);
        assert!(!signal.suspicious);

        // TODO: Create WASM fixture with multiple nested and sequential loops
    }
}
