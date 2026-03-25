use soroban_debugger::debugger::source_map::{SourceLocation, SourceMap};
use std::collections::HashSet;
use std::path::Path;

fn uleb(mut value: u32) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}

fn section(id: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut out = vec![id];
    out.extend(uleb(payload.len() as u32));
    out.extend(payload);
    out
}

fn minimal_two_export_wasm() -> Vec<u8> {
    let mut module = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];

    // Type section: 1 type: (func) -> ()
    let mut type_payload = Vec::new();
    type_payload.extend(uleb(1));
    type_payload.push(0x60);
    type_payload.extend(uleb(0));
    type_payload.extend(uleb(0));
    module.extend(section(1, type_payload));

    // Function section: 2 functions, both type 0
    let mut func_payload = Vec::new();
    func_payload.extend(uleb(2));
    func_payload.extend(uleb(0));
    func_payload.extend(uleb(0));
    module.extend(section(3, func_payload));

    // Export section: export func 0 as "foo", func 1 as "bar"
    let mut export_payload = Vec::new();
    export_payload.extend(uleb(2));
    export_payload.extend(uleb(3));
    export_payload.extend(b"foo");
    export_payload.push(0x00);
    export_payload.extend(uleb(0));
    export_payload.extend(uleb(3));
    export_payload.extend(b"bar");
    export_payload.push(0x00);
    export_payload.extend(uleb(1));
    module.extend(section(7, export_payload));

    // Code section: 2 bodies, each: locals=0, end
    let body = vec![0x00, 0x0B];
    let mut code_payload = Vec::new();
    code_payload.extend(uleb(2));
    code_payload.extend(uleb(body.len() as u32));
    code_payload.extend(body.iter().copied());
    code_payload.extend(uleb(body.len() as u32));
    code_payload.extend(body);
    module.extend(section(10, code_payload));

    module
}

fn code_entry_ranges(wasm: &[u8]) -> Vec<std::ops::Range<usize>> {
    let mut ranges = Vec::new();
    for payload in wasmparser::Parser::new(0).parse_all(wasm) {
        let payload = payload.expect("wasm should parse");
        if let wasmparser::Payload::CodeSectionEntry(body) = payload {
            ranges.push(body.range());
        }
    }
    ranges
}

#[test]
fn resolves_ambiguous_multi_function_line_as_unverified() {
    let wasm = minimal_two_export_wasm();
    let ranges = code_entry_ranges(&wasm);
    assert_eq!(ranges.len(), 2);

    let mut sm = SourceMap::new();
    sm.add_mapping(
        ranges[0].start,
        SourceLocation {
            file: "src/contract.rs".into(),
            line: 10,
            column: None,
        },
    );
    sm.add_mapping(
        ranges[1].start,
        SourceLocation {
            file: "src/contract.rs".into(),
            line: 10,
            column: None,
        },
    );

    let exported: HashSet<String> = ["foo".to_string(), "bar".to_string()].into_iter().collect();
    let resolved =
        sm.resolve_source_breakpoints(&wasm, Path::new("src/contract.rs"), &[10], &exported);

    assert_eq!(resolved.len(), 1);
    assert!(!resolved[0].verified);
    assert_eq!(resolved[0].reason_code, "AMBIGUOUS");
    assert!(resolved[0].function.is_none());
}

#[test]
fn resolves_non_entrypoint_line_as_unverified_not_exported() {
    let wasm = minimal_two_export_wasm();
    let ranges = code_entry_ranges(&wasm);
    assert_eq!(ranges.len(), 2);

    let mut sm = SourceMap::new();
    // Map to the second function (bar) but only allow "foo" entrypoint.
    sm.add_mapping(
        ranges[1].start,
        SourceLocation {
            file: "src/contract.rs".into(),
            line: 20,
            column: None,
        },
    );

    let exported: HashSet<String> = ["foo".to_string()].into_iter().collect();
    let resolved =
        sm.resolve_source_breakpoints(&wasm, Path::new("src/contract.rs"), &[20], &exported);

    assert_eq!(resolved.len(), 1);
    assert!(!resolved[0].verified);
    assert_eq!(resolved[0].reason_code, "NOT_EXPORTED");
}

#[test]
fn resolves_to_next_executable_line_when_requested_line_has_no_code() {
    let wasm = minimal_two_export_wasm();
    let ranges = code_entry_ranges(&wasm);
    assert_eq!(ranges.len(), 2);

    let mut sm = SourceMap::new();
    // Only line 31 has code, but user requests 30.
    sm.add_mapping(
        ranges[0].start,
        SourceLocation {
            file: "src/contract.rs".into(),
            line: 31,
            column: None,
        },
    );

    let exported: HashSet<String> = ["foo".to_string(), "bar".to_string()].into_iter().collect();
    let resolved =
        sm.resolve_source_breakpoints(&wasm, Path::new("src/contract.rs"), &[30], &exported);

    assert_eq!(resolved.len(), 1);
    assert!(resolved[0].verified);
    assert_eq!(resolved[0].reason_code, "ADJUSTED");
    assert_eq!(resolved[0].requested_line, 30);
    assert_eq!(resolved[0].line, 31);
    assert_eq!(resolved[0].function.as_deref(), Some("foo"));
}
