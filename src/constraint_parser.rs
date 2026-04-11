//! Decoder for Apple launch/library constraint DER blobs.
//!
//! Launch constraints are DER-encoded using Apple's CoreEntitlements format.
//! The blob (after the 8-byte `0xfade8181` header) has this structure:
//!
//! ```text
//! [APPLICATION 16] CONSTRUCTED {      -- tag 0x70, outer envelope
//!     INTEGER version,                -- always 1
//!     [CONTEXT 16] CONSTRUCTED {      -- tag 0xb0, constraint body
//!         SEQUENCE { key, value }*    -- key-value pairs
//!     }
//! }
//! ```
//!
//! Keys are abbreviated UTF8Strings:
//!   "ccat" = constraint category (validation-category)
//!   "comp" = component type
//!   "reqs" = requirements (nested constraint facts)
//!   "vers" = format version

use serde::Serialize;

// DER tag constants
const TAG_BOOLEAN: u8 = 0x01;
const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_UTF8STRING: u8 = 0x0c;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_ENVELOPE: u8 = 0x70; // Application, Constructed, tag 16
const TAG_CONTAINER: u8 = 0xb0; // Context-specific, Constructed, tag 16

/// Validation category values from cs_blobs.h.
fn validation_category_name(val: i64) -> &'static str {
    match val {
        0 => "none",
        1 => "platform",
        2 => "TestFlight",
        3 => "development",
        4 => "App Store",
        5 => "enterprise",
        6 => "Developer ID",
        7..=9 => "system-generated",
        10 => "unsigned",
        _ => "unknown",
    }
}

/// A decoded constraint value.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum ConstraintValue {
    Bool(bool),
    Int(i64),
    Str(String),
    Bytes(Vec<u8>),
    Dict(Vec<ConstraintEntry>),
}

/// A key-value entry in a constraint dictionary.
#[derive(Clone, Debug, Serialize)]
pub struct ConstraintEntry {
    pub key: String,
    pub value: ConstraintValue,
}

/// A fully decoded constraint from one slot.
#[derive(Clone, Debug, Serialize)]
pub struct DecodedConstraint {
    pub version: i64,
    pub constraint_category: Option<i64>,
    pub entries: Vec<ConstraintEntry>,
}

impl DecodedConstraint {
    /// Format as human-readable lines for display.
    pub fn describe(&self) -> Vec<String> {
        let mut lines = Vec::new();

        if let Some(ccat) = self.constraint_category {
            if ccat != 0 {
                lines.push(format!(
                    "validation-category: {} ({})",
                    validation_category_name(ccat),
                    ccat
                ));
            }
        }

        // Collect requirement facts
        for entry in &self.entries {
            if entry.key == "requirements" {
                if let ConstraintValue::Dict(ref facts) = entry.value {
                    collect_fact_lines(facts, &mut lines, 0);
                }
            }
        }

        lines
    }
}

/// Recursively collect fact lines, expanding logical operators into multiple lines.
fn collect_fact_lines(facts: &[ConstraintEntry], lines: &mut Vec<String>, depth: usize) {
    let indent = "  ".repeat(depth);
    for entry in facts {
        match (&entry.key as &str, &entry.value) {
            // Logical operators: expand children
            (op @ ("$or" | "$and" | "$optional"), ConstraintValue::Dict(children)) => {
                lines.push(format!("{}{}", indent, op));
                collect_fact_lines(children, lines, depth + 1);
            }
            // Nested dict that isn't an operator (e.g., a sub-requirement)
            (key, ConstraintValue::Dict(children)) if !is_operator(key) => {
                lines.push(format!("{}{}:", indent, key));
                collect_fact_lines(children, lines, depth + 1);
            }
            // Leaf facts
            _ => {
                lines.push(format!("{}{}", indent, format_fact(entry)));
            }
        }
    }
}

fn is_operator(key: &str) -> bool {
    key.starts_with('$')
}

/// Launch type values from AMFI.
fn launch_type_name(val: i64) -> Option<&'static str> {
    match val {
        1 => Some("launchd daemon/agent"),
        2 => Some("on-demand (XPC/sysdiagnose)"),
        3 => Some("app launch"),
        _ => None,
    }
}

fn format_fact(entry: &ConstraintEntry) -> String {
    match &entry.value {
        ConstraintValue::Bool(b) => format!("{} = {}", entry.key, b),
        ConstraintValue::Int(i) => {
            if entry.key == "validation-category" {
                format!("{} = {} ({})", entry.key, validation_category_name(*i), i)
            } else if entry.key == "launch-type" {
                if let Some(name) = launch_type_name(*i) {
                    format!("{} = {} ({})", entry.key, name, i)
                } else {
                    format!("{} = {}", entry.key, i)
                }
            } else {
                format!("{} = {}", entry.key, i)
            }
        }
        ConstraintValue::Str(s) => format!("{} = \"{}\"", entry.key, s),
        ConstraintValue::Bytes(b) => {
            let hex: String = b.iter().map(|byte| format!("{:02x}", byte)).collect();
            format!("{} = h\"{}\"", entry.key, hex)
        }
        ConstraintValue::Dict(entries) => {
            let inner: Vec<String> = entries.iter().map(format_fact).collect();
            format!("{}: {{ {} }}", entry.key, inner.join(", "))
        }
    }
}

/// Expand abbreviated DER keys to their full human-readable names.
fn expand_key(abbr: &str) -> &str {
    match abbr {
        "ccat" => "validation-category",
        "comp" => "component",
        "reqs" => "requirements",
        "vers" => "format-version",
        // Fact keys that appear under "reqs" — pass through as-is
        _ => abbr,
    }
}

/// Parse the DER data from a launch constraint blob (after the 8-byte header).
pub fn decode_constraint(der: &[u8]) -> Option<DecodedConstraint> {
    let (tag, content) = read_tlv(der)?;
    if tag != TAG_ENVELOPE {
        return None;
    }

    let mut pos = 0;

    // Read version INTEGER
    let (vtag, vbytes) = read_tlv(&content[pos..])?;
    pos += tlv_total_len(&content[pos..])?;
    if vtag != TAG_INTEGER {
        return None;
    }
    let version = parse_integer(vbytes);

    // Read body container
    let (btag, body) = read_tlv(&content[pos..])?;
    if btag != TAG_CONTAINER {
        return None;
    }

    let entries = parse_dict(body);

    // Extract constraint category from entries
    let constraint_category = entries.iter().find_map(|e| {
        if e.key == "validation-category" {
            if let ConstraintValue::Int(v) = &e.value {
                return Some(*v);
            }
        }
        None
    });

    Some(DecodedConstraint {
        version,
        constraint_category,
        entries,
    })
}

/// Parse a sequence of SEQUENCE { key, value } pairs from a container.
fn parse_dict(data: &[u8]) -> Vec<ConstraintEntry> {
    let mut entries = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        let Some((tag, content)) = read_tlv(&data[pos..]) else {
            break;
        };
        let Some(advance) = tlv_total_len(&data[pos..]) else {
            break;
        };
        pos += advance;

        if tag != TAG_SEQUENCE {
            continue;
        }

        // Each SEQUENCE contains: UTF8String key, then a value
        let Some((ktag, kbytes)) = read_tlv(content) else {
            continue;
        };
        if ktag != TAG_UTF8STRING {
            continue;
        }
        let raw_key = String::from_utf8_lossy(kbytes).to_string();
        let key = expand_key(&raw_key).to_string();

        let Some(key_len) = tlv_total_len(content) else {
            continue;
        };
        if key_len >= content.len() {
            // Key-only entry (no value), skip
            continue;
        }
        let value_data = &content[key_len..];
        let value = parse_value(value_data);

        entries.push(ConstraintEntry { key, value });
    }

    entries
}

/// Parse a single DER value.
fn parse_value(data: &[u8]) -> ConstraintValue {
    let Some((tag, content)) = read_tlv(data) else {
        return ConstraintValue::Bytes(data.to_vec());
    };

    match tag {
        TAG_BOOLEAN => {
            let val = !content.is_empty() && content[0] != 0;
            ConstraintValue::Bool(val)
        }
        TAG_INTEGER => ConstraintValue::Int(parse_integer(content)),
        TAG_UTF8STRING => ConstraintValue::Str(String::from_utf8_lossy(content).to_string()),
        TAG_OCTET_STRING => ConstraintValue::Bytes(content.to_vec()),
        TAG_CONTAINER => {
            // Nested dictionary (e.g., $or, $and, requirements)
            ConstraintValue::Dict(parse_dict(content))
        }
        TAG_SEQUENCE => {
            // Array of values — parse as dict since Apple uses SEQUENCE for kv pairs
            let mut entries = Vec::new();
            // Re-parse from the start of data since this is a sequence of sequences
            entries.extend(parse_dict(data));
            if entries.is_empty() {
                ConstraintValue::Bytes(data.to_vec())
            } else {
                ConstraintValue::Dict(entries)
            }
        }
        _ => ConstraintValue::Bytes(content.to_vec()),
    }
}

/// Parse a DER-encoded signed integer.
fn parse_integer(bytes: &[u8]) -> i64 {
    if bytes.is_empty() {
        return 0;
    }
    let mut val: i64 = if bytes[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in bytes {
        val = (val << 8) | b as i64;
    }
    val
}

/// Read a DER TLV (tag-length-value) at the start of `data`.
/// Returns (tag, value_bytes).
fn read_tlv(data: &[u8]) -> Option<(u8, &[u8])> {
    if data.is_empty() {
        return None;
    }
    let tag = data[0];
    let (length, header_len) = read_der_length(&data[1..])?;
    let total_header = 1 + header_len;
    let end = total_header + length;
    if end > data.len() {
        return None;
    }
    Some((tag, &data[total_header..end]))
}

/// Compute the total byte length of a TLV at the start of `data`.
fn tlv_total_len(data: &[u8]) -> Option<usize> {
    if data.is_empty() {
        return None;
    }
    let (length, header_len) = read_der_length(&data[1..])?;
    Some(1 + header_len + length)
}

/// Read a DER length encoding. Returns (length_value, bytes_consumed).
fn read_der_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    if data[0] < 0x80 {
        // Short form
        Some((data[0] as usize, 1))
    } else if data[0] == 0x80 {
        // Indefinite form — not used in Apple's encoding
        None
    } else {
        // Long form
        let num_bytes = (data[0] & 0x7f) as usize;
        if num_bytes > 4 || 1 + num_bytes > data.len() {
            return None;
        }
        let mut length: usize = 0;
        for i in 0..num_bytes {
            length = (length << 8) | data[1 + i] as usize;
        }
        Some((length, 1 + num_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // xpcproxy self constraint: ccat=1 (platform), no requirements
    // Raw DER from /usr/libexec/xpcproxy
    const XPCPROXY_SELF: &[u8] = &[
        0x70, 0x26, 0x02, 0x01, 0x01, 0xb0, 0x21, 0x30, 0x09, 0x0c, 0x04, 0x63, 0x63, 0x61, 0x74,
        0x02, 0x01, 0x01, 0x30, 0x09, 0x0c, 0x04, 0x63, 0x6f, 0x6d, 0x70, 0x02, 0x01, 0x01, 0x30,
        0x09, 0x0c, 0x04, 0x76, 0x65, 0x72, 0x73, 0x02, 0x01, 0x01,
    ];

    // launchd parent constraint: ccat=0, reqs: is-kernel-proc=true
    const LAUNCHD_PARENT: &[u8] = &[
        0x70, 0x45, 0x02, 0x01, 0x01, 0xb0, 0x40, 0x30, 0x09, 0x0c, 0x04, 0x63, 0x63, 0x61, 0x74,
        0x02, 0x01, 0x00, 0x30, 0x09, 0x0c, 0x04, 0x63, 0x6f, 0x6d, 0x70, 0x02, 0x01, 0x01, 0x30,
        0x1d, 0x0c, 0x04, 0x72, 0x65, 0x71, 0x73, 0xb0, 0x15, 0x30, 0x13, 0x0c, 0x0e, 0x69, 0x73,
        0x2d, 0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x2d, 0x70, 0x72, 0x6f, 0x63, 0x01, 0x01, 0xff,
        0x30, 0x09, 0x0c, 0x04, 0x76, 0x65, 0x72, 0x73, 0x02, 0x01, 0x01,
    ];

    // gputoolsserviced parent constraint: ccat=0, reqs: is-init-proc=true
    const GPUTOOLS_PARENT: &[u8] = &[
        0x70, 0x43, 0x02, 0x01, 0x01, 0xb0, 0x3e, 0x30, 0x09, 0x0c, 0x04, 0x63, 0x63, 0x61, 0x74,
        0x02, 0x01, 0x00, 0x30, 0x09, 0x0c, 0x04, 0x63, 0x6f, 0x6d, 0x70, 0x02, 0x01, 0x01, 0x30,
        0x1b, 0x0c, 0x04, 0x72, 0x65, 0x71, 0x73, 0xb0, 0x13, 0x30, 0x11, 0x0c, 0x0c, 0x69, 0x73,
        0x2d, 0x69, 0x6e, 0x69, 0x74, 0x2d, 0x70, 0x72, 0x6f, 0x63, 0x01, 0x01, 0xff, 0x30, 0x09,
        0x0c, 0x04, 0x76, 0x65, 0x72, 0x73, 0x02, 0x01, 0x01,
    ];

    #[test]
    fn decode_platform_constraint() {
        let decoded = decode_constraint(XPCPROXY_SELF).expect("failed to decode");
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.constraint_category, Some(1));
        let lines = decoded.describe();
        assert!(
            lines.iter().any(|l| l.contains("platform")),
            "expected 'platform' in output, got: {:?}",
            lines
        );
    }

    #[test]
    fn decode_kernel_proc_constraint() {
        let decoded = decode_constraint(LAUNCHD_PARENT).expect("failed to decode");
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.constraint_category, Some(0));
        let lines = decoded.describe();
        assert!(
            lines.iter().any(|l| l.contains("is-kernel-proc")),
            "expected 'is-kernel-proc' in output, got: {:?}",
            lines
        );
    }

    #[test]
    fn decode_init_proc_constraint() {
        let decoded = decode_constraint(GPUTOOLS_PARENT).expect("failed to decode");
        let lines = decoded.describe();
        assert!(
            lines.iter().any(|l| l.contains("is-init-proc")),
            "expected 'is-init-proc' in output, got: {:?}",
            lines
        );
    }

    #[test]
    fn decode_rejects_invalid_data() {
        assert!(decode_constraint(&[]).is_none());
        assert!(decode_constraint(&[0xFF, 0x00]).is_none());
        assert!(decode_constraint(&[0x70, 0x00]).is_none());
    }

    #[test]
    fn ccat_zero_suppressed_in_describe() {
        let decoded = decode_constraint(LAUNCHD_PARENT).expect("failed to decode");
        let lines = decoded.describe();
        assert!(
            !lines
                .iter()
                .any(|l| l.starts_with("validation-category: none")),
            "ccat=0 should be suppressed, got: {:?}",
            lines
        );
    }

    #[test]
    fn ccat_nonzero_shown_in_describe() {
        let decoded = decode_constraint(XPCPROXY_SELF).expect("failed to decode");
        let lines = decoded.describe();
        assert!(
            lines.iter().any(|l| l.starts_with("validation-category:")),
            "ccat=1 should be shown, got: {:?}",
            lines
        );
    }
}
