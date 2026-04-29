use wasm_bindgen::prelude::*;

use crate::binary::analyze_binary_buf;
use crate::types::DetectionLevel;

#[wasm_bindgen]
pub fn analyze(
    data: &[u8],
    level: Option<String>,
    arch: Option<String>,
) -> Result<String, JsError> {
    let level = match level.as_deref() {
        Some("quick" | "q") => DetectionLevel::Quick,
        Some("full" | "f") => DetectionLevel::Full,
        _ => DetectionLevel::Standard,
    };

    let result = analyze_binary_buf("input", data, level, arch.as_deref())
        .map_err(|e| JsError::new(&e.to_string()))?;

    serde_json::to_string(&result).map_err(|e| JsError::new(&e.to_string()))
}
