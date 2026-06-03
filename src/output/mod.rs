pub mod brief;
pub mod json;
pub mod table;

use crate::types::AnalysisResult;

pub enum OutputFormat {
    Table,
    Json,
    Brief,
}

pub fn print_result(result: &AnalysisResult, format: &OutputFormat) {
    match format {
        OutputFormat::Table => table::print(result),
        OutputFormat::Json => json::print(result),
        OutputFormat::Brief => brief::print(result),
    }
}
