use std::path::PathBuf;
use std::process;

use clap::Parser;

use macchk::binary::{analyze_binary, MappedBinary};
use macchk::output::{self, OutputFormat};
use macchk::types::DetectionLevel;

#[derive(Parser)]
#[command(
    name = "macchk",
    about = "Security analysis tool for Mach-O binaries",
    version
)]
struct Cli {
    /// Binary file(s) to analyze
    #[arg(required = true)]
    files: Vec<PathBuf>,

    /// Detection level: quick, standard, full
    #[arg(short, long, default_value = "standard")]
    level: String,

    /// Output as JSON
    #[arg(long)]
    json: bool,

    /// Brief one-liner output
    #[arg(long)]
    brief: bool,

    /// Analyze only a specific architecture from universal binaries
    #[arg(long)]
    arch: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    let level = match cli.level.as_str() {
        "quick" | "q" => DetectionLevel::Quick,
        "standard" | "s" => DetectionLevel::Standard,
        "full" | "f" => DetectionLevel::Full,
        other => {
            eprintln!("error: unknown detection level '{}' (use quick, standard, or full)", other);
            process::exit(1);
        }
    };

    let format = if cli.json {
        OutputFormat::Json
    } else if cli.brief {
        OutputFormat::Brief
    } else {
        OutputFormat::Table
    };

    let mut any_error = false;

    for path in &cli.files {
        let mapped = match MappedBinary::open(path) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("error: {}: {}", path.display(), e);
                any_error = true;
                continue;
            }
        };

        match analyze_binary(path, &mapped.mmap, level, cli.arch.as_deref()) {
            Ok(result) => {
                output::print_result(&result, &format);
            }
            Err(e) => {
                eprintln!("error: {}: {}", path.display(), e);
                any_error = true;
            }
        }
    }

    if any_error {
        process::exit(1);
    }
}
