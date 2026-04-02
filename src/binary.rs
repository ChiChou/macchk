use anyhow::{Context, Result};
use goblin::mach::{Mach, MachO, SingleArch};
use memmap2::Mmap;
use std::fs::File;
use std::path::Path;

use crate::detection::{analyze_slice, AnalysisContext};
use crate::types::{AnalysisResult, DetectionLevel, SliceResult};

/// Memory-mapped file handle — keeps the mapping alive while we parse.
pub struct MappedBinary {
    pub mmap: Mmap,
}

impl MappedBinary {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let mmap = unsafe { Mmap::map(&file) }
            .with_context(|| format!("memory-mapping {}", path.display()))?;
        Ok(MappedBinary { mmap })
    }
}

fn arch_string(macho: &MachO) -> String {
    use goblin::mach::constants::cputype::*;
    match (macho.header.cputype(), macho.header.cpusubtype()) {
        (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_E) => "arm64e".to_string(),
        (CPU_TYPE_ARM64, _) => "arm64".to_string(),
        (CPU_TYPE_X86_64, _) => "x86_64".to_string(),
        (cpu, sub) => format!("cpu{}:{}", cpu, sub),
    }
}

fn file_type_string(macho: &MachO) -> String {
    use goblin::mach::header::*;
    match macho.header.filetype {
        MH_EXECUTE => "executable",
        MH_DYLIB => "dylib",
        MH_BUNDLE => "bundle",
        MH_OBJECT => "object",
        MH_DYLINKER => "dylinker",
        MH_KEXT_BUNDLE => "kext",
        _ => "unknown",
    }
    .to_string()
}

fn analyze_one_slice(macho: &MachO, raw: &[u8], level: DetectionLevel) -> Result<SliceResult> {
    if !macho.little_endian {
        anyhow::bail!(
            "big-endian Mach-O not supported (cpu_type={:#x})",
            macho.header.cputype()
        );
    }
    let arch = arch_string(macho);
    let ftype = file_type_string(macho);
    let ctx = AnalysisContext::new(level, macho, raw);
    let checks = analyze_slice(&ctx);
    Ok(SliceResult {
        arch,
        file_type: ftype,
        checks,
    })
}

pub fn analyze_binary(
    path: &Path,
    data: &[u8],
    level: DetectionLevel,
    arch_filter: Option<&str>,
) -> Result<AnalysisResult> {
    // goblin handles both little-endian (MH_MAGIC_64: 0xfeedfacf) and
    // big-endian (MH_CIGAM_64: 0xcffaedfe) Mach-O, as well as fat/universal
    // binaries (always big-endian header: 0xcafebabe / 0xbebafeca).
    let parsed =
        Mach::parse(data).with_context(|| format!("parsing Mach-O: {}", path.display()))?;

    let slices = match parsed {
        Mach::Binary(macho) => {
            let arch = arch_string(&macho);
            if let Some(filter) = arch_filter {
                if arch != filter {
                    return Ok(AnalysisResult {
                        path: path.display().to_string(),
                        slices: vec![],
                    });
                }
            }
            vec![analyze_one_slice(&macho, data, level)?]
        }
        Mach::Fat(fat) => {
            let mut slices = Vec::new();
            for i in 0..fat.narches {
                match fat.get(i) {
                    Ok(SingleArch::MachO(macho)) => {
                        let arch = arch_string(&macho);
                        if let Some(filter) = arch_filter {
                            if arch != filter {
                                continue;
                            }
                        }
                        // For fat binaries, get the slice bytes
                        let arch_entry = fat.iter_arches().nth(i).and_then(|r| r.ok());
                        let slice_data = if let Some(entry) = arch_entry {
                            &data[entry.offset as usize..(entry.offset + entry.size) as usize]
                        } else {
                            data
                        };
                        match analyze_one_slice(&macho, slice_data, level) {
                            Ok(s) => slices.push(s),
                            Err(e) => eprintln!("warning: {}: {}", arch, e),
                        }
                    }
                    Ok(SingleArch::Archive(_)) => {
                        // Skip archive slices in fat binaries
                    }
                    Err(e) => {
                        eprintln!("warning: failed to parse fat arch {}: {}", i, e);
                    }
                }
            }
            slices
        }
    };

    Ok(AnalysisResult {
        path: path.display().to_string(),
        slices,
    })
}
