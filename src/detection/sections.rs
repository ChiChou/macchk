use goblin::mach::header::MH_EXECUTE;

use crate::detection::{AnalysisContext, Check};
use crate::types::*;

pub struct PacSectionsCheck;
impl Check for PacSectionsCheck {
    fn id(&self) -> CheckId {
        CheckId::PacSections
    }
    fn name(&self) -> &'static str {
        "PAC Sections"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Quick
    }
    fn category(&self) -> Category {
        Category::Sections
    }
    fn polarity(&self) -> Polarity {
        Polarity::Positive
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        let pac_names = ["__auth_stubs", "__auth_got", "__auth_ptr"];
        let mut evidence = Vec::new();
        for seg in &ctx.macho.segments {
            if let Ok(sections) = seg.sections() {
                for (sec, _) in &sections {
                    let sname = sec.name().unwrap_or("");
                    if pac_names.contains(&sname) {
                        let seg_name = seg.name().unwrap_or("");
                        evidence.push(Evidence {
                            strategy: "section_name".into(),
                            description: format!(
                                "{}/{} (size: {} bytes)",
                                seg_name, sname, sec.size
                            ),
                            confidence: Confidence::High,
                            address: Some(sec.addr),
                            function_name: None,
                        });
                    }
                }
            }
        }
        let detected = !evidence.is_empty();
        CheckResult {
            id: self.id(),
            name: self.name().into(),
            category: self.category(),
            polarity: self.polarity(),
            detected,
            evidence,
            stats: None,
        }
    }
}

pub struct DataConstCheck;
impl Check for DataConstCheck {
    fn id(&self) -> CheckId {
        CheckId::DataConst
    }
    fn name(&self) -> &'static str {
        "__DATA_CONST"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Quick
    }
    fn category(&self) -> Category {
        Category::Sections
    }
    fn polarity(&self) -> Polarity {
        Polarity::Positive
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        let mut detected = false;
        let mut evidence = Vec::new();
        for seg in &ctx.macho.segments {
            let name = seg.name().unwrap_or("");
            if name == "__DATA_CONST" {
                detected = true;
                evidence.push(Evidence {
                    strategy: "segment_name".into(),
                    description: format!(
                        "__DATA_CONST segment: vmaddr={:#x}, vmsize={:#x} (read-only after fixups)",
                        seg.vmaddr, seg.vmsize
                    ),
                    confidence: Confidence::High,
                    address: Some(seg.vmaddr),
                    function_name: None,
                });
                break;
            }
        }
        CheckResult {
            id: self.id(),
            name: self.name().into(),
            category: self.category(),
            polarity: self.polarity(),
            detected,
            evidence,
            stats: None,
        }
    }
}

pub struct PageZeroCheck;
impl Check for PageZeroCheck {
    fn id(&self) -> CheckId {
        CheckId::PageZero
    }
    fn name(&self) -> &'static str {
        "__PAGEZERO"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Quick
    }
    fn category(&self) -> Category {
        Category::Sections
    }
    fn polarity(&self) -> Polarity {
        Polarity::Positive
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        if ctx.macho.header.filetype != MH_EXECUTE {
            return CheckResult {
                id: self.id(),
                name: self.name().into(),
                category: self.category(),
                polarity: Polarity::Info,
                detected: false,
                evidence: vec![Evidence {
                    strategy: "filetype_guard".into(),
                    description: "not applicable (MH_EXECUTE only)".into(),
                    confidence: Confidence::Definitive,
                    address: None,
                    function_name: None,
                }],
                stats: None,
            };
        }
        let mut evidence = Vec::new();
        for seg in &ctx.macho.segments {
            let name = seg.name().unwrap_or("");
            if name != "__PAGEZERO" {
                continue;
            }
            let vmsize = seg.vmsize;
            let prot = seg.initprot;
            let expected = 0x100000000u64;
            evidence.push(Evidence {
                strategy: "segment".into(),
                description: format!(
                    "__PAGEZERO: vmsize={:#x}, prot={:#x}{}",
                    vmsize,
                    prot,
                    if vmsize == 0 {
                        " [WARNING: zero-sized, no NULL page protection]"
                    } else if vmsize < expected {
                        " [NOTE: smaller than typical]"
                    } else {
                        ""
                    }
                ),
                confidence: Confidence::Definitive,
                address: Some(seg.vmaddr),
                function_name: None,
            });
            break;
        }
        if evidence.is_empty() {
            evidence.push(Evidence {
                strategy: "segment".into(),
                description: "no __PAGEZERO segment present [WARNING: no NULL page protection]"
                    .into(),
                confidence: Confidence::Definitive,
                address: None,
                function_name: None,
            });
        }
        let has_pagezero = evidence.iter().any(|e| {
            !e.description.contains("no __PAGEZERO") && !e.description.contains("zero-sized")
        });
        CheckResult {
            id: self.id(),
            name: self.name().into(),
            category: self.category(),
            polarity: self.polarity(),
            detected: has_pagezero,
            evidence,
            stats: None,
        }
    }
}

pub struct SegmentPermissionsCheck;
impl Check for SegmentPermissionsCheck {
    fn id(&self) -> CheckId {
        CheckId::SegmentPermissions
    }
    fn name(&self) -> &'static str {
        "Segment Permissions"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Quick
    }
    fn category(&self) -> Category {
        Category::Sections
    }
    fn polarity(&self) -> Polarity {
        Polarity::Info
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        let mut evidence = Vec::new();
        let mut has_rwx = false;
        for seg in &ctx.macho.segments {
            let name = seg.name().unwrap_or("");
            if name.is_empty() || name == "__PAGEZERO" {
                continue;
            }
            let initprot = seg.initprot;
            let r = if initprot & 1 != 0 { "r" } else { "-" };
            let w = if initprot & 2 != 0 { "w" } else { "-" };
            let x = if initprot & 4 != 0 { "x" } else { "-" };
            let perm_str = format!("{}{}{}", r, w, x);
            let is_rwx = initprot & 7 == 7;
            if is_rwx {
                has_rwx = true;
            }
            evidence.push(Evidence {
                strategy: "segment_prot".into(),
                description: format!(
                    "{}: {} (vmaddr={:#x}, vmsize={:#x}){}",
                    name,
                    perm_str,
                    seg.vmaddr,
                    seg.vmsize,
                    if is_rwx { " [WARNING: rwx]" } else { "" }
                ),
                confidence: Confidence::Definitive,
                address: Some(seg.vmaddr),
                function_name: None,
            });
        }
        CheckResult {
            id: self.id(),
            name: self.name().into(),
            category: self.category(),
            polarity: if has_rwx {
                Polarity::Negative
            } else {
                Polarity::Info
            },
            detected: has_rwx,
            evidence,
            stats: None,
        }
    }
}
