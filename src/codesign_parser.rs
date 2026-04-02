use anyhow::{bail, Result};
use goblin::mach::load_command::CommandVariant;
use goblin::mach::MachO;
use scroll::{Pread, BE};
use serde::Serialize;

// Magic numbers from cs_blobs.h
const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade0cc0;
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade0c02;
const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xfade7171;
const CSMAGIC_BLOBWRAPPER: u32 = 0xfade0b01; // CMS signature
const CSMAGIC_LAUNCH_CONSTRAINT: u32 = 0xfade8181;

// Slot indices
const CSSLOT_CODEDIRECTORY: u32 = 0;
const CSSLOT_ENTITLEMENTS: u32 = 5;
const CSSLOT_LAUNCH_CONSTRAINT_SELF: u32 = 8;
const CSSLOT_LAUNCH_CONSTRAINT_PARENT: u32 = 9;
const CSSLOT_LAUNCH_CONSTRAINT_RESPONSIBLE: u32 = 10;
const CSSLOT_LIBRARY_CONSTRAINT: u32 = 11;
const CSSLOT_SIGNATURESLOT: u32 = 0x10000;

// CS flags
pub const CS_VALID: u32 = 0x00000001;
pub const CS_ADHOC: u32 = 0x00000002;
pub const CS_GET_TASK_ALLOW: u32 = 0x00000004;
pub const CS_HARD: u32 = 0x00000100;
pub const CS_KILL: u32 = 0x00000200;
pub const CS_RESTRICT: u32 = 0x00000800;
pub const CS_ENFORCEMENT: u32 = 0x00001000;
pub const CS_REQUIRE_LV: u32 = 0x00002000;
pub const CS_RUNTIME: u32 = 0x00010000;
pub const CS_LINKER_SIGNED: u32 = 0x00020000;

// CodeDirectory versions
const CS_SUPPORTSRUNTIME: u32 = 0x20500;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningType {
    Unsigned,
    LinkerSigned,
    AdHoc,
    DeveloperSigned,
    PlatformBinary,
}

/// Which launch/library constraint slots are present in the code signature,
/// along with the raw DER bytes (after the 8-byte blob header) for decoding.
#[derive(Clone, Debug, Default, Serialize)]
pub struct LaunchConstraints {
    #[serde(skip)]
    pub self_der: Option<Vec<u8>>,
    #[serde(skip)]
    pub parent_der: Option<Vec<u8>>,
    #[serde(skip)]
    pub responsible_der: Option<Vec<u8>>,
    #[serde(skip)]
    pub library_der: Option<Vec<u8>>,
}

impl LaunchConstraints {
    pub fn any(&self) -> bool {
        self.self_der.is_some()
            || self.parent_der.is_some()
            || self.responsible_der.is_some()
            || self.library_der.is_some()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CodeSignInfo {
    pub flags: u32,
    pub platform: u8,
    pub version: u32,
    pub signing_type: SigningType,
    pub team_id: Option<String>,
    pub entitlements_xml: Option<String>,
    pub runtime_version: Option<u32>,
    pub launch_constraints: LaunchConstraints,
    /// Hash types found across all CodeDirectory blobs (primary + alternatives).
    /// Values: 1=SHA-1, 2=SHA-256/truncated, 3=SHA-256, 4=SHA-384, 5=SHA-512.
    pub hash_types: Vec<u8>,
}

impl CodeSignInfo {
    pub fn has_flag(&self, flag: u32) -> bool {
        self.flags & flag != 0
    }
}

pub fn parse_codesign(macho: &MachO, raw_bytes: &[u8]) -> Result<Option<CodeSignInfo>> {
    // Find LC_CODE_SIGNATURE
    let mut cs_offset = 0u32;
    let mut cs_size = 0u32;
    for lc in &macho.load_commands {
        if let CommandVariant::CodeSignature(cs) = lc.command {
            cs_offset = cs.dataoff;
            cs_size = cs.datasize;
            break;
        }
    }
    if cs_offset == 0 || cs_size == 0 {
        return Ok(None);
    }

    let cs_data = raw_bytes
        .get(cs_offset as usize..(cs_offset + cs_size) as usize)
        .ok_or_else(|| anyhow::anyhow!("code signature data out of bounds"))?;

    // Parse SuperBlob header
    let magic: u32 = cs_data.pread_with(0, BE)?;
    if magic != CSMAGIC_EMBEDDED_SIGNATURE {
        bail!("unexpected code signature magic: {:#x}", magic);
    }
    let _length: u32 = cs_data.pread_with(4, BE)?;
    let count: u32 = cs_data.pread_with(8, BE)?;

    // Parse blob index entries
    let mut cd_blob: Option<(usize, usize)> = None;
    let mut alt_cd_blobs: Vec<(usize, usize)> = Vec::new();
    let mut ent_blob: Option<(usize, usize)> = None;
    let mut has_cms = false;
    let mut launch_constraints = LaunchConstraints::default();

    for i in 0..count {
        let idx_offset = 12 + (i as usize) * 8;
        let slot_type: u32 = cs_data.pread_with(idx_offset, BE)?;
        let blob_offset: u32 = cs_data.pread_with(idx_offset + 4, BE)?;
        let blob_off = blob_offset as usize;

        if blob_off + 8 > cs_data.len() { continue; }
        let blob_magic: u32 = cs_data.pread_with(blob_off, BE)?;
        let blob_length: u32 = cs_data.pread_with(blob_off + 4, BE)?;

        match slot_type {
            CSSLOT_CODEDIRECTORY => {
                if blob_magic == CSMAGIC_CODEDIRECTORY {
                    cd_blob = Some((blob_off, blob_length as usize));
                }
            }
            CSSLOT_ENTITLEMENTS => {
                if blob_magic == CSMAGIC_EMBEDDED_ENTITLEMENTS {
                    ent_blob = Some((blob_off, blob_length as usize));
                }
            }
            CSSLOT_SIGNATURESLOT => {
                if blob_magic == CSMAGIC_BLOBWRAPPER && blob_length > 8 {
                    has_cms = true;
                }
            }
            CSSLOT_LAUNCH_CONSTRAINT_SELF
            | CSSLOT_LAUNCH_CONSTRAINT_PARENT
            | CSSLOT_LAUNCH_CONSTRAINT_RESPONSIBLE
            | CSSLOT_LIBRARY_CONSTRAINT => {
                if blob_magic == CSMAGIC_LAUNCH_CONSTRAINT && blob_length > 8 {
                    let der_start = blob_off + 8; // skip blob header
                    let der_end = blob_off + (blob_length as usize).min(cs_data.len() - blob_off);
                    if der_start < der_end {
                        let der = cs_data[der_start..der_end].to_vec();
                        match slot_type {
                            CSSLOT_LAUNCH_CONSTRAINT_SELF => {
                                launch_constraints.self_der = Some(der);
                            }
                            CSSLOT_LAUNCH_CONSTRAINT_PARENT => {
                                launch_constraints.parent_der = Some(der);
                            }
                            CSSLOT_LAUNCH_CONSTRAINT_RESPONSIBLE => {
                                launch_constraints.responsible_der = Some(der);
                            }
                            CSSLOT_LIBRARY_CONSTRAINT => {
                                launch_constraints.library_der = Some(der);
                            }
                            _ => unreachable!(),
                        }
                    }
                }
            }
            _ => {
                if blob_magic == CSMAGIC_CODEDIRECTORY {
                    if cd_blob.is_none() {
                        cd_blob = Some((blob_off, blob_length as usize));
                    } else {
                        // Alternative code directory (slot >= 0x1000)
                        alt_cd_blobs.push((blob_off, blob_length as usize));
                    }
                }
            }
        }
    }

    let (cd_off, cd_len) = match cd_blob {
        Some(v) => v,
        None => bail!("no CodeDirectory found in code signature"),
    };

    // Parse CodeDirectory
    // struct CS_CodeDirectory layout (from cs_blobs.h):
    //   0: magic (u32)
    //   4: length (u32)
    //   8: version (u32)
    //  12: flags (u32)
    //  16: hashOffset (u32)
    //  20: identOffset (u32)
    //  24: nSpecialSlots (u32)
    //  28: nCodeSlots (u32)
    //  32: codeLimit (u32)
    //  36: hashSize (u8)
    //  37: hashType (u8)
    //  38: platform (u8)
    //  39: pageSize (u8)
    //  40: spare2 (u32)
    //  --- v >= 0x20100:
    //  44: scatterOffset (u32)
    //  --- v >= 0x20200:
    //  48: teamOffset (u32)
    //  --- v >= 0x20500:
    //  ...
    //  76: runtime (u32)

    let cd = &cs_data[cd_off..cd_off + cd_len.min(cs_data.len() - cd_off)];
    let version: u32 = cd.pread_with(8, BE)?;
    let flags: u32 = cd.pread_with(12, BE)?;
    let hash_type: u8 = cd.pread_with(37, BE)?;
    let platform: u8 = cd.pread_with(38, BE)?;

    // Extract identifier
    let _ident_offset: u32 = cd.pread_with(20, BE)?;

    // Extract team ID (if version >= 0x20200)
    let team_id = if version >= 0x20200 && cd.len() > 52 {
        let team_offset: u32 = cd.pread_with(48, BE)?;
        if team_offset > 0 && (team_offset as usize) < cd.len() {
            let start = team_offset as usize;
            let end = cd[start..].iter().position(|&b| b == 0).map(|p| start + p).unwrap_or(cd.len());
            Some(String::from_utf8_lossy(&cd[start..end]).to_string())
        } else {
            None
        }
    } else {
        None
    };

    // Extract runtime version (if version >= 0x20500)
    let runtime_version = if version >= CS_SUPPORTSRUNTIME && cd.len() > 80 {
        let rv: u32 = cd.pread_with(76, BE)?;
        if rv > 0 { Some(rv) } else { None }
    } else {
        None
    };

    // Determine signing type
    let signing_type = if flags & CS_LINKER_SIGNED != 0 {
        SigningType::LinkerSigned
    } else if !has_cms {
        SigningType::AdHoc
    } else if platform != 0 {
        SigningType::PlatformBinary
    } else {
        SigningType::DeveloperSigned
    };

    // Extract entitlements XML
    let entitlements_xml = if let Some((ent_off, ent_len)) = ent_blob {
        let ent_data = &cs_data[ent_off..ent_off + ent_len.min(cs_data.len() - ent_off)];
        // Skip the 8-byte blob header (magic + length)
        if ent_data.len() > 8 {
            let xml = String::from_utf8_lossy(&ent_data[8..]).to_string();
            Some(xml.trim().to_string())
        } else {
            None
        }
    } else {
        None
    };

    // Collect hash types from primary and all alternative CodeDirectories
    let mut hash_types = vec![hash_type];
    for &(alt_off, alt_len) in &alt_cd_blobs {
        let alt_cd = &cs_data[alt_off..alt_off + alt_len.min(cs_data.len() - alt_off)];
        if alt_cd.len() > 38 {
            if let Ok(alt_ht) = alt_cd.pread_with::<u8>(37, BE) {
                if alt_ht != 0 && !hash_types.contains(&alt_ht) {
                    hash_types.push(alt_ht);
                }
            }
        }
    }

    Ok(Some(CodeSignInfo {
        flags,
        platform,
        version,
        signing_type,
        team_id,
        entitlements_xml,
        runtime_version,
        launch_constraints,
        hash_types,
    }))
}
