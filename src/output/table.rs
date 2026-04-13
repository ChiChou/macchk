use colored::*;

use crate::types::*;

pub fn print(result: &AnalysisResult) {
    println!();
    println!("{}", format!("  {}", result.path).bold());

    if result.slices.is_empty() {
        println!("  {}", "No matching architecture found.".yellow());
        return;
    }

    for slice in &result.slices {
        println!(
            "{}",
            format!("  {} ({})", slice.arch, slice.file_type).cyan().bold()
        );


        let mut current_cat: Option<Category> = None;

        for check in &slice.checks {
            // Print category header on change
            if current_cat.as_ref() != Some(&check.category) {
                current_cat = Some(check.category);
                println!();
                println!("  {}", check.category.label().bold().underline());
            }

            // Entitlements section: skip the check name/status line,
            // print each entitlement directly with color
            if check.category == Category::Entitlements {
                print_entitlements(check);
                continue;
            }

            let status = format_status(check);
            let name_width = 25;
            println!("    {:<width$} {}", check.name, status, width = name_width);

            // Show evidence
            let max_evidence = match check.id {
                CheckId::SegmentPermissions => 20,
                CheckId::LaunchConstraints => 16,
                _ => 3,
            };
            for (i, ev) in check.evidence.iter().enumerate() {
                if i >= max_evidence {
                    let remaining = check.evidence.len() - max_evidence;
                    println!(
                        "    {:<width$}   {} more...",
                        "",
                        remaining,
                        width = name_width
                    );
                    break;
                }
                let indent = format!("    {:<width$}   ", "", width = name_width);
                if check.id == CheckId::DyldEnvironment {
                    print_truncated(&ev.description.dimmed().to_string(), &indent, 120);
                } else {
                    println!("{}{}", indent, ev.description.dimmed());
                }
            }

            // Show stats if present
            if let Some(ref stats) = check.stats {
                println!(
                    "    {:<width$}   coverage: {}/{} functions ({:.1}%), {} sites",
                    "",
                    stats.functions_with_feature,
                    stats.functions_scanned,
                    if stats.functions_scanned > 0 {
                        stats.functions_with_feature as f64 / stats.functions_scanned as f64 * 100.0
                    } else {
                        0.0
                    },
                    stats.sites_found,
                    width = name_width
                );
            }
        }
        println!();
    }
}

fn print_entitlements(check: &CheckResult) {
    if check.evidence.is_empty() {
        println!("    {}", "no entitlements".dimmed());
        return;
    }

    for ev in &check.evidence {
        if ev.strategy == "entitlement_summary" {
            println!("    {}", ev.description.dimmed());
            continue;
        }

        let desc = &ev.description;
        if desc.contains("[WEAKENS]") {
            // Red for security-weakening entitlements
            let clean = desc.replace(" [WEAKENS]", "");
            println!("    {} {}", "[-]".red().bold(), clean.red());
        } else if desc.contains("[STRENGTHENS]") {
            // Green for security-strengthening entitlements
            let clean = desc.replace(" [STRENGTHENS]", "");
            println!("    {} {}", "[+]".green().bold(), clean.green());
        } else {
            // Dimmed for informational entitlements
            println!("    {}  {}", " ".dimmed(), desc.dimmed());
        }
    }
}

/// Print text with indent, truncating with ellipsis if too long.
fn print_truncated(text: &str, indent: &str, max_width: usize) {
    let content_width = max_width.saturating_sub(indent.len());
    let plain: String = {
        let mut s = String::with_capacity(text.len());
        let mut in_esc = false;
        for c in text.chars() {
            if in_esc {
                if c.is_ascii_alphabetic() { in_esc = false; }
            } else if c == '\x1b' {
                in_esc = true;
            } else {
                s.push(c);
            }
        }
        s
    };

    if plain.len() <= content_width || content_width < 4 {
        println!("{}{}", indent, text);
    } else {
        // Truncate plain text and re-print dimmed
        let truncated = &plain[..content_width - 3];
        println!("{}{}...", indent, truncated.dimmed());
    }
}

fn format_status(check: &CheckResult) -> ColoredString {
    match (check.detected, check.polarity) {
        (true, Polarity::Positive) => "DETECTED".green().bold(),
        (true, Polarity::Negative) => "DETECTED".red().bold(),
        (true, Polarity::Info) => "PRESENT".cyan(),
        (false, Polarity::Positive) => "not detected".red(),
        (false, Polarity::Negative) => "not detected".green(),
        (false, Polarity::Info) => "not present".dimmed(),
    }
}
