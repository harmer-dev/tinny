use clap::{Parser, Subcommand};
use std::collections::BTreeMap;
use std::fs;

mod version;

#[derive(Parser)]
#[command(
    name = "xtask",
    about = "Repository-internal development and release tooling"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validates the Cargo.toml version against conventional commits since the last tag
    Validate,
    /// Generates conventional markdown release notes
    Changelog,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Validate => validate_version_bump()?,
        Commands::Changelog => generate_changelog()?,
    }
    Ok(())
}

/// Reads the current version string from `Cargo.toml`
fn get_cargo_version() -> Result<String, Box<dyn std::error::Error>> {
    let cargo_toml_content = fs::read_to_string("Cargo.toml")?;
    for line in cargo_toml_content.lines() {
        if line.starts_with("version =") {
            let version = line
                .split('=')
                .nth(1)
                .unwrap_or("")
                .trim()
                .trim_matches('"')
                .to_string();
            return Ok(version);
        }
    }
    Err("Could not find version in Cargo.toml".into())
}

/// Subcommand handler to validate that the version in `Cargo.toml` is bumped sufficiently
fn validate_version_bump() -> Result<(), Box<dyn std::error::Error>> {
    let cargo_version = get_cargo_version()?;
    let info = version::get_git_version_info()?;

    if info.bump == "none" {
        println!(
            "No commits since the last tag ({}). Version validation passed.",
            info.last_tag
        );
        return Ok(());
    }

    // Compare Cargo.toml version with expected_version using basic SemVer comparison
    let cargo_parts: Vec<u32> = cargo_version
        .split('-') // Ignore pre-release suffixes for comparison
        .next()
        .unwrap_or("")
        .split('.')
        .map(|s| s.parse().unwrap_or(0))
        .collect();

    let expected_parts: Vec<u32> = info
        .next_version
        .split('.')
        .map(|s| s.parse().unwrap_or(0))
        .collect();

    let is_valid = if cargo_parts.len() < 3 || expected_parts.len() < 3 {
        false
    } else if cargo_parts[0] > expected_parts[0] {
        true
    } else if cargo_parts[0] == expected_parts[0] {
        if cargo_parts[1] > expected_parts[1] {
            true
        } else if cargo_parts[1] == expected_parts[1] {
            cargo_parts[2] >= expected_parts[2]
        } else {
            false
        }
    } else {
        false
    };

    if !is_valid {
        eprintln!("============================================================");
        eprintln!("❌ VERSION VALIDATION FAILED!");
        eprintln!("============================================================");
        eprintln!(
            "Your Cargo.toml version ({}) is LESS than the required version ({})",
            cargo_version, info.next_version
        );
        eprintln!(
            "based on the conventional commits since last tag ({}):",
            info.last_tag
        );
        eprintln!("Required bump level: {}", info.bump.to_uppercase());
        eprintln!("Please bump the version in Cargo.toml appropriately.");
        eprintln!("============================================================");
        std::process::exit(1);
    }

    println!("============================================================");
    println!("✅ VERSION VALIDATION PASSED!");
    println!(
        "Cargo.toml version ({}) meets or exceeds expected ({})",
        cargo_version, info.next_version
    );
    println!("============================================================");
    Ok(())
}

/// Subcommand handler to generate markdown conventional release notes to stdout
fn generate_changelog() -> Result<(), Box<dyn std::error::Error>> {
    let info = version::get_git_version_info()?;

    let mut categories: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut breaking_changes = Vec::new();

    for commit in info.commits {
        if commit.is_breaking {
            breaking_changes.push(
                commit
                    .message
                    .lines()
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string(),
            );
        }

        let category = match commit.type_part.as_str() {
            "feat" => "🚀 Features",
            "fix" => "🐛 Bug Fixes",
            "refactor" => "⚙️ Refactoring",
            "perf" => "⚡ Performance",
            "docs" => "📚 Documentation",
            "test" => "🧪 Tests",
            "chore" => "🔧 Chore",
            _ => "Other Changes",
        };

        categories
            .entry(category.to_string())
            .or_default()
            .push(format!("- {} ({})", commit.desc_part, commit.oid_short));
    }

    // Print release notes
    println!("# Release Notes\n");

    if !breaking_changes.is_empty() {
        println!("### 🚨 BREAKING CHANGES");
        for bc in breaking_changes {
            println!("- {}", bc);
        }
        println!();
    }

    for (category, commits) in categories {
        println!("### {}", category);
        for commit in commits {
            println!("{}", commit);
        }
        println!();
    }

    Ok(())
}
