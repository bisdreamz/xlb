use anyhow::Result;
use schemars::schema_for;
use std::fs;
use std::process::Command;

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("gendocs") => generate_docs()?,
        _ => {
            println!("Usage: cargo xtask <command>");
            println!("\nCommands:");
            println!("  gendocs    Generate documentation from config structs");
        }
    }

    Ok(())
}

fn generate_docs() -> Result<()> {
    println!("Generating config documentation...");

    // Generate JSON Schema
    let schema = schema_for!(xlb::config::XlbConfig);
    let schema_json = serde_json::to_string_pretty(&schema)?;

    // Write schema.json
    fs::write("docs/schema.json", schema_json)?;
    println!("✓ Generated docs/schema.json");

    // Create configuration directory if it doesn't exist
    fs::create_dir_all("docs/docs/configuration")?;

    // Try to run generate-schema-doc if available
    let output = Command::new("generate-schema-doc")
        .arg("--config")
        .arg("template_name=md")
        .arg("docs/schema.json")
        .arg("docs/docs/configuration/reference.md")
        .output();

    match output {
        Ok(result) if result.status.success() => {
            println!("✓ Generated docs/docs/configuration/reference.md");
        }
        Ok(result) => {
            eprintln!("Warning: generate-schema-doc failed: {}",
                String::from_utf8_lossy(&result.stderr));
            print_install_instructions();
        }
        Err(_) => {
            print_install_instructions();
        }
    }

    Ok(())
}

fn print_install_instructions() {
    println!("\nTo generate markdown docs, install json-schema-for-humans:");
    println!("  pipx install json-schema-for-humans");
    println!("Then run: ./target/debug/xtask gendocs");
}
