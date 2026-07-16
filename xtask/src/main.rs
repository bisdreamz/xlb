use anyhow::{bail, Context as _, Result};
use schemars::schema_for;
use std::fs;
use std::process::Command;

#[allow(dead_code)]
#[rustfmt::skip]
#[path = "../../xlb/src/config.rs"]
mod xlb_config;

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("gendocs") => generate_docs()?,
        Some(command) => bail!("unknown xtask command `{command}`\n\n{}", usage()),
        None => bail!(usage()),
    }

    Ok(())
}

fn generate_docs() -> Result<()> {
    println!("Generating config documentation...");

    // Generate JSON Schema
    let schema = schema_for!(xlb_config::XlbConfig);
    let schema_json = serde_json::to_string_pretty(&schema)?;

    // Write schema.json
    fs::write("docs/schema.json", schema_json)?;
    println!("✓ Generated docs/schema.json");

    // Create configuration directory if it doesn't exist
    fs::create_dir_all("docs/docs/configuration")?;

    let status = Command::new("generate-schema-doc")
        .arg("--config")
        .arg("template_name=md")
        .arg("docs/schema.json")
        .arg("docs/docs/configuration/reference.md")
        .status()
        .context(
            "failed to start generate-schema-doc; install it with `pipx install json-schema-for-humans`",
        )?;
    if !status.success() {
        bail!("generate-schema-doc failed with {status}");
    }
    remove_nondeterministic_generator_footer("docs/docs/configuration/reference.md")?;
    println!("✓ Generated docs/docs/configuration/reference.md");

    println!("Building mkdocs site...");
    let status = Command::new("mkdocs")
        .arg("build")
        .arg("--strict")
        .arg("-f")
        .arg("docs/mkdocs.yml")
        .status()
        .context(
            "failed to start mkdocs; run `pipx install mkdocs` and `pipx inject mkdocs mkdocs-material`",
        )?;
    if !status.success() {
        bail!("mkdocs --strict failed with {status}");
    }
    println!("✓ Built mkdocs site");

    Ok(())
}

fn usage() -> &'static str {
    "Usage: cargo run --package xtask -- <command>\n\nCommands:\n  gendocs    Regenerate the config reference and strictly build the documentation site"
}

fn remove_nondeterministic_generator_footer(path: &str) -> Result<()> {
    const FOOTER: &str = "\n----------------------------------------------------------------------------------------------------------------------------\nGenerated using ";

    let mut contents = fs::read_to_string(path)?;
    if let Some(footer_start) = contents.rfind(FOOTER) {
        contents.truncate(footer_start);
        contents.push('\n');
        fs::write(path, contents)?;
    }

    Ok(())
}
