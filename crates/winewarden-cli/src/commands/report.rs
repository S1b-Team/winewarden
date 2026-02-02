use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use reporting::SessionReport;

pub fn execute(input: &Path, json: bool) -> Result<()> {
    let contents =
        fs::read_to_string(input).with_context(|| format!("read report {}", input.display()))?;
    let report: SessionReport = serde_json::from_str(&contents).context("parse report JSON")?;

    if json {
        println!("{}", contents);
    } else {
        println!("{}", report.human_summary());
    }
    Ok(())
}
