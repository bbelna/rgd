pub mod parser;
pub mod trigger;

pub use parser::{parse, Pressure};
pub use trigger::{Resource, Trigger};

use anyhow::{Context, Result};

pub fn read_current(resource: Resource) -> Result<Pressure> {
    let contents = std::fs::read_to_string(resource.path())
        .with_context(|| format!("reading {}", resource.path()))?;
    parse(&contents)
}
