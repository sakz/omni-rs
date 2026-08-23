pub mod model;
pub mod wire;

use std::path::Path;

#[derive(Debug)]
pub enum ConfigError {
    Read {
        path: String,
        source: std::io::Error,
    },
    Parse {
        path: String,
        msg: String,
    },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Read { path, source } => {
                write!(f, "failed to read config from {}: {}", path, source)
            }
            ConfigError::Parse { path, msg } => {
                write!(f, "failed to parse config {}: {}", path, msg)
            }
        }
    }
}

impl std::error::Error for ConfigError {}

pub fn load_str(path: &str, content: &str) -> Result<wire::RuntimeConfigWire, ConfigError> {
    let ext = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    let parsed: Result<wire::RuntimeConfigWire, String> = match ext {
        "toml" => toml::from_str(content).map_err(|e| e.to_string()),
        _ => serde_json::from_str(content).map_err(|e| e.to_string()),
    };
    parsed.map_err(|e| ConfigError::Parse {
        path: path.to_string(),
        msg: e.to_string(),
    })
}

pub fn read_config(path: &str) -> Result<wire::RuntimeConfigWire, ConfigError> {
    let content = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_string(),
        source,
    })?;
    load_str(path, &content)
}
