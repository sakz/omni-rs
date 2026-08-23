pub mod subscriber;

use std::sync::OnceLock;

static INIT: OnceLock<()> = OnceLock::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Omni,
    Json,
}

impl Format {
    pub fn parse(s: &str) -> Option<Format> {
        match s {
            "json" | "JSON" => Some(Format::Json),
            _ => Some(Format::Omni),
        }
    }
}

pub fn init(format: Format) -> bool {
    if INIT.get().is_some() {
        false
    } else {
        let _ = INIT.set(());
        subscriber::init(format);
        true
    }
}
