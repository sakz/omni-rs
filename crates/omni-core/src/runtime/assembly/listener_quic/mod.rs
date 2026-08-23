pub mod hysteria2;
pub mod naive;

#[derive(Debug)]
pub struct NotReady(pub &'static str);

impl std::fmt::Display for NotReady {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} not yet implemented", self.0)
    }
}

impl std::error::Error for NotReady {}
