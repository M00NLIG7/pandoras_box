#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    pub ip: String,
    pub os: OS,
    pub open_ports: Vec<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OS {
    Unix,
    Windows,
    Unknown,
}

impl std::fmt::Display for OS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OS::Unix => write!(f, "Unix"),
            OS::Windows => write!(f, "Windows"),
            OS::Unknown => write!(f, "Unknown"),
        }
    }
}

