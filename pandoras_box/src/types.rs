#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OS {
    Unix,
    Windows,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    pub ip: String,
    pub os: OS,
    pub open_ports: Vec<u16>,
}
