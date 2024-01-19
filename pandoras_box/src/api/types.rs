#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct RootNode {
    pub(crate) ip: std::net::IpAddr,
    pub(crate) api_key: String,
}

impl Default for RootNode {
    fn default() -> Self {
        Self {
            ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            api_key: String::from(""),
        }
    }
}

// Define a struct for the request JSON body
#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct ServerNode {
    pub(crate) ip: std::net::IpAddr,
    pub(crate) evil_secret: u32,
    pub(crate) supports_docker: bool,
}

impl Default for ServerNode {
    fn default() -> Self {
        Self {
            ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            evil_secret: 0,
            supports_docker: false,
        }
    }
}

impl PartialEq for ServerNode {
    fn eq(&self, other: &Self) -> bool {
        self.evil_secret == other.evil_secret
    }
}
impl Eq for ServerNode {}
impl Ord for ServerNode {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // For max heap based on evil_secret
        self.evil_secret.cmp(&other.evil_secret)

        // If you want a min heap (smallest evil_secret at the top), reverse the comparison:
        // other.evil_secret.cmp(&self.evil_secret)
    }
}

impl PartialOrd for ServerNode {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
