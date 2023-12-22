// Define a struct for the request JSON body
#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct ServerNode {
    pub(crate) ip: std::net::IpAddr,
    pub(crate) evil_secret: u32,
}

impl Default for ServerNode {
    fn default() -> Self {
        Self {
            ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            evil_secret: 0,
        }
    }
}
