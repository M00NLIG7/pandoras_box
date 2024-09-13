use std::net::IpAddr;

pub trait TryIntoIpAddr {
    fn try_into_ip_addr(&self) -> crate::Result<IpAddr>;
}

impl TryIntoIpAddr for IpAddr {
    fn try_into_ip_addr(&self) -> crate::Result<IpAddr> {
        Ok(*self)
    }
}

impl TryIntoIpAddr for &str {
    fn try_into_ip_addr(&self) -> crate::Result<IpAddr> {
        self.parse()
            .map_err(|_| crate::Error::ParseError("Error Parsing IP Address".to_string()))
    }
}

impl TryIntoIpAddr for String {
    fn try_into_ip_addr(&self) -> crate::Result<IpAddr> {
        self.as_str().try_into_ip_addr()
    }
}
