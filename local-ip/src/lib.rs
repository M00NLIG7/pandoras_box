use pnet::datalink;
use procfs::net::{route, RouteEntry};

pub fn get_local_ip() -> Box<str> {
    let routes = match route() {
        Ok(r) => r,
        Err(_) => return "0.0.0.0".into(),
    };
    let intface: &RouteEntry = if routes.len() == 1 {
        match routes.first() {
            Some(route) => route,
            None => return "0.0.0.0".into(),
        }
    } else {
        match routes
            .iter()
            .filter(|r| r.destination.is_unspecified())
            .last()
        {
            Some(route) => route,
            None => return "0.0.0.0".into(),
        }
    };

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == intface.iface);

    match interface {
        Some(iface) => match iface.ips.first() {
            Some(ip) => ip.ip().to_string().into_boxed_str(),
            None => "0.0.0.0".into(),
        },
        None => "0.0.0.0".into(),
    }
}
