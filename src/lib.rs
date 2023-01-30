use std::net::{IpAddr, TcpStream};

pub fn scan(host: &IpAddr, port: &u16) -> u16 {
    match TcpStream::connect((*host, *port)) {
        Ok(_) => *port,
        Err(_) => 0,
    }
}
