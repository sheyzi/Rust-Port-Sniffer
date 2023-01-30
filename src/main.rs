use port_sniffer::scan;
use std::net::{IpAddr, Ipv4Addr};

use clap::Parser;

#[derive(Parser)]
#[command(
    name = "Port Sniffer",
    version = "0.1.0",
    author = "Oluwaseyifunmi Oyefeso"
)]
/// A simple port sniffer written in Rust.
/// This program is used to scan ports on a host to determine if they are open or closed.
/// It is a simple implementation of the TCP connect scan.
/// It is not meant to be used in production environments.
/// It is meant to be used for educational purposes only.
/// It is not meant to be used to scan ports on a host without the host's permission.
/// The author of this program is not responsible for any damages caused by the use of this program.
/// Use at your own risk.
struct Cli {
    /// The host to scan. This must be an Ip Address.
    /// If no host is provided, the program will default to 127.0.0.1
    /// If a host is provided, it must be a valid IpV4 or IpV6 address.
    // #[clap(long, default_value = "localhost")]
    host: Option<IpAddr>,

    /// The port to scan. This can be a single port or a range of ports.
    /// If no port is provided, the program will scan the common vulnerable ports.
    /// If a port is provided, it must be a valid port number.
    #[clap(short, long)]
    port: Option<Vec<u16>>,
    /*
    /// The number of threads to use when scanning ports.
    /// If no number of threads is provided, the program will default to 1.
    #[clap(short, long)]
    threads: Option<u32>,
    */
}

const COMMON_PORTS: [u16; 64] = [
    21, 20, 22, 23, 137, 139, 445, 80, 443, 8080, 8443, 25, 69, 53, 161, 162, 110, 143, 389, 3389,
    3306, 1433, 1521, 5432, 5900, 5901, 5902, 5903, 5904, 5905, 5906, 5907, 5908, 5909, 4899, 4898,
    4897, 4896, 4895, 4894, 4893, 4892, 4891, 4890, 5938, 5937, 5936, 5935, 5934, 5933, 5932, 5931,
    5930, 5929, 177, 176, 175, 174, 173, 172, 171, 170, 169, 168,
];

fn main() {
    let cli = Cli::parse();

    let host = match cli.host {
        Some(host) => host,
        None => IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    };

    let ports = match cli.port {
        Some(port) => port,
        None => Vec::from_iter(COMMON_PORTS.iter().cloned()),
    };

    let mut opened_ports: Vec<u16> = vec![];

    for port in ports.iter() {
        let port = scan(&host, port);
        if port != 0 {
            opened_ports.push(port);
        }
    }

    println!("Opened ports: {:?}", opened_ports);
}
