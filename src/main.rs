use std::cmp::Ordering;

use netstat2::*;
use sysinfo;
use sysinfo::{ProcessExt, System, SystemExt};

struct ProcessInfo {
    pid: u32,
    name: String,
}

struct SocketInfo {
    processes: Vec<ProcessInfo>,
    local_port: u16,
    local_addr: std::net::IpAddr,
    remote_port: Option<u16>,
    remote_addr: Option<std::net::IpAddr>,
    protocol: ProtocolFlags,
    state: Option<TcpState>,
    family: AddressFamilyFlags,
}

// TODO: color output (ports/addr/state)
// TODO: accept arguments - hide UDP by default

fn main() {
    let sys = System::new_all();

    let mut sockets = get_sockets(&sys, AddressFamilyFlags::IPV4);
    let mut sockets6 = get_sockets(&sys, AddressFamilyFlags::IPV6);
    sockets.append(&mut sockets6);

    // sort by port
    sockets.sort_by(|a, b| {
        if a.local_port < b.local_port {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    });

    println!("------------------------------");
    println!("TCP socket information");
    println!("------------------------------");
    print_tcp(&sockets);

    println!();
    println!("------------------------------");
    println!("UDP socket information");
    println!("------------------------------");
    print_udp(&sockets);
}

fn print_tcp(sockets: &Vec<SocketInfo>) {
    for s in sockets {
        if s.protocol != ProtocolFlags::TCP {
            continue;
        }

        let ip_ver = if s.family == AddressFamilyFlags::IPV4 {
            "4"
        } else {
            "6"
        };

        if s.state == Some(TcpState::Listen) {
            println!(
                "TCP{:3}{:>30}:{:>5}    {:>6} {:<30}{:30}[{}]",
                ip_ver,
                format!("{}", s.local_addr),
                s.local_port,
                "",
                "",
                std::format!("{} ({})", s.processes[0].name, s.processes[0].pid),
                s.state.unwrap()
            );
        } else {
            println!(
                "TCP{:3}{:>30}:{:>5} -> {:>6}:{:<30}{:30}[{}]",
                ip_ver,
                format!("{}", s.local_addr),
                s.local_port,
                s.remote_port.unwrap(),
                format!("{}", s.remote_addr.unwrap()),
                std::format!("{} ({})", s.processes[0].name, s.processes[0].pid),
                s.state.unwrap()
            );
        }
    }
}

fn print_udp(sockets: &Vec<SocketInfo>) {
    for s in sockets {
        if s.protocol != ProtocolFlags::UDP {
            continue;
        }

        let ip_ver = if s.family == AddressFamilyFlags::IPV4 {
            "4"
        } else {
            "6"
        };

        println!(
            "UDP{:3}{:>30}:{:<8}{:30}",
            ip_ver,
            s.local_addr,
            s.local_port,
            std::format!("{} ({})", s.processes[0].name, s.processes[0].pid),
        );
    }
}

fn get_sockets(sys: &System, addr: AddressFamilyFlags) -> Vec<SocketInfo> {
    let protos = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let iterator = iterate_sockets_info(addr, protos).expect("Failed to get socket information!");

    let mut sockets: Vec<SocketInfo> = Vec::new();

    for info in iterator {
        let si = match info {
            Ok(si) => si,
            Err(_err) => {
                println!("Failed to get info for socket!");
                continue;
            }
        };

        // gather associated processes
        let process_ids = si.associated_pids;
        let mut processes: Vec<ProcessInfo> = Vec::new();
        for pid in process_ids {
            let name = match sys.get_process(pid as usize) {
                Some(pinfo) => pinfo.name(),
                None => "",
            };
            processes.push(ProcessInfo {
                pid: pid,
                name: name.to_string(),
            });
        }

        match si.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp) => sockets.push(SocketInfo {
                processes: processes,
                local_port: tcp.local_port,
                local_addr: tcp.local_addr,
                remote_port: Some(tcp.remote_port),
                remote_addr: Some(tcp.remote_addr),
                protocol: ProtocolFlags::TCP,
                state: Some(tcp.state),
                family: addr,
            }),
            ProtocolSocketInfo::Udp(udp) => sockets.push(SocketInfo {
                processes: processes,
                local_port: udp.local_port,
                local_addr: udp.local_addr,
                remote_port: None,
                remote_addr: None,
                state: None,
                protocol: ProtocolFlags::UDP,
                family: addr,
            }),
        }
    }

    sockets
}
