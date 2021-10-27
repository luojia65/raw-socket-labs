pub mod raw_socket_sys;
pub mod link;
pub mod net;

use raw_socket_sys::*;
use link::*;
use net::*;

fn main() {
    let mut socket = RawSocketDesc::new("eth0").unwrap();
    socket.bind_interface().unwrap();
    let mtu = socket.interface_mtu().unwrap();
    println!("mtu value: {}", mtu);

    let virtual_dev_eui48 = "01:02:03:04:05:06".parse().unwrap();
    let virtual_dev_ip_addr = IpAddress::from([0xfe80, 0, 0, 0, 0, 0, 0x1234, 0x5678]);

    let mut buf = vec![0u8; mtu];
    let mut eth_frame = EthernetFrame::new(&mut buf);
    eth_frame.set_src_addr(virtual_dev_eui48);
    eth_frame.set_dst_addr("00-15-5D-5E-97-B1".parse().unwrap());
    eth_frame.set_ethertype(EthernetProtocol::Ipv6);
    let mut ip = IpPacket::new(eth_frame.payload_mut());
    ip.set_src_addr(virtual_dev_ip_addr);
    ip.set_dst_addr(IpAddress::from([0xfe80, 0, 0, 0, 0xc86f, 0x2dff, 0x7dfa, 0xfd40]));
    ip.set_version(6);
    let mut icmp = IcmpPacket::new(ip.payload_mut());
    icmp.set_packet_type(IcmpType::EchoRequest);
    icmp.set_code(0);
    icmp.payload_mut()[..4].copy_from_slice(&[1, 2, 3, 4]);
    ip.set_payload_len(8);

    socket.send(&buf).unwrap();
}
