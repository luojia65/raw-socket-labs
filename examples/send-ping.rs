use raw_socket_labs::raw_socket_sys::*;
use raw_socket_labs::link::*;
use raw_socket_labs::net::*;

fn main() {
    let mut socket = RawSocketDesc::new("eth0").unwrap();
    socket.bind_interface().unwrap();
    let mtu = socket.interface_mtu().unwrap();
    println!("mtu value: {}", mtu);

    let virtual_dev_eui48 = "00:15:5d:b7:9f:a9".parse().unwrap();
    let virtual_dev_ip_addr = "fe80::215:5dff:feb7:9fa9".parse().unwrap();

    let mut buf = vec![0u8; mtu];
    let mut eth_frame = EthernetFrame::new(&mut buf);
    eth_frame.set_src_addr(virtual_dev_eui48);
    eth_frame.set_dst_addr("00-15-5D-EE-22-75".parse().unwrap());
    eth_frame.set_ethertype(EthernetProtocol::Ipv6);
    let mut ip = IpPacket::new(eth_frame.payload_mut());
    ip.set_version(6);
    ip.set_src_addr(virtual_dev_ip_addr);
    ip.set_dst_addr("fe80::d19d:d7:769c:3a86".parse().unwrap());
    ip.set_next_header(IpProtocol::Icmpv6);
    ip.set_hop_limit(128);
    
    let mut icmp = IcmpPacket::new(ip.payload_mut());
    icmp.set_packet_type(IcmpType::EchoRequest);
    icmp.set_code(0);
    let mut echo = EchoRequest::new(icmp.payload_mut());
    echo.set_identifier(0x343b);
    echo.set_sequence_number(1);
    echo.data_mut()[..56].copy_from_slice(&[
        0x34, 0x33, 0x79, 0x61, 0x00, 0x00, 0x00, 0x00, 
        0x48, 0x1e, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    ]);
    icmp.set_checksum(0xa688);
    ip.set_payload_len(64);
    loop {
        let _ = socket.send(&buf[..160]); // 这个160是分片系统计算的
        println!("{:x?}", &buf[..160]);
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

// let mut icmp = IcmpPacket::new(ip.payload_mut());
// icmp.set_packet_type(IcmpType::EchoRequest);
// icmp.set_code(0);
// let mut echo = EchoRequest::new(icmp.payload_mut());
// echo.set_identifier(0x343b);
// echo.set_sequence_number(1);
// echo.data_mut()[..64].copy_from_slice(&[
//     0x80, 0x00, 0x2d, 0x14, 0x34, 0x3b, 0x00, 0x01, 0x34, 0x33, 0x79, 0x61, 0x00, 0x00, 0x00, 0x00, 
//     0x48, 0x1e, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
//     0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 
//     0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
// ]);
