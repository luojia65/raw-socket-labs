mod raw_socket_sys;
use raw_socket_sys::*;
mod link;
use link::*;
mod net;
use net::*;

fn main() {
    let mut socket = RawSocketDesc::new("eth0").unwrap();
    println!("{:?}", socket);

    socket.bind_interface().unwrap();
    println!("bind interface success");
    let mtu = socket.interface_mtu().unwrap();
    println!("mtu value: {}", mtu);
    let mut buf = vec![0u8; mtu];
    loop {
        match socket.recv(&mut buf) {
            Ok(len) => {
                // println!("received: {:x?}", &buf[..len]);
                let received = &buf[..len];
                let frame = EthernetFrame::new(received);
                if frame.ethertype() != EthernetProtocol::Ipv6 {
                    continue;
                }
                println!(
                    "From {} To {}, Type {:?}, Payload ({} bytes)", 
                    frame.src_addr(),
                    frame.dst_addr(),
                    frame.ethertype(),
                    frame.payload().len(),
                );
                let packet = IpPacket::new(frame.payload());
                println!(
                    "Ipv6 {} to {}, Ver {}, TrfCls {}, FlwLbl {}, Len {}, NxtHdr {}, HopLim {}",
                    packet.src_addr(), packet.dst_addr(),
                    packet.version(), packet.traffic_class(), packet.flow_label(),
                    packet.length(), packet.next_header(), packet.hop_limit(),
                );
                println!("Payload = {:?}", packet.payload());
            }
            Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(err) => panic!("{}", err),
        }
    }
}
