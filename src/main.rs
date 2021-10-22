mod raw_socket_sys;
use raw_socket_sys::*;
mod link;
use link::*;

fn main() {
    let mut socket = RawSocketDesc::new("lo").unwrap();
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
                println!(
                    "From {} To {}, Type {:?}, Payload ({} bytes)", 
                    frame.src_addr(),
                    frame.dest_addr(),
                    frame.ethertype(),
                    frame.payload().len(),
                );
            }
            Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(err) => panic!("{}", err),
        }
    }
}
