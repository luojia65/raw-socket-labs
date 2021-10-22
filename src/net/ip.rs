// Ip address; only IPv6 is supported

use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;

// Ipv6 address
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IpAddress {
    segments: [u16; 8]
}

impl From<[u8; 16]> for IpAddress {
    fn from(octets: [u8; 16]) -> IpAddress {
        let mut segments = [0u16; 8];
        for idx in 0..8 {
            let buf = &octets[idx * 2..];
            let segment = NetworkEndian::read_u16(buf);
            segments[idx] = segment;
        }
        IpAddress { segments }
    }
}

impl From<[u16; 8]> for IpAddress {
    fn from(segments: [u16; 8]) -> IpAddress {
        IpAddress { segments }
    }
}

impl fmt::Display for IpAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (longest_idx, longest_len) = {
            let (mut longest_idx, mut longest_len) = (0, 0);
            let mut cur_len = 0;
            for idx in 0..8 {
                if self.segments[idx] == 0 {
                    cur_len += 1;
                    if cur_len > longest_len {
                        longest_len = cur_len;
                        longest_idx = idx + 1 - cur_len;
                    }
                } else {
                    cur_len = 0;
                }
            }
            (longest_idx, longest_len)
        };
        let mut idx = 0;
        while idx < 8 {
            if idx == longest_idx && longest_len != 0 {
                write!(f, "::")?;
                idx += longest_len;
            } else {
                write!(f, "{:X}", self.segments[idx])?;
                idx += 1;
                if idx != 8 && idx != longest_idx {
                    write!(f, ":")?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::IpAddress;
    #[test]
    fn ip_address_print() {
        assert_eq!("::", IpAddress::from([0, 0, 0, 0, 0, 0, 0, 0]).to_string());
        assert_eq!("::1", IpAddress::from([0, 0, 0, 0, 0, 0, 0, 1]).to_string());
        assert_eq!("FE80::1234:5678", IpAddress::from([0xfe80, 0, 0, 0, 0, 0, 0x1234, 0x5678]).to_string());
        assert_eq!("FF01::101", IpAddress::from([0xff01, 0, 0, 0, 0, 0, 0, 0x101]).to_string());
        assert_eq!("2001:DB8::8:800:200C:417A", IpAddress::from([0x2001, 0xdb8, 0, 0, 8, 0x800, 0x200c, 0x417a]).to_string());
        assert_eq!("2001:DB8:0:CD30::", IpAddress::from([0x2001, 0xdb8, 0, 0xcd30, 0, 0, 0, 0]).to_string());
    }
}
