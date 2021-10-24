// Ip address; only IPv6 is supported

use byteorder::{ByteOrder, NetworkEndian};
use core::ops::Range;
use core::fmt;

// Ipv6 address
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Address {
    segments: [u16; 8],
}

impl Address {
    pub fn from_bytes(src: &[u8]) -> Self {
        assert!(src.len() == 16);
        let mut segments = [0u16; 8];
        for idx in 0..8 {
            let buf = &src[idx * 2..];
            let segment = NetworkEndian::read_u16(buf);
            segments[idx] = segment;
        }
        Address { segments }
    }
}

impl From<[u8; 16]> for Address {
    fn from(octets: [u8; 16]) -> Address {
        Address::from_bytes(&octets)
    }
}

impl From<[u16; 8]> for Address {
    fn from(segments: [u16; 8]) -> Address {
        Address { segments }
    }
}

impl fmt::Display for Address {
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

pub struct Packet<T> {
    inner: T,
}

impl<T: AsRef<[u8]>> Packet<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

// Ref: smoltcp
// https://tools.ietf.org/html/rfc2460#section-3.

impl<T: AsRef<[u8]>> Packet<T> {
    // 4-bit version number, 8-bit traffic class, and the
    // 20-bit flow label.
    const VER_TC_FLOW: Range<usize> = 0..4;
    // 16-bit value representing the length of the payload.
    // Note: Options are included in this length.
    const LENGTH:      Range<usize> = 4..6;
    // 8-bit value identifying the type of header following this
    // one. Note: The same numbers are used in IPv4.
    const NXT_HDR:     usize = 6;
    // 8-bit value decremented by each node that forwards this
    // packet. The packet is discarded when the value is 0.
    const HOP_LIMIT:   usize = 7;
    // IPv6 address of the source node.
    const SRC_ADDR:    Range<usize> = 8..24;
    // IPv6 address of the destination node.
    const DST_ADDR:    Range<usize> = 24..40;
    
    pub fn version(&self) -> u8 {
        self.inner.as_ref()[Self::VER_TC_FLOW.start] >> 4
    }
    pub fn traffic_class(&self) -> u8 {
        ((NetworkEndian::read_u16(&self.inner.as_ref()[0..2]) & 0x0ff0) >> 4) as u8
    }
    pub fn flow_label(&self) -> u32 {
        NetworkEndian::read_u24(&self.inner.as_ref()[1..4]) & 0x000fffff
    }
    pub fn length(&self) -> u16 {
        NetworkEndian::read_u16(&self.inner.as_ref()[Self::LENGTH])
    }
    pub fn next_header(&self) -> Protocol {
        self.inner.as_ref()[Self::NXT_HDR].into()
    }
    pub fn hop_limit(&self) -> u8 {
        self.inner.as_ref()[Self::HOP_LIMIT]
    }
    pub fn dst_addr(&self) -> Address {
        Address::from_bytes(&self.inner.as_ref()[Self::DST_ADDR])
    }
    pub fn src_addr(&self) -> Address {
        Address::from_bytes(&self.inner.as_ref()[Self::SRC_ADDR])
    }
    pub fn payload(&self) -> &[u8] {
        &self.inner.as_ref()[40..] // todo
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Protocol {
    Icmpv6, // 0x3A, ICMP v6
    Unknown(u8),
}

impl From<u8> for Protocol {
    fn from(src: u8) -> Self {
        match src {
            0x3A => Protocol::Icmpv6,
            others => Protocol::Unknown(others),
        }
    }
}

impl From<Protocol> for u8 {
    fn from(src: Protocol) -> u8 {
        match src {
            Protocol::Icmpv6 => 0x3A,
            Protocol::Unknown(others) => others
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Address;
    #[test]
    fn ip_address_print() {
        assert_eq!("::", Address::from([0, 0, 0, 0, 0, 0, 0, 0]).to_string());
        assert_eq!("::1", Address::from([0, 0, 0, 0, 0, 0, 0, 1]).to_string());
        assert_eq!("FE80::1234:5678", Address::from([0xfe80, 0, 0, 0, 0, 0, 0x1234, 0x5678]).to_string());
        assert_eq!("FF01::101", Address::from([0xff01, 0, 0, 0, 0, 0, 0, 0x101]).to_string());
        assert_eq!("2001:DB8::8:800:200C:417A", Address::from([0x2001, 0xdb8, 0, 0, 8, 0x800, 0x200c, 0x417a]).to_string());
        assert_eq!("2001:DB8:0:CD30::", Address::from([0x2001, 0xdb8, 0, 0xcd30, 0, 0, 0, 0]).to_string());
    }
}
