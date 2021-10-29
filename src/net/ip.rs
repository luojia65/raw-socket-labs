// Ip address; only IPv6 is supported

use byteorder::{ByteOrder, NetworkEndian};
use core::ops::Range;
use core::fmt;
use core::str::FromStr;

// Ipv6 address
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    repr: u128,
}

impl Address {
    pub const UNSPECIFIED: Self = Address::from_segments([0, 0, 0, 0, 0, 0, 0, 0]);
    pub const LOOPBACK: Self = Address::from_segments([0, 0, 0, 0, 0, 0, 0, 1]);
    pub const fn from_segments(segments: [u16; 8]) -> Address {
        // 辣鸡Rust
        let repr = ((segments[0] as u128) << 112) | ((segments[1] as u128) << 96) |
            ((segments[2] as u128) << 80) | ((segments[3] as u128) << 64) |
            ((segments[4] as u128) << 48) | ((segments[5] as u128) << 32) |
            ((segments[6] as u128) << 16) | (segments[7] as u128);
        Self { repr }
    }
    pub fn from_bytes(src: &[u8]) -> Address {
        let repr = NetworkEndian::read_u128(&src);
        Address { repr }
    }
    pub const fn segments(self) -> [u16; 8] {
        let repr = self.repr;
        [
            ((repr >> 112) & 0xFFFF) as u16, ((repr >> 96) & 0xFFFF) as u16,
            ((repr >> 80) & 0xFFFF) as u16, ((repr >> 64) & 0xFFFF) as u16,
            ((repr >> 48) & 0xFFFF) as u16, ((repr >> 32) & 0xFFFF) as u16,
            ((repr >> 16) & 0xFFFF) as u16, (repr & 0xFFFF) as u16,
        ]
    }
    pub const fn octets(self) -> [u8; 16] {
        self.repr.to_be_bytes()
    }
}

impl From<[u8; 16]> for Address {
    #[inline] fn from(octets: [u8; 16]) -> Address {
        Address::from_bytes(&octets)
    }
}

impl From<[u16; 8]> for Address {
    #[inline] fn from(segments: [u16; 8]) -> Address {
        Address::from_segments(segments)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let segments = self.segments();
        let (longest_idx, longest_len) = {
            let (mut longest_idx, mut longest_len) = (0, 0);
            let mut cur_len = 0;
            for idx in 0..8 {
                if segments[idx] == 0 {
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
                write!(f, "{:X}", segments[idx])?;
                idx += 1;
                if idx != 8 && idx != longest_idx {
                    write!(f, ":")?;
                }
            }
        }
        Ok(())
    }
}

impl FromStr for Address {
    type Err = ParseAddressError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut segments = [0u16; 8];
        let mut it = s.bytes().peekable();
        let mut cur_num = 0;
        let mut cur_num_len = 0;
        let mut is_start = true;
        let mut segment_idx = 0;
        loop {
            match it.next() {
                Some(byte @ (b'0'..=b'9' | b'a' ..= b'f' | b'A' ..= b'F')) => {
                    if cur_num_len >= 4 {
                        return Err(ParseAddressError(()))
                    }
                    let digit = match byte {
                        b'0' ..= b'9' => byte - b'0',
                        b'a' ..= b'f' => byte - b'a' + 10,
                        b'A' ..= b'F' => byte - b'A' + 10,
                        _ => unreachable!(),
                    } as u16;
                    cur_num_len += 1;
                    cur_num <<= 4;
                    cur_num |= digit;
                    is_start = false;
                }
                Some(b':') => {
                    let nxt = it.peek();
                    if (nxt != Some(&b':') && is_start) || nxt == None || segment_idx > 8 {
                        return Err(ParseAddressError(()))
                    }
                    if !is_start {
                        segments[segment_idx] = cur_num;
                        segment_idx += 1;
                    }
                    cur_num_len = 0;
                    cur_num = 0;
                    if nxt == Some(&b':') {
                        it.next(); // consume next character
                        break // first part finished
                    } 
                    is_start = false;
                },
                None if segment_idx == 7 => {
                    segments[segment_idx] = cur_num;
                    return Ok(Address::from_segments(segments))
                },
                _ => return Err(ParseAddressError(()))
            }
        }
        let omitted_idx_start = segment_idx;
        is_start = true;
        cur_num_len = 0;
        cur_num = 0;
        loop {
            match it.next() {
                Some(byte @ (b'0'..=b'9' | b'a' ..= b'f' | b'A' ..= b'F')) => {
                    if cur_num_len >= 4 {
                        return Err(ParseAddressError(()))
                    }
                    let digit = match byte {
                        b'0' ..= b'9' => byte - b'0',
                        b'a' ..= b'f' => byte - b'a' + 10,
                        b'A' ..= b'F' => byte - b'A' + 10,
                        _ => unreachable!(),
                    } as u16;
                    cur_num_len += 1;
                    cur_num <<= 4;
                    cur_num |= digit;
                    is_start = false;
                }
                Some(b':') => {
                    let nxt = it.peek();
                    // cannot omit twice
                    if nxt == Some(&b':') || nxt == None || is_start || segment_idx > 8 {
                        return Err(ParseAddressError(()))
                    }
                    segments[segment_idx] = cur_num;
                    segment_idx += 1;
                    cur_num_len = 0;
                    cur_num = 0;
                    is_start = false;
                },
                None => {
                    if !is_start {
                        segments[segment_idx] = cur_num;
                        segment_idx += 1;
                    }
                    break
                },
                _ => return Err(ParseAddressError(()))
            }
        }
        let n_omitted_segments = 8 - segment_idx;
        for idx in (omitted_idx_start + n_omitted_segments .. 8).rev() {
            segments[idx] = segments[idx - n_omitted_segments]
        }
        for idx in omitted_idx_start..omitted_idx_start + n_omitted_segments {
            segments[idx] = 0;
        }
        Ok(Address::from_segments(segments))
    }
}

/// IPv6 address parse error
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ParseAddressError(());

pub struct Packet<T> {
    inner: T,
}

impl<T> Packet<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
    pub fn into_inner(self) -> T {
        self.inner
    }
    // Ref: smoltcp
    // https://tools.ietf.org/html/rfc2460#section-3.

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
    // end of IPv6 header
    const IP_HEADER_END: usize = 40;
}

impl<T: AsRef<[u8]>> Packet<T> {
    pub fn version(&self) -> u8 {
        self.inner.as_ref()[Self::VER_TC_FLOW.start] >> 4
    }
    pub fn traffic_class(&self) -> u8 {
        ((NetworkEndian::read_u16(&self.inner.as_ref()[0..2]) & 0x0ff0) >> 4) as u8
    }
    pub fn flow_label(&self) -> u32 {
        NetworkEndian::read_u24(&self.inner.as_ref()[1..4]) & 0x000fffff
    }
    pub fn payload_len(&self) -> u16 {
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
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    pub fn payload(&self) -> &'a [u8] {
        &self.inner.as_ref()[Self::IP_HEADER_END..]
    }
}

impl<T: AsMut<[u8]>> Packet<T> {
    pub fn set_version(&mut self, version: u8) {
        debug_assert!(version <= 0x0f);
        let data = &mut self.inner.as_mut()[Self::VER_TC_FLOW];
        data[0] = (data[0] & !0xf0) | ((version & 0x0f) << 4);
    }
    pub fn set_traffic_class(&mut self, traffic_class: u8) {
        let data = &mut self.inner.as_mut()[Self::VER_TC_FLOW];
        data[0] = (data[0] & !0x0f) | ((traffic_class & 0xf0) >> 4);
        data[1] = (data[1] & !0xf0) | ((traffic_class & 0x0f) << 4);
    }
    pub fn set_flow_label(&mut self, flow_label: u32) {
        debug_assert!(flow_label <= 0x000fffff);
        let data = &mut self.inner.as_mut()[Self::VER_TC_FLOW];
        data[1] = (data[1] & !0x0f) | ((flow_label & 0x0f0000) >> 16) as u8;
        data[2] = ((flow_label & 0x00ff00) >> 8) as u8;
        data[3] = (flow_label & 0x0000ff) as u8;
    }
    pub fn set_payload_len(&mut self, payload_len: u16) {
        NetworkEndian::write_u16(&mut self.inner.as_mut()[Self::LENGTH], payload_len)
    }
    pub fn set_next_header(&mut self, protocol: Protocol) {
        self.inner.as_mut()[Self::NXT_HDR] = protocol.into()
    }
    pub fn set_hop_limit(&mut self, hop_limit: u8) {
        self.inner.as_mut()[Self::HOP_LIMIT] = hop_limit
    }
    pub fn set_dst_addr(&mut self, address: Address) {
        NetworkEndian::write_u128(&mut self.inner.as_mut()[Self::DST_ADDR], address.repr)
    }
    pub fn set_src_addr(&mut self, address: Address) {
        NetworkEndian::write_u128(&mut self.inner.as_mut()[Self::SRC_ADDR], address.repr)
    }
}

impl<'a, T: AsMut<[u8]> + ?Sized> Packet<&'a mut T> {
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.inner.as_mut()[Self::IP_HEADER_END..]
    }
}

// Info about IPv6 header: https://tools.ietf.org/html/rfc8200

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

// for example: FE80::/10
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Subnet {
    network: Address, // any bits beyond the prefix should be 0
    prefix: u8,
}

impl Subnet {
    // check prefix mask
    pub const fn new(network: Address, prefix: u8) -> Subnet {
        assert!(prefix <= 128);
        assert!(network.repr.trailing_zeros() >= 128 - prefix as u32);
        unsafe { Self::new_unchecked(network, prefix) }
    }
    // variable 'network' must have last '128 - prefix' bits set to zero
    // this is not checked here so it's unsafe
    pub const unsafe fn new_unchecked(network: Address, prefix: u8) -> Self {
        Self { network, prefix }
    }
    // Section 2.4, https://datatracker.ietf.org/doc/html/rfc4291
    pub const UNSPECIFIED: Subnet =
        Subnet { network: Address::from_segments([0, 0, 0, 0, 0, 0, 0, 0]), prefix: 128 };
    pub const LOOPBACK: Subnet =
        Subnet { network: Address::from_segments([0, 0, 0, 0, 0, 0, 0, 1]), prefix: 128 };
    pub const MULTICAST: Subnet =
        Subnet { network: Address::from_segments([0xff00, 0, 0, 0, 0, 0, 0, 0]), prefix: 8 };
    pub const LINK_LOCAL_UNICAST: Subnet =
        Subnet { network: Address::from_segments([0xfe80, 0, 0, 0, 0, 0, 0, 0]), prefix: 10 };
    // get network part of subnet
    pub fn network(self) -> Address {
        self.network
    }
    // get prefix length, smaller number, larger the network
    pub fn prefix(self) -> u8 {
        self.prefix
    }
}

impl fmt::Display for Subnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::{Address, Subnet};
    #[test]
    fn ip_address_print() {
        assert_eq!("::", Address::from([0, 0, 0, 0, 0, 0, 0, 0]).to_string());
        assert_eq!("::1", Address::from([0, 0, 0, 0, 0, 0, 0, 1]).to_string());
        assert_eq!("FE80::1234:5678", Address::from([0xfe80, 0, 0, 0, 0, 0, 0x1234, 0x5678]).to_string());
        assert_eq!("FF01::101", Address::from([0xff01, 0, 0, 0, 0, 0, 0, 0x101]).to_string());
        assert_eq!("2001:DB8::8:800:200C:417A", Address::from([0x2001, 0xdb8, 0, 0, 8, 0x800, 0x200c, 0x417a]).to_string());
        assert_eq!("2001:DB8:0:CD30::", Address::from([0x2001, 0xdb8, 0, 0xcd30, 0, 0, 0, 0]).to_string());
    }
    #[test]
    fn ip_address_parse() {
        let addrs = [
            "::",
            "::1",
            "FE80::1234:5678", 
            "FF01::101", 
            "2001:DB8::8:800:200C:417A", 
            "2001:DB8:0:CD30::",
            "FD12:3456:7890:ABCD:1122:3344:5566:7788", 
            "FD12:3456:7890:ABCD:1122:3344:5566::", 
            "FD12:3456:7890:ABCD:1122:3344::", 
            "::3456:7890:ABCD:1122:3344:5566:7788", 
            "::7890:ABCD:1122:3344:5566:7788", 
        ];
        for addr_str in addrs {
            let addr = addr_str.parse::<Address>().unwrap();
            assert_eq!(addr_str, addr.to_string());
        }
        let wrong_addrs = [
            "::1::",
            "FF01:::101", 
            "2001:DB8::8:800::200C:417A",
            ":FD12:3456:7890:ABCD:1122:3344:5566:7788", 
            "FD12:3456:7890:ABCD:1122:3344:5566:7788:", 
            "FD12:3456:7890:ABCD:1122:3344:5566:7788:9", 
            "FD12:3456:7890:ABCD:1122:3344:5566:EFGH", 
        ];
        for addr_str in wrong_addrs {
            assert!(addr_str.parse::<Address>().is_err());
        }
    }
    #[test]
    fn ip_address_segments_octets() {
        assert_eq!(
            Address::from([0xfe80, 0, 0, 0, 0, 0, 0x1234, 0x5678]).segments(), 
            [0xfe80, 0, 0, 0, 0, 0, 0x1234, 0x5678]
        );
        assert_eq!(
            Address::from([0xfe80, 0, 0, 0, 0, 0, 0x1234, 0x5678]).octets(), 
            [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78]
        );
    }
    #[test]
    fn ip_subnet_print() {
        assert_eq!("FF00::/8", Subnet::MULTICAST.to_string());
        assert_eq!("FE80::/10", Subnet::LINK_LOCAL_UNICAST.to_string());
        assert_eq!("::1/128", Subnet::LOOPBACK.to_string());
        assert_eq!("::/128", Subnet::UNSPECIFIED.to_string());
    }
}
