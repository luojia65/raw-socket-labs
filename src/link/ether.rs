use super::eui::Eui48 as Address;
use byteorder::{ByteOrder, NetworkEndian};

pub struct Frame<T> {
    inner: T
}

impl<T: AsRef<[u8]>> Frame<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

mod field {
    use core::ops::{Range, RangeFrom};
    pub const DEST_ADDR: Range<usize> = 0..6;
    pub const SRC_ADDR: Range<usize> = 6..12;
    pub const ETHERTYPE: Range<usize> = 12..14;
    pub const PAYLOAD: RangeFrom<usize> = 14..;
}
// pub const HEADER_LEN: usize = field::PAYLOAD.start;

impl<T: AsRef<[u8]>> Frame<T> {
    pub fn dst_addr(&self) -> Address {
        Address::from_bytes(&self.inner.as_ref()[field::DEST_ADDR])
    }
    pub fn src_addr(&self) -> Address {
        Address::from_bytes(&self.inner.as_ref()[field::SRC_ADDR])
    }
    // does not support IEEE 802.3 frames and 802.1Q fields
    pub fn ethertype(&self) -> Type {
        let ty = NetworkEndian::read_u16(&self.inner.as_ref()[field::ETHERTYPE]);
        Type::from(ty)
    }
    pub fn payload(&self) -> &[u8] {
        &self.inner.as_ref()[field::PAYLOAD]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Type {
    Ipv6,
    Unknown(u16),
}

impl From<u16> for Type {
    fn from(src: u16) -> Self {
        match src {
            0x86DD => Type::Ipv6,
            others => Type::Unknown(others),
        }
    }
}

impl From<Type> for u16 {
    fn from(src: Type) -> u16 {
        match src {
            Type::Ipv6 => 0x86DD,
            Type::Unknown(others) => others
        }
    }
}
