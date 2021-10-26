use super::eui::Eui48 as Address;
use byteorder::{ByteOrder, NetworkEndian};
use core::ops::{Range, RangeFrom};

pub struct Frame<T> {
    inner: T
}

impl<T: AsRef<[u8]>> Frame<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}


impl<T: AsRef<[u8]>> Frame<T> {
    const DEST_ADDR: Range<usize> = 0..6;
    const SRC_ADDR: Range<usize> = 6..12;
    const ETHERTYPE: Range<usize> = 12..14;
    const PAYLOAD: RangeFrom<usize> = 14..;

    pub fn dst_addr(&self) -> Address {
        Address::from_bytes(&self.inner.as_ref()[Self::DEST_ADDR])
    }
    pub fn src_addr(&self) -> Address {
        Address::from_bytes(&self.inner.as_ref()[Self::SRC_ADDR])
    }
    // does not support IEEE 802.3 frames and 802.1Q fields
    pub fn ethertype(&self) -> Type {
        let ty = NetworkEndian::read_u16(&self.inner.as_ref()[Self::ETHERTYPE]);
        Type::from(ty)
    }
    pub fn header_len(&self) -> usize {
        Self::PAYLOAD.start
    }
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Frame<&'a T> {
    pub fn payload(&self) -> &'a [u8] {
        &self.inner.as_ref()[Self::PAYLOAD]
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
