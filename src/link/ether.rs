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
    pub fn dest_addr(&self) -> Address {
        Address::from_bytes(&self.inner.as_ref()[field::DEST_ADDR])
    }
    pub fn src_addr(&self) -> Address {
        Address::from_bytes(&self.inner.as_ref()[field::SRC_ADDR])
    }
    pub fn ethertype(&self) -> u16 {
        NetworkEndian::read_u16(&self.inner.as_ref()[field::ETHERTYPE])
    }
    pub fn payload(&self) -> &[u8] {
        &self.inner.as_ref()[field::PAYLOAD]
    }
}
