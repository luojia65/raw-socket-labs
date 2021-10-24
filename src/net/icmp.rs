// ICMPv6
use byteorder::{ByteOrder, NetworkEndian};
use core::ops::Range;

// ICMPv6 packet
#[derive(Debug, Clone, Copy)]
pub struct Packet<T> {
    inner: T
}

impl<T: AsRef<[u8]>> Packet<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

// ICMPv6: See https://tools.ietf.org/html/rfc4443

impl<T: AsRef<[u8]>> Packet<T> {
    const TYPE: usize = 0;
    const CODE: usize = 1;
    const CHECKSUM: Range<usize> = 2..4;

    pub fn packet_type(&self) -> Type {
        self.inner.as_ref()[Self::TYPE].into()
    }
    pub fn code(&self) -> u8 {
        self.inner.as_ref()[Self::CODE]
    }
    pub fn checksum(&self) -> u16 {
        NetworkEndian::read_u16(&self.inner.as_ref()[Self::CHECKSUM])
    }
    pub fn payload(&self) -> &[u8] {
        &self.inner.as_ref()[4..]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    EchoRequest, // 128
    Unknown(u8),
}

impl From<u8> for Type {
    fn from(src: u8) -> Self {
        match src {
            128 => Type::EchoRequest,
            others => Type::Unknown(others),
        }
    }
}

impl From<Type> for u8 {
    fn from(src: Type) -> u8 {
        match src {
            Type::EchoRequest => 128,
            Type::Unknown(others) => others
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EchoRequest<T> {
    inner: T
}

impl<T: AsRef<[u8]>> EchoRequest<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T: AsRef<[u8]>> EchoRequest<T> {
    const IDENTIFIER: Range<usize> = 0..2;
    const SEQUENCE_NUMBER: Range<usize> = 2..4;
    
    pub fn identifier(&self) -> u16 {
        NetworkEndian::read_u16(&self.inner.as_ref()[Self::IDENTIFIER])
    }
    pub fn sequence_number(&self) -> u16 {
        NetworkEndian::read_u16(&self.inner.as_ref()[Self::SEQUENCE_NUMBER])
    }
    pub fn data(&self) -> &[u8] {
        &self.inner.as_ref()[4..]
    }
}
