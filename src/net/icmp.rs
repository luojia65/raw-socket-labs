// ICMPv6
use byteorder::{ByteOrder, NetworkEndian};
use core::ops::Range;

// ICMPv6 packet
#[derive(Debug, Clone, Copy)]
pub struct Packet<T> {
    inner: T
}

impl<T> Packet<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
    const TYPE: usize = 0;
    const CODE: usize = 1;
    const CHECKSUM: Range<usize> = 2..4;
}

// ICMPv6: See https://tools.ietf.org/html/rfc4443

impl<T: AsRef<[u8]>> Packet<T> {
    pub fn packet_type(&self) -> Type {
        self.inner.as_ref()[Self::TYPE].into()
    }
    pub fn code(&self) -> u8 {
        self.inner.as_ref()[Self::CODE]
    }
    pub fn checksum(&self) -> u16 {
        NetworkEndian::read_u16(&self.inner.as_ref()[Self::CHECKSUM])
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    pub fn payload(&self) -> &'a [u8] {
        &self.inner.as_ref()[4..]
    }
}

impl<T: AsMut<[u8]>> Packet<T> {
    pub fn set_packet_type(&mut self, ty: Type) {
        self.inner.as_mut()[Self::TYPE] = ty.into()
    }
    pub fn set_code(&mut self, code: u8) {
        self.inner.as_mut()[Self::CODE] = code
    }
    pub fn set_checksum(&mut self, checksum: u16) {
        NetworkEndian::write_u16(&mut self.inner.as_mut()[Self::CHECKSUM], checksum)
    }
}

impl<'a, T: AsMut<[u8]> + ?Sized> Packet<&'a mut T> {
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.inner.as_mut()[Self::CHECKSUM.end..]
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

impl<T> EchoRequest<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
    const IDENTIFIER: Range<usize> = 0..2;
    const SEQUENCE_NUMBER: Range<usize> = 2..4;
    
}

impl<T: AsRef<[u8]>> EchoRequest<T> {
    pub fn identifier(&self) -> u16 {
        NetworkEndian::read_u16(&self.inner.as_ref()[Self::IDENTIFIER])
    }
    pub fn sequence_number(&self) -> u16 {
        NetworkEndian::read_u16(&self.inner.as_ref()[Self::SEQUENCE_NUMBER])
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> EchoRequest<&'a T> {
    pub fn data(&self) -> &'a [u8] {
        &self.inner.as_ref()[Self::SEQUENCE_NUMBER.end..]
    }
}

impl<T: AsMut<[u8]>> EchoRequest<T> {
    pub fn set_identifier(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.inner.as_mut()[Self::IDENTIFIER], value)
    }
    pub fn set_sequence_number(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.inner.as_mut()[Self::SEQUENCE_NUMBER], value)
    }
}

impl<'a, T: AsMut<[u8]> + ?Sized> EchoRequest<&'a mut T> {
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.inner.as_mut()[Self::SEQUENCE_NUMBER.end..]
    }
}
