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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Buffer<T> {
    write_type: WriteType<T>,
    byte_idx: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum WriteType<T> {
    EchoRequest { identifier: u16, sequence_number: u16, data: T }
}

impl<T> Buffer<T> {
    pub fn echo_request(identifier: u16, sequence_number: u16, data: T) -> Buffer<T> {
        Buffer { 
            write_type: WriteType::EchoRequest { identifier, sequence_number, data },
            byte_idx: 0,
        }
    }
}

impl<T: AsRef<[u8]>> Buffer<T> {
    pub fn len(&self) -> usize {
        match &self.write_type {
            WriteType::EchoRequest { data, .. } => data.as_ref().len() + 8,
        }
    }
    #[must_use]
    pub fn consume(&mut self, out_buf: &mut [u8]) -> usize {
        let mut cur_idx = 0;
        let (typ, code) = match self.write_type {
            WriteType::EchoRequest { .. } => (Type::EchoRequest, 0),
        };
        if self.byte_idx < 1 {
            if cur_idx < out_buf.len() {
                out_buf[cur_idx] = typ.into(); 
                self.byte_idx += 1;
                cur_idx += 1;
            }
        }
        if self.byte_idx >= 1 && self.byte_idx < 2 {
            if cur_idx < out_buf.len() {
                out_buf[cur_idx] = code; 
                self.byte_idx += 1;
                cur_idx += 1;
            }
        }
        let mut tmp_buf = [0u8; 2];
        let checksum = 0x8901; // todo
        if self.byte_idx >= 2 && self.byte_idx < 4 {
            NetworkEndian::write_u16(&mut tmp_buf, checksum);
            let write_len = usize::min(4 - self.byte_idx, out_buf.len() - cur_idx);
            let start_idx = self.byte_idx - 2;
            out_buf[cur_idx..cur_idx + write_len].copy_from_slice(&tmp_buf[start_idx..start_idx + write_len]); 
            self.byte_idx += write_len;
            cur_idx += write_len;
        }
        match &self.write_type {
            WriteType::EchoRequest { identifier, sequence_number, data } => {
                if self.byte_idx >= 4 && self.byte_idx < 6 {
                    NetworkEndian::write_u16(&mut tmp_buf, *identifier);
                    let write_len = usize::min(6 - self.byte_idx, out_buf.len() - cur_idx);
                    let start_idx = self.byte_idx - 4;
                    out_buf[cur_idx..cur_idx + write_len].copy_from_slice(&tmp_buf[start_idx..start_idx + write_len]); 
                    self.byte_idx += write_len;
                    cur_idx += write_len;
                }
                if self.byte_idx >= 6 && self.byte_idx < 8 {
                    NetworkEndian::write_u16(&mut tmp_buf, *sequence_number);
                    let write_len = usize::min(8 - self.byte_idx, out_buf.len() - cur_idx);
                    let start_idx = self.byte_idx - 6;
                    out_buf[cur_idx..cur_idx + write_len].copy_from_slice(&tmp_buf[start_idx..start_idx + write_len]); 
                    self.byte_idx += write_len;
                    cur_idx += write_len;
                }
                if self.byte_idx >= 8 {
                    let in_buf = data.as_ref();
                    let write_len = usize::min(in_buf.len() + 8 - self.byte_idx, out_buf.len() - cur_idx);
                    let start_idx = self.byte_idx - 8;
                    out_buf[cur_idx..cur_idx + write_len].copy_from_slice(&in_buf[start_idx..start_idx + write_len]); 
                    self.byte_idx += write_len;
                    cur_idx += write_len;
                }
            },
        }
        cur_idx
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icmp_buffer_write() {
        let data: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
        let mut echo = Buffer::echo_request(0x1234, 0x5678, data);
        let mut out = vec![0u8; 3]; // not enough to write whole icmp packet
        let len = echo.consume(&mut out);
        eprintln!("{:x?}", &out[..len]);
        let mut out = vec![0u8; 5]; 
        let len = echo.consume(&mut out);
        eprintln!("{:x?}", &out[..len]);
        let mut out = vec![0u8; 20]; 
        let len = echo.consume(&mut out);
        eprintln!("{:x?}", &out[..len]);
    }
}
