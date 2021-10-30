use byteorder::{ByteOrder, NetworkEndian};
use core::ops::{Range, RangeFrom};

pub struct PacketWrite<T> {
    out_buf: T,
    byte_idx: usize,
    cur_idx: usize,
}

impl<T: AsMut<[u8]>> PacketWrite<T> {
    #[inline]
    pub fn new(buf: T, byte_idx: usize) -> Self {
        Self { out_buf: buf, byte_idx, cur_idx: 0 }
    }
    #[inline]
    pub(crate) fn buffer_index(&self) -> usize {
        self.byte_idx
    }
    #[inline]
    pub(crate) fn bytes_written(&self) -> usize {
        self.cur_idx
    }
}

impl<T: AsMut<[u8]>> PacketWrite<T> {
    #[inline]
    pub fn write_u8_at(&mut self, range: Range<usize>, value: u8) {
        if !range.contains(&self.byte_idx) {
            return
        }
        let out_buf = self.out_buf.as_mut();
        if self.cur_idx < out_buf.len() {
            out_buf[self.cur_idx] = value; 
            self.byte_idx += 1;
            self.cur_idx += 1;
        }
    }
    #[inline]
    pub fn write_u16_at(&mut self, range: Range<usize>, value: u16) {
        if !range.contains(&self.byte_idx) {
            return
        }
        let mut tmp_buf = [0u8; 2];
        NetworkEndian::write_u16(&mut tmp_buf, value);
        let out_buf = self.out_buf.as_mut();
        let write_len = usize::min(range.end - self.byte_idx, out_buf.len() - self.cur_idx);
        let start_idx = self.byte_idx - range.start;
        out_buf[self.cur_idx..self.cur_idx + write_len].copy_from_slice(&tmp_buf[start_idx..start_idx + write_len]); 
        self.byte_idx += write_len;
        self.cur_idx += write_len;
    }
    #[inline]
    pub fn write_slice_at(&mut self, range: RangeFrom<usize>, slice: &[u8]) {
        if !range.contains(&self.byte_idx) {
            return
        }
        let out_buf = self.out_buf.as_mut();
        let write_len = usize::min(slice.len() + (range.start - self.byte_idx), out_buf.len() - self.cur_idx);
        let start_idx = self.byte_idx - range.start;
        out_buf[self.cur_idx..self.cur_idx + write_len].copy_from_slice(&slice[start_idx..start_idx + write_len]); 
        self.byte_idx += write_len;
        self.cur_idx += write_len;
    }
}
