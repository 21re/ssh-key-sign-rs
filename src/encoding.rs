use crate::error::{Error, Result};
use byteorder::{BigEndian, ByteOrder};

pub struct Reader<'a> {
  data: &'a [u8],
  position: usize,
}

impl<'a> Reader<'a> {
  pub fn new(data: &'a [u8]) -> Reader<'a> {
    Reader { data, position: 0 }
  }

  #[inline]
  pub fn remaining_len(&self) -> usize {
    self.data.len() - self.position
  }

  pub fn remaining(&self) -> &'a [u8] {
    &self.data[self.position..]
  }

  pub fn read_u8(&mut self) -> Result<u8> {
    if self.remaining_len() >= 1 {
      let b = self.data[self.position];
      self.position += 1;
      Ok(b)
    } else {
      Err(Error::BufferTooShort)
    }
  }

  pub fn read_u32(&mut self) -> Result<u32> {
    if self.remaining_len() >= 4 {
      let u = BigEndian::read_u32(&self.data[self.position..]);
      self.position += 4;
      Ok(u)
    } else {
      Err(Error::BufferTooShort)
    }
  }

  pub fn read_string(&mut self) -> Result<&'a [u8]> {
    let len = self.read_u32()? as usize;
    if self.remaining_len() >= len {
      let result = &self.data[self.position..(self.position + len)];
      self.position += len;
      Ok(result)
    } else {
      Err(Error::BufferTooShort)
    }
  }
}

pub struct Writer {
  pub buffer: Vec<u8>,
}

impl Writer {
  pub fn new() -> Writer {
    let buffer = Vec::with_capacity(256);
    Writer { buffer }
  }

  pub fn write_u8(&mut self, b: u8) {
    self.buffer.push(b);
  }

  pub fn write_u32(&mut self, i: u32) {
    let mut bytes = [0u8; 4];
    BigEndian::write_u32(&mut bytes, i);
    self.buffer.extend_from_slice(&bytes);
  }

  pub fn write_string(&mut self, s: &[u8]) {
    let mut len_bytes = [0u8; 4];
    BigEndian::write_u32(&mut len_bytes, s.len() as u32);
    self.buffer.reserve(4 + s.len());
    self.buffer.extend_from_slice(&len_bytes);
    self.buffer.extend_from_slice(s);
  }
}
