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
  pub fn remaining(&self) -> usize {
    self.data.len() - self.position
  }

  pub fn read_u8(&mut self) -> Result<u8> {
    if self.remaining() >= 1 {
      let b = self.data[self.position];
      self.position += 1;
      Ok(b)
    } else {
      Err(Error::BufferTooShort)
    }
  }

  pub fn read_u32(&mut self) -> Result<u32> {
    if self.remaining() >= 4 {
      let u = BigEndian::read_u32(&self.data[self.position..]);
      self.position += 4;
      Ok(u)
    } else {
      Err(Error::BufferTooShort)
    }
  }

  pub fn read_string(&mut self) -> Result<&'a [u8]> {
    let len = self.read_u32()? as usize;
    if self.remaining() >= len {
      let result = &self.data[self.position..(self.position + len)];
      self.position += len;
      Ok(result)
    } else {
      Err(Error::BufferTooShort)
    }
  }
}
