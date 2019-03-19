use crate::encoding::Writer;
use byteorder::{BigEndian, ByteOrder};

pub const FAILURE: u8 = 5;
pub const SUCCESS: u8 = 6;
pub const IDENTITIES_ANSWER: u8 = 12;
pub const SIGN_RESPONSE: u8 = 14;

pub const REQUEST_IDENTITIES: u8 = 11;
pub const SIGN_REQUEST: u8 = 13;
pub const ADD_IDENTITY: u8 = 17;
pub const REMOVE_IDENTITY: u8 = 18;
pub const REMOVE_ALL_IDENTITIES: u8 = 19;
pub const ADD_ID_CONSTRAINED: u8 = 25;
pub const ADD_SMARTCARD_KEY: u8 = 20;
pub const REMOVE_SMARTCARD_KEY: u8 = 21;
pub const LOCK: u8 = 22;
pub const UNLOCK: u8 = 23;
pub const ADD_SMARTCARD_KEY_CONSTRAINED: u8 = 26;
pub const EXTENSION: u8 = 27;

pub const CONSTRAIN_LIFETIME: u8 = 1;
pub const CONSTRAIN_CONFIRM: u8 = 2;
pub const CONSTRAIN_EXTENSION: u8 = 3;

pub struct MessageBuilder {
  writer: Writer,
}

impl MessageBuilder {
  pub fn new() -> MessageBuilder {
    let mut writer = Writer::new();
    writer.write_u32(0);
    MessageBuilder { writer }
  }

  pub fn write_u8(&mut self, b: u8) {
    self.writer.write_u8(b);
  }

  pub fn write_u32(&mut self, i: u32) {
    self.writer.write_u32(i);
  }

  pub fn write_string(&mut self, s: &[u8]) {
    self.writer.write_string(s)
  }

  pub fn payload(&mut self) -> &[u8] {
    let msg_len = self.writer.buffer.len() as u32 - 4;
    BigEndian::write_u32(&mut self.writer.buffer, msg_len);
    &self.writer.buffer
  }
}
