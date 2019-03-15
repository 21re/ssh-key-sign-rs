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
  buffer: Vec<u8>,
}

impl MessageBuilder {
  pub fn new() -> MessageBuilder {
    let mut buffer = Vec::with_capacity(256);
    buffer.extend_from_slice(&[0; 4]);
    MessageBuilder { buffer }
  }

  pub fn write_u8(&mut self, b: u8) {
    self.buffer.push(b);
  }

  pub fn write_string(&mut self, s: &[u8]) {
    let mut len_bytes = [0u8; 4];
    BigEndian::write_u32(&mut len_bytes, s.len() as u32);
    self.buffer.reserve(4 + s.len());
    self.buffer.extend_from_slice(&len_bytes);
    self.buffer.extend_from_slice(s);
  }

  pub fn payload(&mut self) -> &[u8] {
    let msg_len = self.buffer.len() as u32 - 4;
    BigEndian::write_u32(&mut self.buffer, msg_len);
    &self.buffer
  }
}
