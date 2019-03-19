use crate::agent::msg::{
  MessageBuilder, IDENTITIES_ANSWER, REMOVE_ALL_IDENTITIES, REQUEST_IDENTITIES, SIGN_REQUEST, SIGN_RESPONSE, SUCCESS,
};
use crate::encoding::Reader;
use crate::error::{Error, Result};
use crate::public::PublicKey;
use crate::signature::{Signature, SignatureHash};
use byteorder::{BigEndian, ByteOrder};
use std::io::{Read, Write};
use std::str;

#[derive(Debug)]
pub struct Identity {
  pub key: PublicKey,
  pub comment: String,
}

pub struct AgentClient<S> {
  stream: S,
}

impl<S> AgentClient<S>
where
  S: Read + Write,
{
  pub fn connect(stream: S) -> AgentClient<S> {
    AgentClient { stream }
  }

  pub fn request_identities(&mut self) -> Result<Vec<Identity>> {
    let mut msg = MessageBuilder::new();

    msg.write_u8(REQUEST_IDENTITIES);
    self.stream.write_all(msg.payload())?;

    let response = self.read_response()?;
    let mut reader = Reader::new(&response);

    if reader.read_u8()? != IDENTITIES_ANSWER {
      return Err(Error::RequestFailure);
    }
    let n = reader.read_u32()?;
    let mut identities = Vec::with_capacity(n as usize);

    for _ in 0..n {
      let raw_key = reader.read_string()?;
      let raw_comment = reader.read_string()?;
      let key = PublicKey::parse_raw(raw_key)?;
      let comment = str::from_utf8(raw_comment)?.to_string();

      identities.push(Identity { key, comment })
    }

    Ok(identities)
  }

  pub fn sign_request(&mut self, key: &PublicKey, data: &[u8]) -> Result<Signature> {
    let mut msg = MessageBuilder::new();

    msg.write_u8(SIGN_REQUEST);
    msg.write_string(&key.to_ssh_key());
    msg.write_string(data);
    match key {
      PublicKey::Rsa {
        preferred_hash: SignatureHash::RsaSha256,
        ..
      } => msg.write_u32(2),
      PublicKey::Rsa {
        preferred_hash: SignatureHash::RsaSha512,
        ..
      } => msg.write_u32(4),
      _ => msg.write_u32(0),
    }
    self.stream.write_all(msg.payload())?;

    let response = self.read_response()?;
    let mut reader = Reader::new(&response);

    if reader.read_u8()? != SIGN_RESPONSE {
      return Err(Error::RequestFailure);
    }
    let raw_signature = reader.read_string()?;

    Signature::parse_raw(raw_signature)
  }

  pub fn remove_all_identities(&mut self) -> Result<()> {
    let mut msg = MessageBuilder::new();

    msg.write_u8(REMOVE_ALL_IDENTITIES);
    self.stream.write_all(msg.payload())?;

    let response = self.read_response()?;
    let mut reader = Reader::new(&response);

    if reader.read_u8()? != SUCCESS {
      return Err(Error::RequestFailure);
    }
    Ok(())
  }

  fn read_response(&mut self) -> Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    self.stream.read_exact(&mut len_bytes)?;
    let msg_len = BigEndian::read_u32(&len_bytes) as usize;

    let mut msg = vec![0u8; msg_len];
    self.stream.read_exact(&mut msg)?;

    Ok(msg)
  }
}
