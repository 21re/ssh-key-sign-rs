use crate::encoding::Reader;
use crate::error::{Error, Result};
use ring::signature::ED25519_PUBLIC_KEY_LEN;
use crate::mini_der;

const SSH_ED25519: &[u8] = b"ssh-ed25519";
const SSH_ECDSA_P256: &[u8] = b"ecdsa-sha2-nistp256";
const SSH_RSA: &[u8] = b"ssh-rsa";

#[derive(Debug)]
pub enum PublicKey {
  ED25519(Vec<u8>),
  ECDSA_P256(Vec<u8>),
  RSA(Vec<u8>),
}

impl PublicKey {
  pub fn parse_pub(line: &str) -> Result<PublicKey> {
    let parts: Vec<&str> = line.split(' ').collect();

    if parts.len() < 2 {
      return Err(Error::CouldNotReadKey);
    }
    let raw_key = base64::decode_config(parts[1], base64::STANDARD)?;
    let (key_algo, key) = Self::decode_key(&raw_key)?;

    match (parts[0].as_bytes(), key_algo) {
      (SSH_ED25519, SSH_ED25519) => {
        if key.len() == ED25519_PUBLIC_KEY_LEN {
          Ok(PublicKey::ED25519(key))
        } else {
          Err(Error::InvalidKeyLength)
        }
      }
      (SSH_ECDSA_P256, SSH_ECDSA_P256) => Ok(PublicKey::ECDSA_P256(key)),
      (SSH_RSA, SSH_RSA) => Ok(PublicKey::RSA(key)),
      _ => Err(Error::CouldNotReadKey),
    }
  }

  pub fn parse_rew(raw_key: &[u8]) -> Result<PublicKey> {
    let (key_algo, key) = Self::decode_key(&raw_key)?;

    match key_algo {
      SSH_ECDSA_P256 => {
        if key.len() == ED25519_PUBLIC_KEY_LEN {
          Ok(PublicKey::ED25519(key))
        } else {
          Err(Error::InvalidKeyLength)
        }
      }
      SSH_ECDSA_P256 => Ok(PublicKey::ECDSA_P256(key)),
      SSH_RSA => Ok(PublicKey::RSA(key)),
      _ => Err(Error::CouldNotReadKey),
    }
  }

  fn decode_key(raw_key: &[u8]) -> Result<(&[u8], Vec<u8>)> {
    let mut reader = Reader::new(raw_key);

    let algo = reader.read_string()?;

    match algo {
      SSH_ED25519 => {
        let key = reader.read_string()?;

        Ok((algo, Vec::from(key)))
      },
      SSH_ECDSA_P256 => {
        let key = reader.read_string()?;

        Ok((algo, Vec::from(key)))
      }
      SSH_RSA => {
        let e = reader.read_string()?;
        let n = reader.read_string()?;
        let key = mini_der::encode_rsa_public(n, e);

        Ok((algo, key))
      }
      _ => Err(Error::CouldNotReadKey),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::fs::File;
  use std::io::{BufRead, BufReader};

  fn read_first_line(file: &str) -> String {
    let reader = BufReader::new(File::open(file).unwrap());

    reader.lines().next().unwrap().unwrap()
  }
  use spectral::prelude::*;
  #[test]
  fn read_rsa_pub() {
    let line = read_first_line("fixtures/unencrypted_rsa.pub");
    match PublicKey::parse_pub(&line).unwrap() {
      PublicKey::RSA(der) => {
        println!("{:x?}", der);

      },
      _ => panic!("Not a rsa key"),
    }

    let der = base64::decode_config("MIIBCgKCAQEAs3zgPf9b1KHtUmgfKy9QX0ucGtLqXpVZ0ThyEQifn6zishl/4o+v8092W24q33s0AoiOa/Nm233Isb3M9M//14qMCNHOAsggrccFOTgKxxYjBEJLZg7gIOShOdtVh8KI+QFQybBpsY3OIR6dTFlR32eQsZonab5lLWOlWPaxXYNfmmhPF8dxM87oyBp6Au+1IhzuYuP0uiQdAn2yww2AgZ0aFybh9OtnvTvidrbrdsBUEq3Vni4/MMd4+w/YciJBN0Zn4R0FXW3Ns4XKwSfKRbb/5SYSg0nR8c7SS5IAdWS5khR5nqUId995oEfOAzLhzHNiwAujPlSBITTYQ9u0IwIDAQAB", base64::STANDARD).unwrap();

    println!("{:x?}", der);

  }

  #[test]
  fn read_ecdsa_pub() {
    let line = read_first_line("fixtures/unencrypted_ecdsa.pub");
    match PublicKey::parse_pub(&line).unwrap() {
      PublicKey::ECDSA_P256(_) => (),
      _ => panic!("Not an ecdsa key"),
    }

  }

  #[test]
  fn read_ed25519() {
    let line = read_first_line("fixtures/unencrypted_ed25519.pub");
    match PublicKey::parse_pub(&line).unwrap() {
      PublicKey::ED25519(_) => (),
      _ => panic!("Not an ed25519 key"),
    }
  }
}
