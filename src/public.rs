use crate::encoding::{Reader, Writer};
use crate::error::{Error, Result};
use crate::mini_der;
use crate::signature::SignatureHash;
use ring::signature::ED25519_PUBLIC_KEY_LEN;

pub const SSH_ED25519: &[u8] = b"ssh-ed25519";
pub const SSH_ECDSA_P256: &[u8] = b"ecdsa-sha2-nistp256";
pub const SSH_ECDSA_P384: &[u8] = b"ecdsa-sha2-nistp384";
pub const SSH_ECDSA_P256_KEY_TYPE: &[u8] = b"nistp256";
pub const SSH_ECDSA_P384_KEY_TYPE: &[u8] = b"nistp384";
pub const SSH_RSA: &[u8] = b"ssh-rsa";
pub const SSH_RSA_SHA2_256: &[u8] = b"rsa-sha2-256";
pub const SSH_RSA_SHA2_512: &[u8] = b"rsa-sha2-512";

#[derive(Debug)]
pub enum PublicKey {
  Ed25519(Vec<u8>),
  EcdsaP256(Vec<u8>),
  EcdsaP384(Vec<u8>),
  Rsa {
    e: Vec<u8>,
    n: Vec<u8>,
    preferred_hash: SignatureHash,
  },
}

impl PublicKey {
  pub fn parse_pub(line: &str) -> Result<PublicKey> {
    let parts: Vec<&str> = line.split(' ').collect();

    if parts.len() < 2 {
      return Err(Error::CouldNotReadKey);
    }
    let raw_key = base64::decode_config(parts[1], base64::STANDARD)?;
    let key = Self::parse_raw(&raw_key)?;

    match (parts[0].as_bytes(), key) {
      (SSH_ED25519, k @ PublicKey::Ed25519(_)) => Ok(k),
      (SSH_ECDSA_P256, k @ PublicKey::EcdsaP256(_)) => Ok(k),
      (SSH_ECDSA_P384, k @ PublicKey::EcdsaP384(_)) => Ok(k),
      (SSH_RSA, PublicKey::Rsa { e, n, .. }) => Ok(PublicKey::Rsa {
        n,
        e,
        preferred_hash: SignatureHash::RsaSha1,
      }),
      (SSH_RSA_SHA2_256, PublicKey::Rsa { e, n, .. }) => Ok(PublicKey::Rsa {
        n,
        e,
        preferred_hash: SignatureHash::RsaSha256,
      }),
      (SSH_RSA_SHA2_512, PublicKey::Rsa { e, n, .. }) => Ok(PublicKey::Rsa {
        n,
        e,
        preferred_hash: SignatureHash::RsaSha512,
      }),
      _ => Err(Error::CouldNotReadKey),
    }
  }

  pub fn parse_raw(raw_key: &[u8]) -> Result<PublicKey> {
    let mut reader = Reader::new(raw_key);

    let algo = reader.read_string()?;

    match algo {
      SSH_ED25519 => {
        let key = reader.read_string()?;

        if key.len() == ED25519_PUBLIC_KEY_LEN {
          Ok(PublicKey::Ed25519(Vec::from(key)))
        } else {
          Err(Error::InvalidKeyLength)
        }
      }
      SSH_ECDSA_P256 => {
        let key_type = reader.read_string()?;
        let q = reader.read_string()?;

        if key_type == SSH_ECDSA_P256_KEY_TYPE {
          Ok(PublicKey::EcdsaP256(Vec::from(q)))
        } else {
          Err(Error::CouldNotReadKey)
        }
      }
      SSH_ECDSA_P384 => {
        let key_type = reader.read_string()?;
        let q = reader.read_string()?;

        if key_type == SSH_ECDSA_P384_KEY_TYPE {
          Ok(PublicKey::EcdsaP384(Vec::from(q)))
        } else {
          Err(Error::CouldNotReadKey)
        }
      }
      SSH_RSA => {
        let e = Vec::from(reader.read_string()?);
        let n = Vec::from(reader.read_string()?);

        Ok(PublicKey::Rsa {
          n,
          e,
          preferred_hash: SignatureHash::RsaSha512, // By default we always prefer SHA2 signatures
        })
      }
      _ => Err(Error::CouldNotReadKey),
    }
  }

  pub fn to_ssh_key(&self) -> Vec<u8> {
    let mut writer = Writer::new();
    match self {
      PublicKey::Ed25519(key) => {
        writer.write_string(SSH_ED25519);
        writer.write_string(key);
      }
      PublicKey::EcdsaP256(key) => {
        writer.write_string(SSH_ECDSA_P256);
        writer.write_string(SSH_ECDSA_P256_KEY_TYPE);
        writer.write_string(key);
      }
      PublicKey::EcdsaP384(key) => {
        writer.write_string(SSH_ECDSA_P384);
        writer.write_string(SSH_ECDSA_P384_KEY_TYPE);
        writer.write_string(key);
      }
      PublicKey::Rsa { e, n, .. } => {
        writer.write_string(SSH_RSA);
        writer.write_string(e);
        writer.write_string(n);
      }
    }
    writer.buffer
  }

  pub fn to_ring_key(&self) -> Vec<u8> {
    match self {
      PublicKey::Ed25519(key) => key.clone(),
      PublicKey::EcdsaP256(key) => key.clone(),
      PublicKey::EcdsaP384(key) => key.clone(),
      PublicKey::Rsa { n, e, .. } => mini_der::encode_rsa_public(n, e),
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

  #[test]
  fn read_rsa_pub() {
    let line = read_first_line("fixtures/unencrypted_rsa.pub");
    match PublicKey::parse_pub(&line).unwrap() {
      PublicKey::Rsa { .. } => (),
      _ => panic!("Not a rsa key"),
    }
  }

  #[test]
  fn read_ecdsa_pub() {
    let line = read_first_line("fixtures/unencrypted_ecdsa.pub");
    match PublicKey::parse_pub(&line).unwrap() {
      PublicKey::EcdsaP256(_) => (),
      _ => panic!("Not an ecdsa key"),
    }
  }

  #[test]
  fn read_ecdsa384_pub() {
    let line = read_first_line("fixtures/unencrypted_ecdsa384.pub");
    match PublicKey::parse_pub(&line).unwrap() {
      PublicKey::EcdsaP384(_) => (),
      _ => panic!("Not an ecdsa key"),
    }
  }

  #[test]
  fn read_ed25519() {
    let line = read_first_line("fixtures/unencrypted_ed25519.pub");
    match PublicKey::parse_pub(&line).unwrap() {
      PublicKey::Ed25519(_) => (),
      _ => panic!("Not an ed25519 key"),
    }
  }
}
