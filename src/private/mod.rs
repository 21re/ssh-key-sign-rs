use crate::error::{Error, Result};
use hex::FromHex;
mod bcrypt_pbkdf;
mod blowflish;
mod openssh;

const AES_128_CBC: &'static str = "DEK-Info: AES-128-CBC,";

#[derive(Debug)]
pub enum KeyPair {
  Rsa,
  Ed25519 { pubkey: Vec<u8>, seckey: Vec<u8> },
}

#[derive(Clone, Copy, Debug)]
/// AES encryption key.
pub enum Encryption {
  /// Key for AES128
  Aes128Cbc([u8; 16]),
  /// Key for AES256
  Aes256Cbc([u8; 16]),
}

#[derive(Debug)]
enum Format {
  Openssh,
  Rsa,
  Pkcs5Encrypted(Encryption),
  Pkcs8Encrypted,
  Pkcs8,
}

/// Decode a secret key, possibly deciphering it with the supplied
/// password.
pub fn decode_secret_key(secret: &str, password: Option<&[u8]>) -> Result<KeyPair> {
  let mut format = None;
  let secret = {
    let mut started = false;
    let mut sec = String::new();
    for l in secret.lines() {
      if started {
        if l.starts_with("-----END ") {
          break;
        }
        if l.chars().all(is_base64_char) {
          sec.push_str(l)
        } else if l.starts_with(AES_128_CBC) {
          let iv_: Vec<u8> = FromHex::from_hex(l.split_at(AES_128_CBC.len()).1)?;
          if iv_.len() != 16 {
            return Err(Error::CouldNotReadKey);
          }
          let mut iv = [0; 16];
          iv.clone_from_slice(&iv_);
          format = Some(Format::Pkcs5Encrypted(Encryption::Aes128Cbc(iv)))
        }
      }
      if l == "-----BEGIN OPENSSH PRIVATE KEY-----" {
        started = true;
        format = Some(Format::Openssh);
      } else if l == "-----BEGIN RSA PRIVATE KEY-----" {
        started = true;
        format = Some(Format::Rsa);
      } else if l == "-----BEGIN ENCRYPTED PRIVATE KEY-----" {
        started = true;
        format = Some(Format::Pkcs8Encrypted);
      } else if l == "-----BEGIN PRIVATE KEY-----" {
        started = true;
        format = Some(Format::Pkcs8);
      }
    }
    sec
  };

  // debug!("secret = {:?}", secret);
  let secret = base64::decode_config(&secret, base64::STANDARD)?;
  match format {
    Some(Format::Openssh) => openssh::decode_openssh(&secret, password),
    //    Some(Format::Rsa) => decode_rsa(&secret),
    //    Some(Format::Pkcs5Encrypted(enc)) => decode_pkcs5(&secret, password, enc),
    //    Some(Format::Pkcs8Encrypted) |
    //    Some(Format::Pkcs8) => self::pkcs8::decode_pkcs8(&secret, password),
    _ => Err(Error::CouldNotReadKey),
  }
}

fn is_base64_char(c: char) -> bool {
  (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '/' || c == '+' || c == '='
}
