use crate::encoding::Reader;
use crate::error::{Error, Result};
use crate::private::{bcrypt_pbkdf, KeyPair};
use crate::public::SSH_ED25519;
use openssl::symm::{Cipher, Crypter, Mode};

const MAGIC: &[u8] = b"openssh-key-v1\0";

pub fn decode_openssh(secret: &[u8], password: Option<&[u8]>) -> Result<KeyPair> {
  if &secret[0..15] != MAGIC {
    return Err(Error::CouldNotReadKey);
  }
  let mut reader = Reader::new(&secret[15..]);
  let ciphername = reader.read_string()?;
  let kdfname = reader.read_string()?;
  let kdfoptions = reader.read_string()?;
  let nkeys = reader.read_u32()?;

  // Read all public keys
  for _ in 0..nkeys {
    reader.read_string()?;
  }

  // Read all secret keys
  let secret_ = reader.read_string()?;
  let secret = decrypt_secret_key(ciphername, kdfname, kdfoptions, password, secret_)?;
  reader = Reader::new(&secret);
  let _check0 = reader.read_u32()?;
  let _check1 = reader.read_u32()?;
  for _ in 0..nkeys {
    let key_type = reader.read_string()?;
    let pubkey = Vec::from(reader.read_string()?);
    let seckey = Vec::from(reader.read_string()?);
    let _comment = reader.read_string()?;

    if key_type == SSH_ED25519 {
      assert_eq!(pubkey, &seckey[32..]);
      return Ok(KeyPair::Ed25519 { pubkey, seckey });
    } else {
      return Err(Error::CouldNotReadKey);
    }
  }
  Err(Error::CouldNotReadKey)
}

fn decrypt_secret_key(
  ciphername: &[u8],
  kdfname: &[u8],
  kdfoptions: &[u8],
  password: Option<&[u8]>,
  secret_key: &[u8],
) -> Result<Vec<u8>> {
  if kdfname == b"none" {
    if password.is_none() {
      Ok(secret_key.to_vec())
    } else {
      Err(Error::CouldNotReadKey)
    }
  } else if let Some(password) = password {
    let mut key = Vec::new();
    let cipher = match ciphername {
      b"aes128-cbc" => {
        key.extend_from_slice(&[0u8; 16 + 16]);
        Cipher::aes_128_cbc()
      }
      b"aes128-ctr" => {
        key.extend_from_slice(&[0u8; 16 + 16]);
        Cipher::aes_128_ctr()
      }
      b"aes256-cbc" => {
        key.extend_from_slice(&[0u8; 16 + 32]);
        Cipher::aes_256_cbc()
      }
      b"aes256-ctr" => {
        key.extend_from_slice(&[0u8; 16 + 32]);
        Cipher::aes_256_ctr()
      }
      _ => return Err(Error::CouldNotReadKey),
    };

    match kdfname {
      b"bcrypt" => {
        let mut kdfopts = Reader::new(kdfoptions);
        let salt = kdfopts.read_string()?;
        let rounds = kdfopts.read_u32()?;
        bcrypt_pbkdf::bcrypt_pbkdf(password, salt, rounds, &mut key);
      }
      _kdfname => {
        return Err(Error::CouldNotReadKey);
      }
    };
    let iv = &key[32..];
    let key = &key[..32];
    let mut c = Crypter::new(cipher, Mode::Decrypt, &key, Some(&iv))?;
    c.pad(false);
    let mut dec = vec![0; secret_key.len() + 32];
    let n = c.update(&secret_key, &mut dec)?;
    let n = n + c.finalize(&mut dec[n..])?;
    dec.truncate(n);
    Ok(dec)
  } else {
    Err(Error::KeyIsEncrypted)
  }
}
