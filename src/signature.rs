use crate::encoding::Reader;
use crate::error::{Error, Result};
use crate::public::{PublicKey, SSH_RSA, SSH_RSA_SHA2_256, SSH_RSA_SHA2_512};
use ring::signature;
use untrusted::Input;

#[derive(Debug)]
pub enum SignatureHash {
  RsaSha1,
  RsaSha256,
  RsaSha512,
}

impl SignatureHash {
  pub fn from_name(name: &[u8]) -> Result<SignatureHash> {
    match name {
      SSH_RSA => Ok(SignatureHash::RsaSha1),
      SSH_RSA_SHA2_256 => Ok(SignatureHash::RsaSha256),
      SSH_RSA_SHA2_512 => Ok(SignatureHash::RsaSha512),
      _ => Err(Error::InvalidSignature),
    }
  }
}

#[derive(Debug)]
pub struct Signature {
  pub hash: SignatureHash,
  pub signature: Vec<u8>,
}

impl Signature {
  pub fn parse_raw(raw_signature: &[u8]) -> Result<Signature> {
    let mut reader = Reader::new(raw_signature);

    let algo = reader.read_string()?;
    let hash = SignatureHash::from_name(algo)?;
    let signature = Vec::from(reader.read_string()?);

    Ok(Signature { hash, signature })
  }

  pub fn verify(&self, key: &PublicKey, data: &[u8]) -> Result<()> {
    let algorithm = match (&self.hash, key) {
      (SignatureHash::RsaSha1, k @ PublicKey::Rsa { .. }) => &signature::RSA_PKCS1_2048_8192_SHA1,
      (SignatureHash::RsaSha256, k @ PublicKey::Rsa { .. }) => &signature::RSA_PKCS1_2048_8192_SHA256,
      (SignatureHash::RsaSha512, k @ PublicKey::Rsa { .. }) => &signature::RSA_PKCS1_2048_8192_SHA512,
      _ => return Err(Error::InvalidSignature),
    };
    if signature::verify(
      algorithm,
      Input::from(&key.to_ring_key()),
      Input::from(data),
      Input::from(&self.signature),
    )
    .is_ok()
    {
      Ok(())
    } else {
      Err(Error::SignatureDoesNotMatch)
    }
  }
}
