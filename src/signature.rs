use crate::encoding::Reader;
use crate::error::{Error, Result};
use crate::mini_der;
use crate::public::{PublicKey, SSH_ECDSA_P256, SSH_ED25519, SSH_RSA, SSH_RSA_SHA2_256, SSH_RSA_SHA2_512};
use ring::signature;
use untrusted::Input;

#[derive(Debug, PartialEq, Eq)]
pub enum SignatureHash {
  RsaSha1,
  RsaSha256,
  RsaSha512,
  EcdsaP256,
  Ed25519,
}

impl SignatureHash {
  pub fn from_name(name: &[u8]) -> Result<SignatureHash> {
    match name {
      SSH_RSA => Ok(SignatureHash::RsaSha1),
      SSH_RSA_SHA2_256 => Ok(SignatureHash::RsaSha256),
      SSH_RSA_SHA2_512 => Ok(SignatureHash::RsaSha512),
      SSH_ECDSA_P256 => Ok(SignatureHash::EcdsaP256),
      SSH_ED25519 => Ok(SignatureHash::Ed25519),
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

  pub fn to_ring_sig(&self) -> Result<Vec<u8>> {
    match self.hash {
      SignatureHash::EcdsaP256 => {
        let mut reader = Reader::new(&self.signature);
        let r = reader.read_string()?;
        let s = reader.read_string()?;

        Ok(mini_der::encode_ecdsa_sig(r, s))
      }
      _ => Ok(self.signature.clone()),
    }
  }

  pub fn verify(&self, key: &PublicKey, data: &[u8]) -> Result<()> {
    let algorithm: &signature::VerificationAlgorithm = match (&self.hash, key) {
      (SignatureHash::RsaSha1, PublicKey::Rsa { .. }) => &signature::RSA_PKCS1_2048_8192_SHA1,
      (SignatureHash::RsaSha256, PublicKey::Rsa { .. }) => &signature::RSA_PKCS1_2048_8192_SHA256,
      (SignatureHash::RsaSha512, PublicKey::Rsa { .. }) => &signature::RSA_PKCS1_2048_8192_SHA512,
      (SignatureHash::EcdsaP256, PublicKey::EcdsaP256(_)) => &signature::ECDSA_P256_SHA256_ASN1,
      (SignatureHash::Ed25519, PublicKey::Ed25519(_)) => &signature::ED25519,
      _ => return Err(Error::InvalidSignature),
    };
    let ring_sig = self.to_ring_sig()?;
    if signature::verify(
      algorithm,
      Input::from(&key.to_ring_key()),
      Input::from(data),
      Input::from(&ring_sig),
    )
    .is_ok()
    {
      Ok(())
    } else {
      Err(Error::SignatureDoesNotMatch)
    }
  }
}
