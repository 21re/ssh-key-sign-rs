use crate::encoding::{Reader, Writer};
use crate::error::{Error, Result};
use crate::mini_der;
use crate::public::{
  PublicKey, SSH_ECDSA_P256, SSH_ECDSA_P384, SSH_ED25519, SSH_RSA, SSH_RSA_SHA2_256, SSH_RSA_SHA2_512,
};
use ring::signature;

#[derive(Debug, PartialEq, Eq)]
pub enum SignatureHash {
  RsaSha1,
  RsaSha256,
  RsaSha512,
  EcdsaP256,
  EcdsaP384,
  Ed25519,
}

impl SignatureHash {
  pub fn from_name(name: &[u8]) -> Result<SignatureHash> {
    match name {
      SSH_RSA => Ok(SignatureHash::RsaSha1),
      SSH_RSA_SHA2_256 => Ok(SignatureHash::RsaSha256),
      SSH_RSA_SHA2_512 => Ok(SignatureHash::RsaSha512),
      SSH_ECDSA_P256 => Ok(SignatureHash::EcdsaP256),
      SSH_ECDSA_P384 => Ok(SignatureHash::EcdsaP384),
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
  pub fn parse_raw(raw_signature: &[u8]) -> Result<(Signature, &[u8])> {
    let mut reader = Reader::new(raw_signature);

    let algo = reader.read_string()?;
    let hash = SignatureHash::from_name(algo)?;
    let signature = Vec::from(reader.read_string()?);

    Ok((Signature { hash, signature }, reader.remaining()))
  }

  pub fn to_ssh_sig(&self) -> Vec<u8> {
    let mut writer = Writer::new();

    match self.hash {
      SignatureHash::RsaSha1 => writer.write_string(SSH_RSA),
      SignatureHash::RsaSha256 => writer.write_string(SSH_RSA_SHA2_256),
      SignatureHash::RsaSha512 => writer.write_string(SSH_RSA_SHA2_512),
      SignatureHash::EcdsaP256 => writer.write_string(SSH_ECDSA_P256),
      SignatureHash::EcdsaP384 => writer.write_string(SSH_ECDSA_P384),
      SignatureHash::Ed25519 => writer.write_string(SSH_ED25519),
    }

    writer.write_string(&self.signature);

    writer.buffer
  }

  pub fn to_ring_sig(&self) -> Result<Vec<u8>> {
    match self.hash {
      SignatureHash::EcdsaP256 | SignatureHash::EcdsaP384 => {
        let mut reader = Reader::new(&self.signature);
        let r = reader.read_string()?;
        let s = reader.read_string()?;

        Ok(mini_der::encode_ecdsa_sig(r, s))
      }
      _ => Ok(self.signature.clone()),
    }
  }

  pub fn verify(&self, key: &PublicKey, data: &[u8]) -> Result<()> {
    let algorithm: &dyn signature::VerificationAlgorithm = match (&self.hash, key) {
      (SignatureHash::RsaSha256, PublicKey::Rsa { .. }) => &signature::RSA_PKCS1_2048_8192_SHA256,
      (SignatureHash::RsaSha512, PublicKey::Rsa { .. }) => &signature::RSA_PKCS1_2048_8192_SHA512,
      (SignatureHash::EcdsaP256, PublicKey::EcdsaP256(_)) => &signature::ECDSA_P256_SHA256_ASN1,
      (SignatureHash::EcdsaP384, PublicKey::EcdsaP384(_)) => &signature::ECDSA_P384_SHA384_ASN1,
      (SignatureHash::Ed25519, PublicKey::Ed25519(_)) => &signature::ED25519,
      _ => return Err(Error::InvalidSignature),
    };

    let peer_public_key =
        signature::UnparsedPublicKey::new(algorithm, key.to_ring_key());

    let ring_sig = self.to_ring_sig()?;

    if peer_public_key.verify(data,&ring_sig)
    .is_ok()
    {
      Ok(())
    } else {
      Err(Error::SignatureDoesNotMatch)
    }
  }
}
