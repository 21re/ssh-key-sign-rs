use std::fmt;

#[derive(Debug)]
pub enum Error {
  CouldNotReadKey,
  InvalidKeyLength,
  InvalidSignature,
  SignatureDoesNotMatch,
  KeyIsEncrypted,
  BufferTooShort,
  RequestFailure,
  Base64(String),
  IO(String),
  OpenSsl(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      Error::CouldNotReadKey => write!(f, "could not read key"),
      Error::InvalidKeyLength => write!(f, "invalid key length"),
      Error::InvalidSignature => write!(f, "invalid signature"),
      Error::SignatureDoesNotMatch => write!(f, "signature does not match"),
      Error::KeyIsEncrypted => write!(f, "key is encrypted"),
      Error::BufferTooShort => write!(f, "buffer too short"),
      Error::RequestFailure => write!(f, "request failure"),
      Error::Base64(msg) => write!(f, "invalid base64: {}", msg),
      Error::IO(msg) => write!(f, "I/O error: {}", msg),
      Error::OpenSsl(msg) => write!(f, "I/O error: {}", msg),
    }
  }
}

impl From<base64::DecodeError> for Error {
  fn from(err: base64::DecodeError) -> Self {
    Error::Base64(format!("{}", err))
  }
}

impl From<std::io::Error> for Error {
  fn from(err: std::io::Error) -> Self {
    Error::IO(format!("{}", err))
  }
}

impl From<std::str::Utf8Error> for Error {
  fn from(err: std::str::Utf8Error) -> Self {
    Error::IO(format!("{}", err))
  }
}

#[cfg(feature = "with-private")]
impl From<openssl::error::ErrorStack> for Error {
  fn from(err: openssl::error::ErrorStack) -> Self {
    Error::OpenSsl(format!("{}", err))
  }
}

#[cfg(feature = "with-private")]
impl From<hex::FromHexError> for Error {
  fn from(err: hex::FromHexError) -> Self {
    Error::IO(format!("{}", err))
  }
}
