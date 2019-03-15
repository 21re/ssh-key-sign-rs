use std::fmt;

#[derive(Debug)]
pub enum Error {
  CouldNotReadKey,
  InvalidKeyLength,
  BufferTooShort,
  RequestFailure,
  Base64(String),
  IO(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      Error::CouldNotReadKey => write!(f, "could not read key"),
      Error::InvalidKeyLength => write!(f, "invalid key length"),
      Error::BufferTooShort => write!(f, "buffer too short"),
      Error::RequestFailure => write!(f, "request failure"),
      Error::Base64(msg) => write!(f, "invalid base64: {}", msg),
      Error::IO(msg) => write!(f, "I/O error: {}", msg),
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