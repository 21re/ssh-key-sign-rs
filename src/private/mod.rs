
mod openssh;
mod bcrypt_pbkdf;
mod blowflish;

#[derive(Debug)]
pub enum KeyPair {
  Rsa
}

#[derive(Debug)]
enum Format {
  Openssh,
}
