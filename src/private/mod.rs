mod bcrypt_pbkdf;
mod blowflish;
mod openssh;

#[derive(Debug)]
pub enum KeyPair {
  Rsa,
}

#[derive(Debug)]
enum Format {
  Openssh,
}
