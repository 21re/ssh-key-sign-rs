use crate::agent::client::AgentClient;
use spectral::prelude::*;
use std::env;
use std::os::unix::net::UnixStream;
use crate::error::{Result, Error};
use std::path::PathBuf;
use std::process::{Command, Child, Stdio};
use std::time;
use std::thread;
use tempfile::TempDir;
use std::os::unix::fs::PermissionsExt;
use std::fs;
use rand::RngCore;
use crate::public::PublicKey;
use std::fs::read_to_string;

struct TestAgent {
  _temp_dir: TempDir,
  pub file_name: PathBuf,
  agent: Child,
}

impl TestAgent {
  pub fn spawn() -> Result<TestAgent> {
    let temp_dir = TempDir::new()?;
    let file_name = temp_dir.path().join("ssh-agent.sock");

    let mut agent = Command::new("/usr/bin/ssh-agent").arg("-a").arg(&file_name).arg("-d").stdout(Stdio::null()).stderr(Stdio::null()).spawn()?;
    let start = time::Instant::now();

    while !file_name.exists() {
      if start.elapsed() > time::Duration::from_secs(5) {
        return Err(Error::IO("test agent timed out".to_string()));
      }
      thread::sleep(time::Duration::from_millis(100));
    }

    Ok(TestAgent {
      _temp_dir: temp_dir,
      file_name,
      agent,
    })
  }

  pub fn add_fixture_key(&self, name: &str) -> Result<()> {
    let cwd = env::current_dir()?;
    let path = cwd.join("fixtures").join(name);
    let mut perms = fs::metadata(&path)?.permissions();
    perms.set_mode(0o400);
    fs::set_permissions(&path, perms)?;
    Command::new("/usr/bin/ssh-add").env("SSH_AUTH_SOCK", &self.file_name).arg(path).output()?;
    Ok(())
  }
}

impl Drop for TestAgent {
  fn drop(&mut self) {
    self.agent.kill().ok();
  }
}

fn read_pub_key(name: &str) -> Result<PublicKey> {
  let cwd = env::current_dir()?;
  let path = cwd.join("fixtures").join(name);
  let line = fs::read_to_string(path)?;

  PublicKey::parse_pub(&line)
}

#[test]
fn test_request_identities() {
  let test_agent = TestAgent::spawn().unwrap();
  let socket = UnixStream::connect(&test_agent.file_name).unwrap();
  let mut client = AgentClient::connect(socket);

  test_agent.add_fixture_key("unencrypted_rsa").unwrap();
  test_agent.add_fixture_key("unencrypted_ecdsa").unwrap();
  test_agent.add_fixture_key("unencrypted_ed25519").unwrap();

  let mut identities = client.request_identities().unwrap();

  assert_that(&identities).has_length(3);

  client.remove_all_identities().unwrap();

  identities = client.request_identities().unwrap();

  assert_that(&identities).has_length(0);
}

#[test]
fn test_rsa_signature() {
  let test_agent = TestAgent::spawn().unwrap();
  let socket = UnixStream::connect(&test_agent.file_name).unwrap();
  let mut client = AgentClient::connect(socket);

  test_agent.add_fixture_key("unencrypted_rsa").unwrap();

  let identities = client.request_identities().unwrap();

  assert_that(&identities).has_length(1);

  let key = &identities.first().unwrap().key;
  let ref_key = read_pub_key("unencrypted_rsa.pub").unwrap();
  let mut rng = rand::thread_rng();

  for _ in 0..100 {
    let mut data = [0u8; 64];
    rng.fill_bytes(&mut data);

    let signature = client.sign_request(key, &data).unwrap();

    signature.verify(key, &data).unwrap();
    signature.verify(&ref_key, &data).unwrap();
  }
}

#[test]
fn test_ed25519_signature() {
  let test_agent = TestAgent::spawn().unwrap();
  let socket = UnixStream::connect(&test_agent.file_name).unwrap();
  let mut client = AgentClient::connect(socket);

  test_agent.add_fixture_key("unencrypted_ed25519").unwrap();

  let identities = client.request_identities().unwrap();

  assert_that(&identities).has_length(1);

  let key = &identities.first().unwrap().key;
  let ref_key = read_pub_key("unencrypted_ed25519.pub").unwrap();
  let mut rng = rand::thread_rng();

  for _ in 0..100 {
    let mut data = [0u8; 64];
    rng.fill_bytes(&mut data);

    let signature = client.sign_request(key, &data).unwrap();

    signature.verify(key, &data).unwrap();
    signature.verify(&ref_key, &data).unwrap();
  }
}

#[test]
fn test_ecdsa_signature() {
  let test_agent = TestAgent::spawn().unwrap();
  let socket = UnixStream::connect(&test_agent.file_name).unwrap();
  let mut client = AgentClient::connect(socket);

  test_agent.add_fixture_key("unencrypted_ecdsa").unwrap();

  let identities = client.request_identities().unwrap();

  assert_that(&identities).has_length(1);

  let key = &identities.first().unwrap().key;
  let ref_key = read_pub_key("unencrypted_ecdsa.pub").unwrap();
  let mut rng = rand::thread_rng();

  for _ in 0..100 {
    let mut data = [0u8; 64];
    rng.fill_bytes(&mut data);

    let signature = client.sign_request(key, &data).unwrap();

    signature.verify(key, &data).unwrap();
    signature.verify(&ref_key, &data).unwrap();
  }
}
