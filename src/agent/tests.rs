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

struct TestAgent {
  temp_dir: TempDir,
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
      temp_dir,
      file_name,
      agent,
    })
  }

  pub fn add_fixture_key(&self, name: &str) -> Result<()> {
    let cwd = env::current_dir()?;
    Command::new("/usr/bin/ssh-add").env("SSH_AUTH_SOCK", &self.file_name).arg(cwd.join("fixtures").join(name)).output()?;
    Ok(())
  }

  pub fn agent_path(&self) -> &str {
    self.file_name.to_str().unwrap()
  }
}

impl Drop for TestAgent {
  fn drop(&mut self) {
    self.agent.kill().ok();
  }
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
  let signature = client.sign_request(key, b"Bla").unwrap();

  println!("{:?}", signature);

  signature.verify(key, b"Bla").unwrap();
}
