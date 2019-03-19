use crate::agent::client::AgentClient;
use spectral::prelude::*;
use std::env;
use std::os::unix::net::UnixStream;

#[test]
fn test_request_identities() {
  let agent_path = env::var("SSH_AUTH_SOCK").unwrap();
  let socket = UnixStream::connect(agent_path).unwrap();
  let mut client = AgentClient::connect(socket);

  let identities = client.request_identities().unwrap();

  assert_that(&identities).has_length(1);

  let key = &identities.first().unwrap().key;
  let signature = client.sign_request(key, b"Bla").unwrap();

  println!("{:?}", signature);

  signature.verify(key, b"Bla").unwrap();
}
