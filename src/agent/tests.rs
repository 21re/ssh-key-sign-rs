use crate::agent::client::AgentClient;
use std::env;
use std::os::unix::net::UnixStream;

#[test]
fn test_request_identities() {
  let agent_path = env::var("SSH_AUTH_SOCK").unwrap();
  let socket = UnixStream::connect(agent_path).unwrap();
  let mut client = AgentClient::connect(socket);

  let identities = client.request_identities().unwrap();
}
