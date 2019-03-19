const TAG_INTEGER: u8 = 0x2;
const TAG_SEQUENCE: u8 = 0x30;

fn length_length(length: usize) -> u8 {
  let mut i = length;
  let mut num_bytes = 1;
  while i > 255 {
    num_bytes += 1;
    i >>= 8;
  }
  return num_bytes;
}

fn block_length(length: usize) -> usize {
  if length >= 128 {
    let n = length_length(length);
    length + 1 + 1 + n as usize
  } else {
    length + 1 + 1
  }
}

fn encode_tag(target: &mut Vec<u8>, tag: u8, length: usize) {
  target.push(tag);
  if length >= 128 {
    let n = length_length(length);
    target.push(0x80 | n);
    for i in (0..n).rev() {
      target.push((length >> (i * 8)) as u8);
    }
  } else {
    target.push(length as u8);
  }
}

pub fn encode_rsa_public(n: &[u8], e: &[u8]) -> Vec<u8> {
  let n_length = block_length( n.len());
  let e_length = block_length( e.len());
  let mut der = Vec::with_capacity(block_length( e_length + n_length));

  encode_tag(&mut der, TAG_SEQUENCE, e_length + n_length);
  encode_tag(&mut der, TAG_INTEGER, n.len());
  der.extend_from_slice(n);
  encode_tag(&mut der, TAG_INTEGER, e.len());
  der.extend_from_slice(e);

  der
}
