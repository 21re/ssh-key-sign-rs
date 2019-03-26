# ssh-key-sign-rs

A simplified library for handling ssh keys and signatures.

This library takes a lot of ideas from the https://crates.io/crates/thrussh-keys package, with some differences:
* The interaction with the ssh-agent are blocking ... because it is just simpler and I do not see any usecase where non-blocking would be reasonable
* Signature verification is done with `ring`, i.e. there is no dependency to `libsodium`. `openssl` is only required if it is necessary to ready private key files
* ECDSA-256 and EDDSA-384 are supported (even though ssh recomends not to use those)

