# kmip

From [Wikipedia](https://en.wikipedia.org/wiki/Key_Management_Interoperability_Protocol_(KMIP)):
> The Key Management Interoperability Protocol (KMIP) is an extensible communication protocol that defines message formats for the manipulation of cryptographic keys on a key management server. This facilitates data encryption by simplifying encryption key management.

`kmip` is a `#![no_std]` crate that provides the ability to encode and decode KMIP messages. Due to incredibly wide scope of KMIP, only a subset of capabilities defined in the v1.3 spec are supported at this time.

KMIP spec: <https://docs.oasis-open.org/kmip/spec/v1.3/kmip-spec-v1.3.html>

## Usage

```rust
use kmip::{self, ttlv::{Ttlv, parse_ttlv_len}};

let key_name: &str = "test_key_name";
let creds: Option<(&str, &str)> = Some(("username", "password"));
let kmip_max_buffer_len: usize = 1024;

// Encode locate request to buffer
let buf = &mut [0u8; kmip_max_buffer_len];
let request_len = kmip::request(creds, kmip::locate(key_name)).encode(buf)?;

// Send/recieve over tls stream
let tls = unimplemented!();
tls.flush()?;
tls.write(&buf[..request_len])?;
tls.read(&mut buf[..8])?;
let response_len = parse_ttlv_len(&buf[4..8]) + 8;
tls.read(&mut buf[8..response_len])?;

// Decode locate response from buffer
let (ttlv_response, parsed_len) = Ttlv::decode(&buf[..response_len])?;
assert_eq!(response_len, parsed_len);
// Parse response and collect UUID
let uuid: &str = kmip::collect_uuid(kmip::collect_response_payload(&ttlv_response)?)?;
```

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
