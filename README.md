[![Documentation](https://docs.rs/jws/badge.svg)](https://docs.rs/jws)
[![crates.io](https://img.shields.io/crates/v/jws.svg)](https://crates.io/crates/jws)
[![tests](https://github.com/de-vri-es/jws/actions/workflows/rust.yml/badge.svg)](https://github.com/de-vri-es/jws/actions/workflows/rust.yml)

# jws

This library provides JSON Web Signature encoding, decoding, signing and verification
as described in [RFC 7515](https://tools.ietf.org/html/rfc7515).

Currently, encoding and decoding is available only for the JWS Compact Serialization scheme in the
[`compact`] module.

Signing and verifying is done through the [`Signer`] and [`Verifier`] traits.
The [`hmac`] module contains implementations for these traits that support the HMAC-SHA2 family of algorithms.

## Example:
```rust
use jws::{JsonObject, JsonValue};
use jws::compact::{decode_verify, encode_sign};
use jws::hmac::{Hs512Signer, HmacVerifier};

fn encode_decode() -> jws::Result<()> {
  // Add custom header parameters.
  let mut header = JsonObject::new();
  header.insert(String::from("typ"), JsonValue::from("text/plain"));

  // Encode and sign the message.
  let encoded = encode_sign(header, b"payload", &Hs512Signer::new(b"secretkey"))?;

  // Decode and verify the message.
  let decoded = decode_verify(encoded.data().as_bytes(), &HmacVerifier::new(b"secretkey"))?;

  assert_eq!(decoded.payload, b"payload");
  assert_eq!(decoded.header.get("typ").and_then(|x| x.as_str()), Some("text/plain"));

  Ok(())
}

```

[`compact`]: https://docs.rs/jws/latest/jws/compact/index.html
[`Signer`]: https://docs.rs/jws/latest/jws/trait.Signer.html
[`Verifier`]: https://docs.rs/jws/latest/jws/trait.Verifier.html
[`hmac`]: https://docs.rs/jws/latest/jws/hmac/index.html
