//! This library provides JSON Web Signature encoding, decoding, signing and verification
//! as described in [RFC 7515](https://tools.ietf.org/html/rfc7515).
//!
//! Currently, encoding and decoding is available only for the JWS Compact Serialization scheme in the
//! [`compact`] module.
//!
//! Signing and verifying is done through the [`Signer`] and [`Verifier`] traits.
//! The [`hmac`] module contains implementations for these traits that support the HMAC-SHA2 family of algorithms.
//!
//! # Example:
//! ```
//! use jws::{JsonObject, JsonValue};
//! use jws::compact::{decode_verify, encode_sign};
//! use jws::hmac::{Hs512Signer, HmacVerifier};
//!
//! fn encode_decode() -> jws::Result<()> {
//!   // Add custom header parameters.
//!   let mut header = JsonObject::new();
//!   header.insert(String::from("typ"), JsonValue::from("text/plain"));
//!
//!   // Encode and sign the message.
//!   let encoded = encode_sign(header, b"payload", Hs512Signer::new(b"secretkey"))?;
//!
//!   // Decode and verify the message.
//!   let decoded = decode_verify(encoded.data().as_bytes(), HmacVerifier::new(b"secretkey"))?;
//!
//!   assert_eq!(decoded.payload, b"payload");
//!   assert_eq!(decoded.header.get("typ").and_then(|x| x.as_str()), Some("text/plain"));
//!
//!   Ok(())
//! }
//!
//! ```
//! To sign and verify a message

pub mod compact;
pub mod hmac;
mod error;
pub mod header;

pub use crate::error::{Error, ErrorKind, Result};
pub use crate::header::{AvailableHeaders, HeadersRef, HeadersMut};

/// Re-exported [`serde_json::Value`].
pub type JsonValue  = serde_json::Value;

/// A JSON object.
pub type JsonObject = std::collections::BTreeMap<String, JsonValue>;

/// A verifier for JWS messages.
pub trait Verifier {
	/// Verify the signature of a JWS message.
	///
	/// This function needs access to the decoded message headers in order to determine which MAC algorithm to use.
	/// It also needs access to the raw encoded parts to verify the MAC.
	///
	/// If the signature is invalid, the function should return a `[error::InvalidSignature]` error.
	/// It may also report any of the other supported error variants.
	///
	/// # Args:
	///   - headers:         The available message headers: the protected and/or unpprotected header.
	///   - encoded_header:  The raw encoded protected header, needed to compute the MAC. If there is no protected header, this is an empty slice.
	///   - encoded_payload: The raw encoded payload, needed to compute the MAC.
	///   - signature:       The signature associated with the message, should be tested against the computed MAC.
	fn verify(
		&mut self,
		headers          : HeadersRef,
		encoded_header   : &[u8],
		encoded_payload  : &[u8],
		signature        : &[u8],
	) -> Result<()>;
}

/// A signer for JWS messages.
pub trait Signer {
	/// Set the header parameters to indicate how the message should be verified.
	///
	/// This is the first step in the signing process, since the encoded headers will end up in the signature if they are added to the protected header.
	fn set_header_params(&mut self, headers: HeadersMut) -> Result<()>;

	/// Compute the Message Authentication Code for the encoded protected header and encoded payload.
	///
	/// The returned MAC must be plain bytes, not hex or base64 encoded.
	fn compute_mac(&mut self, encoded_protected_header: &[u8], encoded_payload: &[u8]) -> Result<Vec<u8>>;
}
