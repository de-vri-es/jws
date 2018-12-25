//! This library provides JSON Web Signature encoding, decoding, signing and verification.
//!
//! Currently, encoding and decoding is available only for the JWS Compact Serialization scheme in the
//! [`compact`] module.
//!
//! Signing and verifying is done through the [`Signer`] and [`Verifier`] traits,
//! for which some implementations based on `rust-crypto` are available in the `[crypto]` module.

pub mod compact;
pub mod crypto;
pub mod error;
pub mod header;

pub use serde_json::Value as JsonValue;
pub use crate::error::{Error, Result};
pub use crate::header::{AvailableHeaders, HeaderMap, Headers, HeadersMut};

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
		headers          : Headers,
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

	/// Sign a message.
	///
	/// This is a shorthand for calling [`set_header_params`](#method.set_header_params) followed by [`compute_mac`](#compute_mac).
	fn sign(&mut self, headers: HeadersMut, encoded_protected_header: &[u8], encoded_payload: &[u8]) -> Result<Vec<u8>> {
		self.set_header_params(headers)?;
		self.compute_mac(encoded_protected_header, encoded_payload)
	}
}
