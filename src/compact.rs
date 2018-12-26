//! JWS Compact Serialization implementaton.

use std::collections::BTreeMap;

use crate::{
	AvailableHeaders,
	Error,
	HeaderMap,
	JsonValue,
	Result,
	Verifier,
};

/// A compact JWS message with header and payload, but without signature.
///
/// The signature is left off because the signature can only be computed from (and verified for) a serialized message,
/// whereas this struct represents a mostly decoded message (the payload is still raw bytes).
///
/// You can call [`decode_verify`] to decode and verify a message.
/// Alternatively, you can call [`split_encoded_parts`], decode the parts and then use a [`Verifier`] manually.
/// The latter allows you to access the decoded message, even if it's signature is invalid.
pub struct Message {
	pub header  : HeaderMap,
	pub payload : Vec<u8>,
}

impl Message {
	/// Create a new Message by decoding the individual parts of a JWS Compact Serialization message.
	pub fn decode_parts(header: &[u8], payload: &[u8]) -> Result<Self> {
		// Undo base64 encoding of parts.
		let header  = decode_base64_url(header,  "header")?;
		let payload = decode_base64_url(payload, "payload")?;

		// Decode the header as JSON dictionary.
		let header: BTreeMap<String, JsonValue> = decode_json(&header, "header")?;

		// Put the parts back together.
		Ok(Self{header, payload})
	}
}

/// Split the parts of a JWS Compact Serialization message.
///
/// A JWS Compact Serialization message contains three base64-url encoded parts separated by period '.' characters:
///   - header
///   - payload
///   - signature
///
/// This function splits a byte slice into these three parts.
pub fn split_encoded_parts(data: &[u8]) -> Result<CompactSerializedParts> {
	// Split data into parts.
	let mut parts = data.splitn(4, |&c| c == b'.');

	let header    = parts.next().ok_or_else(|| Error::invalid_message("encoded message does not contain a header"))?;
	let payload   = parts.next().ok_or_else(|| Error::invalid_message("encoded message does not contain a payload"))?;
	let signature = parts.next().ok_or_else(|| Error::invalid_message("encoded message does not contain a signature"))?;

	// Make sure there are no additional message parts in the input.
	if parts.next().is_some() {
		return Err(Error::invalid_message("encoded message contains an additional field after the signature"));
	}

	Ok(CompactSerializedParts{header, payload, signature})
}

/// Decode and verify a JWS Compact Serialization message.
pub fn decode_verify(data: &[u8], mut verifier: impl Verifier) -> Result<Message> {
	let parts = split_encoded_parts(data)?;
	let (message, signature) = parts.decode()?;
	verifier.verify(AvailableHeaders::ProtectedOnly(&message.header), parts.header, parts.payload, &signature)?;
	Ok(message)
}

/// The individual (still encoded) parts of a JWS Compact Serialized message.
pub struct CompactSerializedParts<'a> {
	pub header:    &'a [u8],
	pub payload:   &'a [u8],
	pub signature: &'a [u8],
}

impl<'a> CompactSerializedParts<'a> {
	/// Decode a JWS Compact Serialization message with signature from a byte slice.
	///
	/// A JWS Compact message consists of a base64-url encoded header and payload and signature,
	/// separated by period '.' characters.
	pub fn decode(&self) -> Result<(Message, Vec<u8>)> {
		let message   = Message::decode_parts(self.header, self.payload)?;
		let signature = decode_base64_url(self.signature, "signature")?;
		Ok((message, signature))
	}
}

/// Decode a base64-url encoded string.
fn decode_base64_url(value: &[u8], field_name: &str) -> Result<Vec<u8>> {
	match base64::decode_config(value,  base64::URL_SAFE_NO_PAD) {
		Ok(x)  => Ok(x),
		Err(_) => Err(Error::invalid_message(format!("invalid base64 in {}", field_name)))
	}
}

/// Decode a JSON string.
fn decode_json<'a, T: serde::Deserialize<'a>>(value: &'a [u8], field_name: &str) -> Result<T> {
	match serde_json::from_slice(value) {
		Ok(x)  => Ok(x),
		Err(_) => Err(Error::invalid_message(format!("invalid JSON in {}", field_name)))
	}
}

#[cfg(test)]
mod test {
	use super::*;

	fn test_split_valid(source: &[u8], header: &[u8], payload: &[u8], signature: &[u8]) {
		let parts = split_encoded_parts(source).unwrap();
		assert_eq!(parts.header,    header);
		assert_eq!(parts.payload,   payload);
		assert_eq!(parts.signature, signature);

	}

	#[test]
	fn test_split_encoded_parts() {
		// Test splitting some valid sequences.
		test_split_valid(b"..",            b"",    b"",     b"");
		test_split_valid(b"..mies",        b"",    b"",     b"mies");
		test_split_valid(b".noot.",        b"",    b"noot", b"");
		test_split_valid(b".noot.mies",    b"",    b"noot", b"mies");
		test_split_valid(b"aap..",         b"aap", b"",     b"");
		test_split_valid(b"aap..mies",     b"aap", b"",     b"mies");
		test_split_valid(b"aap.noot.",     b"aap", b"noot", b"");
		test_split_valid(b"aap.noot.mies", b"aap", b"noot", b"mies");

		// Test splitting some invalid sequences.
		assert_eq!(split_encoded_parts(b"aapnootmies").err().unwrap().kind(), Error::InvalidMessage);
		assert_eq!(split_encoded_parts(b"aap.nootmies").err().unwrap().kind(), Error::InvalidMessage);
		assert_eq!(split_encoded_parts(b"aap.noot.mies.").err().unwrap().kind(), Error::InvalidMessage);
	}

	// Example taken from RFC 7515 appendix A.1
	// https://tools.ietf.org/html/rfc7515#appendix-A.1
	//
	// Header:
	//   {"typ":"JWT",
	//    "alg":"HS256"}
	//
	// Payload:
	//  {"iss":"joe",
	//   "exp":1300819380,
	//   "http://example.com/is_root":true}
	//
	//  Key: AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow
	//
	//  Signature: dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk

	const RFC7515_A1_ENCODED         : &[u8] = b"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
	const RFC7515_A1_ENCODED_MANGLED : &[u8] = b"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTlzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
	const RFC7515_A1_PAYLOAD         : &[u8] = b"{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";
	const RFC7515_A1_PAYLOAD_MANGLED : &[u8] = b"{\"iss\":\"joe\",\r\n \"exp\":1300819s80,\r\n \"http://example.com/is_root\":true}";
	const RFC7515_A1_SIGNATURE       : &[u8] = &[116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121];

	#[test]
	fn test_decode() {
		let (message, signature) = split_encoded_parts(RFC7515_A1_ENCODED).unwrap().decode().unwrap();

		// Check that the header contains exactly the two values we expect.
		assert_eq!(message.header.get("alg").unwrap(), "HS256");
		assert_eq!(message.header.get("typ").unwrap(), "JWT");
		assert_eq!(message.header.len(), 2);

		assert_eq!(&message.payload[..], RFC7515_A1_PAYLOAD);
		assert_eq!(&signature[..], RFC7515_A1_SIGNATURE);
	}

	#[test]
	fn test_decode_mangled() {
		let (message, signature) = split_encoded_parts(RFC7515_A1_ENCODED_MANGLED).unwrap().decode().unwrap();

		// Check that the header contains exactly the two values we expect.
		assert_eq!(message.header.get("alg").unwrap(), "HS256");
		assert_eq!(message.header.get("typ").unwrap(), "JWT");
		assert_eq!(message.header.len(), 2);

		assert_eq!(&message.payload[..], RFC7515_A1_PAYLOAD_MANGLED);
		assert_eq!(&signature[..], RFC7515_A1_SIGNATURE);
	}
}
