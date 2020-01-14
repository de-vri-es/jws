//! JWS Compact Serialization implementaton.
//!
//! This module contains types and functions to encode/decode
//! and sign/verify messages encoded with the JWS Compact Serialization Scheme
//! as defined in [RFC 1715 section 7.1](https://tools.ietf.org/html/rfc7515#section-7.1).
//!
//! Most applications should use [`encode_sign`](fn.encode_sign.html) and [`decode_verify`](fn.decode_verify.html).
//! These functions combine encoding and signing or decoding and verifying in a single step.

use std::collections::BTreeMap;

use crate::{
	Error,
	JsonObject,
	JsonValue,
	Result,
	Signer,
	Verifier,
};

/// Encode a message using the JWS Compact Serialization scheme.
///
/// Note that the signer should already have added it's parameters to the header.
/// If added later, they will not be part of the encoded message.
///
/// See [`encode_sign`] for an easier way to make sure the message is encoded with the right header parameters added.
pub fn encode(header: &JsonObject, payload: &[u8]) -> EncodedMessage {
	// Serializing header can't fail since it's already a JSON object.
	let header_json  = serde_json::to_vec(&header).unwrap();

	let output_len = base64_len(header_json.len()) + base64_len(payload.len()) + 1;
	let mut buffer = String::with_capacity(output_len);

	base64::encode_config_buf(&header_json, base64::URL_SAFE_NO_PAD, &mut buffer);
	let header_length = buffer.len();

	buffer.push('.');
	base64::encode_config_buf(&payload, base64::URL_SAFE_NO_PAD, &mut buffer);

	EncodedMessage{data: buffer, header_length}
}

/// Encode and sign the message.
///
/// This function will first use to [`crate::Signer`] to add header parameters to the header,
/// then encode the message and finally sign it.
///
/// Using this function ensures that the header parameters are set correctly before encoding/signing.
pub fn encode_sign(header: JsonObject, payload: &[u8], signer: &impl Signer) -> Result<EncodedSignedMessage> {
	let mut header = header;

	// Let the signer set the headers before encoding the message.
	signer.set_header_params(&mut header);
	let encoded = encode(&header, payload);

	// Sign the encoded message.
	let signature = signer.compute_mac(encoded.header().as_bytes(), encoded.payload().as_bytes())?;

	// Concat the signature to the encoded message.
	let header_length  = encoded.header().len();
	let payload_length = encoded.payload().len();
	let mut data       = encoded.into_data();
	data.reserve(base64_len(signature.len()) + 1);
	data.push('.');
	base64::encode_config_buf(&signature, base64::URL_SAFE_NO_PAD, &mut data);

	Ok(EncodedSignedMessage{data, header_length, payload_length})
}

/// Decode a JWS Compact Serialization message with signature from a byte slice.
///
/// This function is marked unsafe because it does not verify the message signature.
/// You can use [`decode_verify`] as a safe alternative.
pub unsafe fn decode(data: &[u8]) -> Result<(DecodedMessage, Vec<u8>)> {
	split_encoded_parts(data)?.decode()
}

/// Decode and verify a JWS Compact Serialization message.
///
/// Note that if verification fails, you will not have access to the decoded message.
/// If that is required, you may use [`split_encoded_parts`] and decode/verify the message manually.
pub fn decode_verify(data: &[u8], verifier: &impl Verifier) -> Result<DecodedMessage> {
	let parts = split_encoded_parts(data)?;
	let (message, signature) = parts.decode()?;
	verifier.verify(Some(&message.header), None, parts.header, parts.payload, &signature)?;
	Ok(message)
}

/// A compact JWS message with header and payload, but without signature.
///
/// The signature is left off because the signature can only be computed from (and verified for) a serialized message,
/// whereas this struct represents a mostly decoded message (the payload is still raw bytes).
///
/// You can call [`decode_verify`] to decode and verify a message.
/// Alternatively, you can call [`split_encoded_parts`], decode the parts and then use a [`Verifier`] manually.
/// The latter allows you to access the decoded message, even if it's signature is invalid.
#[derive(Clone, Debug, PartialEq)]
pub struct DecodedMessage {
	pub header  : JsonObject,
	pub payload : Vec<u8>,
}

/// An encoded JWS Compact Serialization message without signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedMessage {
	data          : String,
	header_length : usize,
}
/// An encoded JWS Compact Serialization message with signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedSignedMessage {
	data           : String,
	header_length  : usize,
	payload_length : usize,
}

impl DecodedMessage {
	/// Create a new message from a header and a payload.
	pub fn new(header: impl Into<JsonObject>, payload: impl Into<Vec<u8>>) -> Self {
		Self{header: header.into(), payload: payload.into()}
	}

	/// Create a new DecodedMessage by decoding the header and payload of a JWS Compact Serialization message.
	pub fn from_encoded_parts(header: &[u8], payload: &[u8]) -> Result<Self> {
		// Undo base64 encoding of parts.
		let header  = decode_base64_url(header,  "header")?;
		let payload = decode_base64_url(payload, "payload")?;

		// Decode the header as JSON.
		let header: BTreeMap<String, JsonValue> = decode_json(&header,  "header")?;

		// Put the decoded parts back together.
		Ok(Self{header, payload})
	}

	/// Parse the payload as JSON using serde.
	///
	/// The type must implement the [`serde::Deserialize`] trait
	pub fn parse_json<'de, T: serde::de::Deserialize<'de> + 'de>(&'de self) -> std::result::Result<T, serde_json::Error> {
		serde_json::from_slice(&self.payload)
	}

	/// Parse the payload as a [`JsonValue`].
	///
	/// This method avoids the need for type annotations.
	pub fn parse_json_value(&self) -> std::result::Result<JsonValue, serde_json::Error> {
		self.parse_json()
	}

	/// Parse the payload as a [`JsonObject`].
	///
	/// This method avoids the need for type annotations.
	pub fn parse_json_object(&self) -> std::result::Result<JsonObject, serde_json::Error> {
		self.parse_json()
	}
}

impl EncodedMessage {
	/// Get a reference to the raw data.
	pub fn data(&self) -> &str {
		&self.data
	}

	/// Get the raw data, consuming the encoded message.
	pub fn into_data(self) -> String {
		self.data
	}

	/// Get a reference to the raw data as bytes.
	pub fn as_bytes(&self) -> &[u8] {
		self.data().as_bytes()
	}

	/// Get the header part of the encoded message.
	pub fn header(&self) -> &str {
		&self.data[..self.header_length]
	}

	/// Get the payload part of the encoded message.
	pub fn payload(&self) -> &str {
		&self.data[self.header_length + 1..]
	}
}

impl EncodedSignedMessage {
	/// Get a reference to the raw data.
	pub fn data(&self) -> &str {
		&self.data
	}

	/// Get the raw data, consuming the encoded message.
	pub fn into_data(self) -> String {
		self.data
	}

	/// Get a reference to the raw data as bytes.
	pub fn as_bytes(&self) -> &[u8] {
		self.data().as_bytes()
	}

	/// Get the header part of the encoded message.
	pub fn header(&self) -> &str {
		&self.data[..self.header_length]
	}

	/// Get the payload part of the encoded message.
	pub fn payload(&self) -> &str {
		&self.data[self.payload_start()..self.payload_end()]
	}

	/// Get the signature part of the encoded message.
	pub fn signature(&self) -> &str {
		&self.data[self.signature_start()..]
	}

	/// Get the parts of the message as a [`CompactSerializedParts`] struct.
	pub fn parts(&self) -> CompactSerializedParts {
		CompactSerializedParts {
			header:    self.header().as_bytes(),
			payload:   self.payload().as_bytes(),
			signature: self.signature().as_bytes(),
		}
	}

	fn payload_start(&self) -> usize {
		self.header_length + 1
	}

	fn payload_end(&self) -> usize {
		self.payload_start() + self.payload_length
	}

	fn signature_start(&self) -> usize {
		self.payload_end() + 1
	}
}

/// The individual (still encoded) parts of a JWS Compact Serialized message.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CompactSerializedParts<'a> {
	pub header:    &'a [u8],
	pub payload:   &'a [u8],
	pub signature: &'a [u8],
}

impl<'a> CompactSerializedParts<'a> {
	/// Decode the already-split parts of a JWS Compact Serialization message.
	pub fn decode(&self) -> Result<(DecodedMessage, Vec<u8>)> {
		let message   = DecodedMessage::from_encoded_parts(self.header, self.payload)?;
		let signature = decode_base64_url(self.signature, "signature")?;
		Ok((message, signature))
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

/// Compute the length of a base64 encoded string without padding, given the input length.
fn base64_len(input_len: usize) -> usize {
	// Multiply by 4, divide by 3 rounding up.
	(input_len * 4 + 2) / 3
}

/// Decode a base64-url encoded string.
fn decode_base64_url(value: &[u8], field_name: &str) -> Result<Vec<u8>> {
	match base64::decode_config(value, base64::URL_SAFE_NO_PAD) {
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
	use crate::json_object;

	use assert2::assert;

	fn test_split_valid(source: &[u8], header: &[u8], payload: &[u8], signature: &[u8]) {
		let parts = split_encoded_parts(source).unwrap();
		assert!(parts.header == header);
		assert!(parts.payload == payload);
		assert!(parts.signature == signature);

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
		assert!(let Err(Error { kind: Error::InvalidMessage, .. }) = split_encoded_parts(b"aapnootmies"));
		assert!(let Err(Error { kind: Error::InvalidMessage, .. }) = split_encoded_parts(b"aap.nootmies"));
		assert!(let Err(Error { kind: Error::InvalidMessage, .. }) = split_encoded_parts(b"aap.noot.mies."));
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
	const RFC7515_A1_ENCODED_MANGLED : &[u8] = b"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqc2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
	const RFC7515_A1_SIGNATURE       : &[u8] = &[116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121];

	#[test]
	fn test_decode() {
		let (message, signature) = split_encoded_parts(RFC7515_A1_ENCODED).unwrap().decode().unwrap();

		assert!(&message.header == &json_object!{
			"alg": "HS256",
			"typ": "JWT"
		});

		assert!(let Ok(_) = message.parse_json_object());
		assert!(message.parse_json_object().ok() == Some(json_object!{
			"iss": "joe",
			"exp": 1300819380,
			"http://example.com/is_root": true,
		}));

		assert!(&signature[..] == RFC7515_A1_SIGNATURE);
	}

	#[test]
	fn test_decode_mangled() {
		let (message, signature) = split_encoded_parts(RFC7515_A1_ENCODED_MANGLED).unwrap().decode().unwrap();

		assert!(&message.header == &json_object!{
			"alg": "HS256",
			"typ": "JWT",
		});

		assert!(message.parse_json_object().unwrap() == json_object!{
			"iss": "jse",
			"exp": 1300819380,
			"http://example.com/is_root": true,
		});

		assert!(&signature[..] == RFC7515_A1_SIGNATURE);
	}

	#[test]
	fn test_encode() {
		let header  = json_object!{"typ": "JWT", "alg": "HS256"};
		let encoded = encode(&header, b"foo");
		assert!(encoded.header() == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
		assert!(encoded.payload() == "Zm9v");
		assert!(encoded.data() == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.Zm9v")
	}
}
