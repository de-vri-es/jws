//! [`Verifier`] and [`Signer`] implementations using rust-crypto.

use crypto::digest::Digest;
use crypto::mac::{Mac, MacResult};
use crypto::hmac::{Hmac};
use crypto::sha2;

use crate::{Error, Headers, HeadersMut, Result, Signer, Verifier};

pub struct HmacVerifier{
	key: Vec<u8>,
}

pub struct MacSigner<M>(pub M);

/// Create a HMAC MacSigner for a given digest implementation.
fn signer_hmac<D: Digest>(digest: D, key: &[u8]) -> MacSigner<Hmac<D>> {
	MacSigner(Hmac::new(digest, key.into()))
}

/// Create a HS256 signer.
pub fn signer_hs256(key: &[u8]) -> MacSigner<Hmac<sha2::Sha256>> {
	signer_hmac(sha2::Sha256::new(), key)
}

/// Create a HS384 signer.
pub fn signer_hs384(key: &[u8]) -> MacSigner<Hmac<sha2::Sha384>> {
	signer_hmac(sha2::Sha384::new(), key)
}

/// Create a HS512 signer.
pub fn signer_hs512(key: &[u8]) -> MacSigner<Hmac<sha2::Sha512>> {
	signer_hmac(sha2::Sha512::new(), key)
}

impl HmacVerifier {
	pub fn new<K>(key: K) -> Self where
		Vec<u8>: From<K>,
	{
		Self{key: key.into()}
	}
}

impl Verifier for HmacVerifier {
	/// Verify the signature of a JWS Compact Serialization message.
	///
	/// This function needs access to the decoded message headers in order to determine which MAC algorithm to use.
	/// It also needs access to the raw encoded parts to verify the MAC.
	fn verify(&mut self, headers: Headers, encoded_header: &[u8], encoded_payload: &[u8], signature: &[u8]) -> Result<()> {
		let algorithm : &str = headers.deserialize_required("alg")?;

		match algorithm {
			"HS256" => verify_mac(encoded_header, encoded_payload, signature, &mut Hmac::new(sha2::Sha256::new(), &self.key)),
			"HS384" => verify_mac(encoded_header, encoded_payload, signature, &mut Hmac::new(sha2::Sha384::new(), &self.key)),
			"HS512" => verify_mac(encoded_header, encoded_payload, signature, &mut Hmac::new(sha2::Sha512::new(), &self.key)),
			_       => Err(Error::unsupported_mac_algorithm(algorithm.to_string())),
		}
	}
}

impl Signer for MacSigner<Hmac<sha2::Sha256>> {
	fn set_header_params(&mut self, mut headers: HeadersMut) -> Result<()> {
		headers.insert("alg".to_string(), "HS256");
		Ok(())
	}

	fn compute_mac(&mut self, encoded_header: &[u8], encoded_payload: &[u8]) -> Result<Vec<u8>> {
		Ok(compute_mac(encoded_header, encoded_payload, &mut self.0).code().to_owned())
	}
}

impl Signer for MacSigner<Hmac<sha2::Sha384>> {
	fn set_header_params(&mut self, mut headers: HeadersMut) -> Result<()> {
		headers.insert("alg".to_string(), "HS384");
		Ok(())
	}

	fn compute_mac(&mut self, encoded_header: &[u8], encoded_payload: &[u8]) -> Result<Vec<u8>> {
		Ok(compute_mac(encoded_header, encoded_payload, &mut self.0).code().to_owned())
	}
}

impl Signer for MacSigner<Hmac<sha2::Sha512>> {
	fn set_header_params(&mut self, mut headers: HeadersMut) -> Result<()> {
		headers.insert("alg".to_string(), "HS512");
		Ok(())
	}

	fn compute_mac(&mut self, encoded_header: &[u8], encoded_payload: &[u8]) -> Result<Vec<u8>> {
		Ok(compute_mac(encoded_header, encoded_payload, &mut self.0).code().to_owned())
	}
}

/// Compute the Message Authentication Code for the MAC function.
fn compute_mac(encoded_header: &[u8], encoded_payload: &[u8], mac: &mut impl Mac) -> MacResult {
	mac.reset();
	mac.input(encoded_header);
	mac.input(b".");
	mac.input(encoded_payload);
	mac.result()
}

/// Verify the signature of a JWS Compact Serialization message.
fn verify_mac(encoded_header: &[u8], encoded_payload: &[u8], signature: &[u8], mac: &mut impl Mac) -> Result<()> {
	let digest = compute_mac(encoded_header, encoded_payload, mac);
	if digest == MacResult::new(signature) {
		Ok(())
	} else {
		Err(Error::invalid_signature(""))
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::{compact};
	use serde_json::json;

	macro_rules! json_object {
		({ $($tokens:tt)* }) => { serde_json::from_value::<$crate::JsonObject>(json!({ $($tokens)* })).unwrap() };
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
	const RFC7515_A1_KEY             : &[u8] = &[3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166, 143, 90, 179, 40, 230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80, 46, 191, 211, 251, 90, 146, 210, 6, 71, 239, 150, 138, 180, 195, 119, 98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205, 154, 245, 103, 208, 128, 163];

	#[test]
	fn test_decode_verify() {
		let message = compact::decode_verify(RFC7515_A1_ENCODED, HmacVerifier::new(RFC7515_A1_KEY)).unwrap();

		assert_eq!(message.header, json_object!({
			"alg": "HS256",
			"typ": "JWT",
		}));

		assert_eq!(message.payload, json!({
			"iss": "joe",
			"exp": 1300819380,
			"http://example.com/is_root": true,
		}));
	}

	#[test]
	fn test_decode_verify_invalid() {
		let result = compact::decode_verify(RFC7515_A1_ENCODED_MANGLED, HmacVerifier::new(RFC7515_A1_KEY));
		assert_eq!(result.err().unwrap().kind(), Error::InvalidSignature);
	}

	#[test]
	fn test_encode_sign_hs256() {
		let header       = serde_json::from_value(json!({"typ": "JWT"})).unwrap();
		let mut message  = compact::Message::new(header, "foo");
		let signed_hs256 = message.encode_sign(signer_hs256(b"secretkey")).unwrap();
		let signed_hs384 = message.encode_sign(signer_hs384(b"secretkey")).unwrap();
		let signed_hs512 = message.encode_sign(signer_hs512(b"secretkey")).unwrap();

		// Test that the signed message can be decoded and verified with the right key.
		let decoded_hs256 = compact::decode_verify(signed_hs256.as_bytes(), HmacVerifier::new(&b"secretkey"[..])).unwrap();
		let decoded_hs384 = compact::decode_verify(signed_hs384.as_bytes(), HmacVerifier::new(&b"secretkey"[..])).unwrap();
		let decoded_hs512 = compact::decode_verify(signed_hs512.as_bytes(), HmacVerifier::new(&b"secretkey"[..])).unwrap();

		// Test that the decoded payload is still correct.
		assert_eq!(decoded_hs256.payload, json!("foo"));
		assert_eq!(decoded_hs384.payload, json!("foo"));
		assert_eq!(decoded_hs512.payload, json!("foo"));

		// Test that the decoded header is correct.
		assert_eq!(decoded_hs256.header, json_object!({"typ": "JWT", "alg": "HS256"}));
		assert_eq!(decoded_hs384.header, json_object!({"typ": "JWT", "alg": "HS384"}));
		assert_eq!(decoded_hs512.header, json_object!({"typ": "JWT", "alg": "HS512"}));

		// Test that the signed message can bot be verified with a wrong key.
		assert_eq!(compact::decode_verify(signed_hs256.as_bytes(), HmacVerifier::new(&b"notthekey"[..])).err().unwrap().kind(), Error::InvalidSignature);
		assert_eq!(compact::decode_verify(signed_hs384.as_bytes(), HmacVerifier::new(&b"notthekey"[..])).err().unwrap().kind(), Error::InvalidSignature);
		assert_eq!(compact::decode_verify(signed_hs512.as_bytes(), HmacVerifier::new(&b"notthekey"[..])).err().unwrap().kind(), Error::InvalidSignature);

		// Also test the raw encoded form, although that's not really part of the API guarantee.
		assert_eq!(signed_hs256.data(), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ImZvbyI.y9Bvl5HwWI5zCLMcBDLTlYD9OZ4m_dbQ-Ow4VauJRPU");
		assert_eq!(signed_hs384.data(), "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.ImZvbyI.m3UtLo1QpfvOlABDm0TlU1hz_tZTi5SnH4KHCQo5l7N6ECiR1SiBZJAAtLwJo5Gu");
		assert_eq!(signed_hs512.data(), "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.ImZvbyI.f7TMTJN17caxFxy_tHhdXomjpY4qhmll-uOVa4a616NDaB7xEpRXVoCJQE4oZb0az1EPH5_iFi8_WpPnkOKtkw");
	}
}
