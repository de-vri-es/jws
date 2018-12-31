//! HMAC [`Verifier`] and [`Signer`] implementations using [RustCrypto](https://github.com/RustCrypto).

use crypto_mac::{Mac, MacResult};
use hmac::{Hmac};

use crate::{Error, JsonObject, JsonValue, HeadersRef, Result, Signer, Verifier};

type HmacSha256 = Hmac<sha2::Sha256>;
type HmacSha384 = Hmac<sha2::Sha384>;
type HmacSha512 = Hmac<sha2::Sha512>;

/// Message verifier that supports the HMAC-SHA-256, HMAC-SHA-384 and HMAC-SHA-512 algorithms using `rust-crypto`.
///
/// The wrapped key type may be anything that implements `AsRef<[u8]>`.
/// You can use a `Vec<u8>` to have the verifier own the key,
/// or a `&[u8]` to prevent copying the key more than necessary.
pub struct HmacVerifier<Key: AsRef<[u8]>> {
	key: Key,
}

/// Message signer using HMAC-SHA-256.
pub struct Hs256Signer(HmacSha256);

/// Message signer using HMAC-SHA-384.
pub struct Hs384Signer(HmacSha384);

/// Message signer using HMAC-SHA-512.
pub struct Hs512Signer(HmacSha512);

impl<K: AsRef<[u8]>> HmacVerifier<K> {
	/// Create a new HMAC verifier using a specified key.
	pub fn new(key: K) -> Self {
		Self{key}
	}
}

impl Hs256Signer {
	/// Create a HS256 signer.
	pub fn new(key: &[u8]) -> Self {
		Self(Hmac::new_varkey(key).unwrap())
	}
}

impl Hs384Signer {
	/// Create a HS384 signer.
	pub fn new(key: &[u8]) -> Self {
		Self(Hmac::new_varkey(key).unwrap())
	}
}

impl Hs512Signer {
	/// Create a HS512 signer.
	pub fn new(key: &[u8]) -> Self {
		Self(Hmac::new_varkey(key).unwrap())
	}
}

impl<K: AsRef<[u8]>> Verifier for HmacVerifier<K> {
	/// Verify the signature of a JWS message.
	///
	/// This function needs access to the decoded message headers in order to determine which MAC algorithm to use.
	/// It also needs access to the raw encoded parts to verify the MAC.
	fn verify(&mut self, headers: HeadersRef, encoded_header: &[u8], encoded_payload: &[u8], signature: &[u8]) -> Result<()> {
		let algorithm : &str = headers.deserialize_required("alg")?;

		match algorithm {
			"HS256" => verify_mac(encoded_header, encoded_payload, signature, HmacSha256::new_varkey(self.key.as_ref()).unwrap()),
			"HS384" => verify_mac(encoded_header, encoded_payload, signature, HmacSha384::new_varkey(self.key.as_ref()).unwrap()),
			"HS512" => verify_mac(encoded_header, encoded_payload, signature, HmacSha512::new_varkey(self.key.as_ref()).unwrap()),
			_       => Err(Error::unsupported_mac_algorithm(algorithm.to_string())),
		}
	}
}

impl Signer for Hs256Signer {
	fn set_header_params(&mut self, header: &mut JsonObject) -> Result<()> {
		header.insert("alg".to_string(), JsonValue::from("HS256"));
		Ok(())
	}

	fn compute_mac(&mut self, encoded_header: &[u8], encoded_payload: &[u8]) -> Result<Vec<u8>> {
		Ok(compute_mac(encoded_header, encoded_payload, self.0.clone()).code().as_slice().to_owned())
	}
}

impl Signer for Hs384Signer {
	fn set_header_params(&mut self, header: &mut JsonObject) -> Result<()> {
		header.insert("alg".to_string(), JsonValue::from("HS384"));
		Ok(())
	}

	fn compute_mac(&mut self, encoded_header: &[u8], encoded_payload: &[u8]) -> Result<Vec<u8>> {
		Ok(compute_mac(encoded_header, encoded_payload, self.0.clone()).code().as_slice().to_owned())
	}
}

impl Signer for Hs512Signer {
	fn set_header_params(&mut self, header: &mut JsonObject) -> Result<()> {
		header.insert("alg".to_string(), JsonValue::from("HS512"));
		Ok(())
	}

	fn compute_mac(&mut self, encoded_header: &[u8], encoded_payload: &[u8]) -> Result<Vec<u8>> {
		Ok(compute_mac(encoded_header, encoded_payload, self.0.clone()).code().as_slice().to_owned())
	}
}

/// Feed the encoded header and payload to a MAC in the proper format.
fn feed_mac(encoded_header: &[u8], encoded_payload: &[u8], mac: &mut impl Mac) {
	mac.reset();
	mac.input(encoded_header);
	mac.input(b".");
	mac.input(encoded_payload);
}

/// Compute the Message Authentication Code for the MAC function.
fn compute_mac<M: Mac>(encoded_header: &[u8], encoded_payload: &[u8], mut mac: M) -> MacResult<M::OutputSize> {
	feed_mac(encoded_header, encoded_payload, &mut mac);
	mac.result()
}

/// Verify the signature of a JWS Compact Serialization message.
fn verify_mac<M: Mac>(encoded_header: &[u8], encoded_payload: &[u8], signature: &[u8], mut mac: M) -> Result<()> {
	feed_mac(encoded_header, encoded_payload, &mut mac);
	mac.verify(signature).map_err(|_| Error::invalid_signature(""))
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

		assert_eq!(message.parse_json_value().unwrap(), json!({
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
	fn test_encode_sign_hmac_sha2() {
		let header       = json_object!({"typ": "JWT"});
		let signed_hs256 = compact::encode_sign(header.clone(), b"foo", Hs256Signer::new(b"secretkey")).unwrap();
		let signed_hs384 = compact::encode_sign(header.clone(), b"foo", Hs384Signer::new(b"secretkey")).unwrap();
		let signed_hs512 = compact::encode_sign(header.clone(), b"foo", Hs512Signer::new(b"secretkey")).unwrap();

		// Test that the signed message can be decoded and verified with the right key.
		let decoded_hs256 = compact::decode_verify(signed_hs256.as_bytes(), HmacVerifier::new(&b"secretkey"[..])).unwrap();
		let decoded_hs384 = compact::decode_verify(signed_hs384.as_bytes(), HmacVerifier::new(&b"secretkey"[..])).unwrap();
		let decoded_hs512 = compact::decode_verify(signed_hs512.as_bytes(), HmacVerifier::new(&b"secretkey"[..])).unwrap();

		// Test that the decoded payload is still correct.
		assert_eq!(decoded_hs256.payload, b"foo");
		assert_eq!(decoded_hs384.payload, b"foo");
		assert_eq!(decoded_hs512.payload, b"foo");

		// Test that the decoded header is correct.
		assert_eq!(decoded_hs256.header, json_object!({"typ": "JWT", "alg": "HS256"}));
		assert_eq!(decoded_hs384.header, json_object!({"typ": "JWT", "alg": "HS384"}));
		assert_eq!(decoded_hs512.header, json_object!({"typ": "JWT", "alg": "HS512"}));

		// Test that the signed message can bot be verified with a wrong key.
		assert_eq!(compact::decode_verify(signed_hs256.as_bytes(), HmacVerifier::new(&b"notthekey"[..])).err().unwrap().kind(), Error::InvalidSignature);
		assert_eq!(compact::decode_verify(signed_hs384.as_bytes(), HmacVerifier::new(&b"notthekey"[..])).err().unwrap().kind(), Error::InvalidSignature);
		assert_eq!(compact::decode_verify(signed_hs512.as_bytes(), HmacVerifier::new(&b"notthekey"[..])).err().unwrap().kind(), Error::InvalidSignature);

		// Also test the raw encoded form, although that's not really part of the API guarantee.
		assert_eq!(signed_hs256.data(), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.Zm9v.4o4hfsHG_tN4bMqxCi0CYt-OArTTogFmgZuN54HS7ZY");
		assert_eq!(signed_hs384.data(), "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.Zm9v.OoAr5wyN5KnBRY0OFYCqsk1mHrxuR_Lot33HVV43udouF1wlD1lvXL2oINrGU-9v");
		assert_eq!(signed_hs512.data(), "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.Zm9v.Al1_vJpGnm78IRKDm48NkAoYkpR4KE1hA5jN09_QnGktPKgP4QB7MJnXgeXuC5E6BVlOp7oaR-FSphbq206vxA");
	}
}
