//! [`Verifier`] and [`Signer`] implementations using rust-crypto.

use crypto::mac::{Mac, MacResult};
use crypto::hmac::{Hmac};
use crypto::sha2;

use crate::{Error, Headers, HeadersMut, Result, Signer, Verifier};

pub struct HmacVerifier{
	key: Vec<u8>,
}

pub struct MacSigner<M>(pub Hmac<M>);

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

impl Signer for MacSigner<sha2::Sha256> {
	fn set_header_params(&mut self, mut headers: HeadersMut) -> Result<()> {
		headers.insert("alg".to_string(), "HS256");
		Ok(())
	}

	fn compute_mac(&mut self, encoded_header: &[u8], encoded_payload: &[u8]) -> Result<Vec<u8>> {
		Ok(compute_mac(encoded_header, encoded_payload, &mut self.0).code().to_owned())
	}
}

impl Signer for MacSigner<sha2::Sha384> {
	fn set_header_params(&mut self, mut headers: HeadersMut) -> Result<()> {
		headers.insert("alg".to_string(), "HS384");
		Ok(())
	}

	fn compute_mac(&mut self, encoded_header: &[u8], encoded_payload: &[u8]) -> Result<Vec<u8>> {
		Ok(compute_mac(encoded_header, encoded_payload, &mut self.0).code().to_owned())
	}
}

impl Signer for MacSigner<sha2::Sha512> {
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
	use crate::compact;

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
	const RFC7515_A1_KEY             : &[u8] = &[3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166, 143, 90, 179, 40, 230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80, 46, 191, 211, 251, 90, 146, 210, 6, 71, 239, 150, 138, 180, 195, 119, 98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205, 154, 245, 103, 208, 128, 163];

	#[test]
	fn test_decode_verify() {
		let message = compact::decode_verify(RFC7515_A1_ENCODED, HmacVerifier::new(RFC7515_A1_KEY)).unwrap();
		assert_eq!(message.header.get("alg").unwrap(), "HS256");
		assert_eq!(message.header.get("typ").unwrap(), "JWT");
		assert_eq!(message.header.len(), 2);

		assert_eq!(&message.payload[..], RFC7515_A1_PAYLOAD);
	}

	#[test]
	fn test_decode_verify_invalid() {
		let result = compact::decode_verify(RFC7515_A1_ENCODED_MANGLED, HmacVerifier::new(RFC7515_A1_KEY));
		assert_eq!(result.err().unwrap().kind(), Error::InvalidSignature);
	}
}
