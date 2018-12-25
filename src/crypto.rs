//! [`Verifier`] and [`Signer`] implementations using rust-crypto.

use crypto::mac::{Mac, MacResult};
use crypto::hmac::{Hmac};
use crypto::sha2;

use crate::{error, Error, Headers, HeadersMut, Result, Signer, Verifier};

pub struct HmacVerifier{
	key: Vec<u8>,
}

pub struct MacSigner<M>(pub Hmac<M>);

impl HmacVerifier {
	pub fn new(key: Vec<u8>) -> Self {
		Self{key}
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
			_       => Err(Error::from(error::UnsupportedMacAlgorithm(algorithm.to_string()))),
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
		Err(Error::InvalidSignature)
	}
}
