//! [`Verifier`] and [`Signer`] implementations for the `none` algorithm.
//!
//! The `none` algorithm is defined in [RFC 7518 section 3.6](https://tools.ietf.org/html/rfc7518#section-3.6).
//! It does not provide any integrity protection.
//!
//! It doesn't often make sense to use this "algorithm".

use crate::{Error, JsonObject, JsonValue, HeadersRef, Result, Signer, Verifier};

/// Message verifier for the `none` algorithm.
///
/// The `none` algorithm has an empty signature and does not provide integrity protection.
/// The verifier does check that the signature is indeed empty as required by [RFC 7518 (section 3.6)](https://tools.ietf.org/html/rfc7518#section-3.6).
pub struct NoneVerifier;

/// Message signer for the `none` algorithm.
///
/// Adds an empty signature that does not provide integrity protection.
pub struct NoneSigner;


impl Verifier for NoneVerifier {
	fn verify(&mut self, headers: HeadersRef, _encoded_header: &[u8], _encoded_payload: &[u8], signature: &[u8]) -> Result<()> {
		let algorithm : &str = headers.deserialize_required("alg")?;

		if algorithm != "none" {
			Err(Error::unsupported_mac_algorithm(algorithm))
		} else if !signature.is_empty() {
			Err(Error::invalid_signature(""))
		} else {
			Ok(())
		}
	}
}

impl Signer for NoneSigner {
	fn set_header_params(&mut self, header: &mut JsonObject) {
		header.insert("alg".to_string(), JsonValue::from("none"));
	}

	fn compute_mac(&mut self, _encoded_header: &[u8], _encoded_payload: &[u8]) -> Result<Vec<u8>> {
		Ok(Vec::new())
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::{AvailableHeaders, ErrorKind, json_object};

	#[test]
	fn test_none_signer_header() {
		let mut header = json_object!{};
		let mut signer = NoneSigner;

		signer.set_header_params(&mut header);
		assert_eq!(header, json_object!{"alg": "none"});
	}

	#[test]
	fn test_none_signer_mac() {
		let mut signer = NoneSigner;
		assert_eq!(&signer.compute_mac(b"fake_header", b"fake_payload").unwrap(), b"");
		assert_eq!(&signer.compute_mac(b"fake_header", b"").unwrap(),             b"");
		assert_eq!(&signer.compute_mac(b"",            b"fake_payload").unwrap(), b"");
		assert_eq!(&signer.compute_mac(b"",            b"").unwrap(),             b"");
	}

	#[test]
	fn test_verify_none() {
		let header  = &json_object!{"alg": "none"};
		let headers = AvailableHeaders::ProtectedOnly(header);
		let mut verifier = NoneVerifier;

		// Test that an empty signature is accepted.
		verifier.verify(headers, b"fake_header", b"fake_payload", b"").unwrap();
		verifier.verify(headers, b"fake_header", b"",             b"").unwrap();
		verifier.verify(headers, b"",            b"fake_payload", b"").unwrap();
		verifier.verify(headers, b"",            b"fake_payload", b"").unwrap();

		// Test that a non-empty signature is rejected.
		assert_eq!(verifier.verify(headers, b"fake_header", b"fake_payload", b"bad-signature").err().unwrap().kind(), ErrorKind::InvalidSignature);
		assert_eq!(verifier.verify(headers, b"fake_header", b"",             b"bad-signature").err().unwrap().kind(), ErrorKind::InvalidSignature);
		assert_eq!(verifier.verify(headers, b"",            b"fake_payload", b"bad-signature").err().unwrap().kind(), ErrorKind::InvalidSignature);
		assert_eq!(verifier.verify(headers, b"",            b"fake_payload", b"bad-signature").err().unwrap().kind(), ErrorKind::InvalidSignature);
	}
}
