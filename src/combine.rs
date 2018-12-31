///! Combine multiple verifiers.

use crate::{Error, JsonObject, Result, Verifier};

#[derive(Clone, Debug)]
pub struct OrVerifier<Left, Right> {
	pub left  : Left,
	pub right : Right,
}

#[derive(Clone, Debug)]
pub struct AndVerifier<Left, Right> {
	pub left  : Left,
	pub right : Right,
}

/// Verifier that accepts messages if they are accepted by one of the wrapped verifiers.
impl<Left, Right> OrVerifier<Left, Right> {
	pub fn new(left: Left, right: Right) -> Self {
		Self{left, right}
	}

	pub fn into_inner(self) -> (Left, Right) {
		(self.left, self.right)
	}

	pub fn left(&self) -> &Left {
		&self.left
	}

	pub fn right(&self) -> &Right {
		&self.right
	}
}

/// Verifier that accepts messages if they are accepted by both of the wrapped verifiers.
impl<Left, Right> AndVerifier<Left, Right> {
	pub fn new(left: Left, right: Right) -> Self {
		Self{left, right}
	}

	pub fn into_inner(self) -> (Left, Right) {
		(self.left, self.right)
	}

	pub fn left(&self) -> &Left {
		&self.left
	}

	pub fn right(&self) -> &Right {
		&self.right
	}
}

impl<Left: Verifier, Right: Verifier> Verifier for OrVerifier<Left, Right> {
	fn verify(&self, protected_header: Option<&JsonObject>, unprotected_header: Option<&JsonObject>, encoded_header: &[u8], encoded_payload: &[u8], signature: &[u8]) -> Result<()> {
		// Try verifier Left first.
		let error_a = match self.left.verify(protected_header, unprotected_header, encoded_header, encoded_payload, signature) {
			Ok(()) => return Ok(()),
			Err(x) => x,
		};

		// Also try verifier Right if Left didn't succeed.
		let error_b = match self.right.verify(protected_header, unprotected_header, encoded_header, encoded_payload, signature) {
			Ok(()) => return Ok(()),
			Err(x) => x,
		};

		// Favor errors that aren't UnsupportedMacAlgorithm as returned error.
		Err(match (error_a.kind(), error_b.kind()) {
			(_, Error::UnsupportedMacAlgorithm) => error_a,
			(Error::UnsupportedMacAlgorithm, _) => error_b,
			(_, _)                              => error_a
		})
	}
}

impl<Left: Verifier, Right: Verifier> Verifier for AndVerifier<Left, Right> {
	fn verify(&self, protected_header: Option<&JsonObject>, unprotected_header: Option<&JsonObject>, encoded_header: &[u8], encoded_payload: &[u8], signature: &[u8]) -> Result<()> {
		// Try verifier Left and Right in order, pass all errors up.
		self.left.verify(protected_header, unprotected_header, encoded_header, encoded_payload, signature)?;
		self.right.verify(protected_header, unprotected_header, encoded_header, encoded_payload, signature)?;
		Ok(())
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::{compact, json_object};
	use crate::hmac::{HmacVerifier, Hs256Signer};

	#[test]
	fn test_encode_sign_hmac_sha2() {
		let header = json_object!{"typ": "JWT"};
		let signed = compact::encode_sign(header.clone(), b"foo", &Hs256Signer::new(b"secretkey")).expect("sign HS256 failed");

		let verifier_wrong = HmacVerifier::new(b"wrong-key");
		let verifier_right = HmacVerifier::new(b"secretkey");

		let wrong_or_right  = verifier_wrong.clone().or(verifier_right.clone());
		let wrong_or_wrong  = verifier_wrong.clone().or(verifier_wrong.clone());
		let wrong_and_right = verifier_wrong.clone().and(verifier_right.clone());
		let right_and_right = verifier_right.clone().and(verifier_right.clone());

		// Make sure the individual verifiers work as expected.
		let wrong_result = compact::decode_verify(signed.as_bytes(), &verifier_wrong);
		let right_result = compact::decode_verify(signed.as_bytes(), &verifier_right);

		let wrong_or_right_result = compact::decode_verify(signed.as_bytes(), &wrong_or_right);
		let wrong_or_wrong_result = compact::decode_verify(signed.as_bytes(), &wrong_or_wrong);

		let wrong_and_right_result = compact::decode_verify(signed.as_bytes(), &wrong_and_right);
		let right_and_right_result = compact::decode_verify(signed.as_bytes(), &right_and_right);

		right_result.expect("(right) verifies message");
		wrong_or_right_result.expect("(wrong OR right) verifies message");
		right_and_right_result.expect("(right AND right) verifies message");

		assert_eq!(wrong_result.expect_err("(wrong) rejects message").kind(), Error::InvalidSignature);
		assert_eq!(wrong_or_wrong_result.expect_err("(wrong OR wrong) rejects message").kind(), Error::InvalidSignature);
		assert_eq!(wrong_and_right_result.expect_err("(wrong AND right) rejects message").kind(), Error::InvalidSignature);
	}
}
