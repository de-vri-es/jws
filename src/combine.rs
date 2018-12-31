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
