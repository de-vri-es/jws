//! Error types for this crate.

use derive_error::Error;
use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
	MissingHeaderParam(MissingHeaderParam),
	InvalidHeaderParam(InvalidHeaderParam),
	UnsupportedMacAlgorithm(UnsupportedMacAlgorithm),
	InvalidJson(serde_json::Error),
	InvalidBase64(base64::DecodeError),
	InvalidUtf8(std::string::FromUtf8Error),
	InvalidMessage(InvalidMessage),
	InvalidSignature,
}

macro_rules! define_error_variant {
	($name:ident($type:ty, $description:expr)) => {
		#[derive(Clone, Debug)]
		pub struct $name(pub $type);

		impl std::fmt::Display for $name {
			fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
				write!(f, "{}: {}", $description, self.0)
			}
		}

		impl std::error::Error for $name {
			fn description(&self) -> &str {
				$description
			}
		}
	};
}

define_error_variant!(MissingHeaderParam      (String, "missing required header parameter"));
define_error_variant!(InvalidHeaderParam      (String, "invalid type for header parameter"));
define_error_variant!(InvalidMessage          (String, "invalid message"));
define_error_variant!(UnsupportedMacAlgorithm (String, "unsupported MAC algorithm"));
