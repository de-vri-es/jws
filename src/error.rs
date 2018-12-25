//! Error types for this crate.

use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

/// Indicates the type of an error that can occur during JWS processing.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ErrorKind {
	/// A required header parameter is missing.
	MissingHeaderParam,

	/// A header param was found but it's value is invalid.
	InvalidHeaderParam,

	/// The MAC algorithm indicates by the JWS header is not supported by the used [`Verifier`].
	UnsupportedMacAlgorithm,

	/// The message being processed is not valid.
	InvalidMessage,

	/// The signature of a message being verified is invalid.
	InvalidSignature,

	/// An error that doesn't match any of the other types.
	Other,
}

/// An error that can occur during JWS processing.
///
/// An error consists of an [`ErrorKind`] indicating the type of error,
/// and a human readable message.
///
/// The message is purely for human consumption.
/// It should not be used by error handling code to change handling logic.
#[derive(Clone, Debug)]
pub struct Error{
	kind:    ErrorKind,
	message: String,
}

impl ErrorKind {
	fn with_message(self, message: impl Into<String>) -> Error {
		Error{kind: self, message: message.into()}
	}
}

impl Error {
	pub const Other                   : ErrorKind = ErrorKind::Other;
	pub const MissingHeaderParam      : ErrorKind = ErrorKind::MissingHeaderParam;
	pub const InvalidHeaderParam      : ErrorKind = ErrorKind::InvalidHeaderParam;
	pub const UnsupportedMacAlgorithm : ErrorKind = ErrorKind::UnsupportedMacAlgorithm;
	pub const InvalidMessage          : ErrorKind = ErrorKind::InvalidMessage;
	pub const InvalidSignature        : ErrorKind = ErrorKind::InvalidSignature;

	/// Get the kind of error.
	pub fn kind(&self) -> ErrorKind {
		self.kind
	}

	/// Get the error message.
	pub fn message(&self) -> &str {
		&self.message
	}

	/// Create a new error of type [`ErrorKind::Other`] with a given message.
	pub fn other(message: impl Into<String>) -> Self {
		ErrorKind::Other.with_message(message)
	}

	/// Create a new error of type [`ErrorKind::MissingHeaderParam`] with a given message.
	pub fn missing_header_param(message: impl Into<String>) -> Self {
		ErrorKind::MissingHeaderParam.with_message(message)
	}

	/// Create a new error of type [`ErrorKind::InvalidHeaderParam`] with a given message.
	pub fn invalid_header_param(message: impl Into<String>) -> Self {
		ErrorKind::InvalidHeaderParam.with_message(message)
	}

	/// Create a new error of type [`ErrorKind::UnsupportedMacAlgorithm`] with a given message.
	pub fn unsupported_mac_algorithm(message: impl Into<String>) -> Self {
		ErrorKind::UnsupportedMacAlgorithm.with_message(message)
	}

	/// Create a new error of type [`ErrorKind::InvalidMessage`] with a given message.
	pub fn invalid_message(message: impl Into<String>) -> Self {
		ErrorKind::InvalidMessage.with_message(message)
	}

	/// Create a new error of type [`ErrorKind::InvalidSignature`] with a given message.
	pub fn invalid_signature(message: impl Into<String>) -> Self {
		ErrorKind::InvalidSignature.with_message(message)
	}
}


impl fmt::Display for ErrorKind {
	fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Other                   => write!(formatter, "unspecified error"),
			MissingHeaderParam      => write!(formatter, "missing header parameter"),
			InvalidHeaderParam      => write!(formatter, "invalid header parameter"),
			UnsupportedMacAlgorithm => write!(formatter, "unsupported MAC algorithm"),
			InvalidMessage          => write!(formatter, "invalid message"),
			InvalidSignature        => write!(formatter, "invalid signature"),
		}
	}
}

impl fmt::Display for Error {
	fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
		if self.message.is_empty() {
			write!(formatter, "{}", self.kind)
		} else {
			write!(formatter, "{}: {}", self.kind, self.message)
		}
	}
}
