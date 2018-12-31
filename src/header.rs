//! Types for working with message headers.

use crate::{JsonObject, JsonValue, Result};
use crate::error::Error;

/// Get a parameter from either the protected or unprotected header, depending on which are available and which has the parameter.
///
/// If a parameter is found in the protected header, the unprotected header is not consulted anymore.
pub fn get_header_param<'a>(protected: Option<&'a JsonObject>, unprotected: Option<&'a JsonObject>, key: &str) -> Option<&'a JsonValue> {
	// Try the protected header first.
	if let Some(header) = protected {
		if let Some(value) = header.get(key) {
			return Some(value)
		}
	}

	// Try the unprotected header next.
	if let Some(header) = unprotected {
		if let Some(value) = header.get(key) {
			return Some(value)
		}
	}

	// Didn't find it anywhere.
	None
}

/// Get a required parameter from either header.
///
/// This is almost identical to [`get`](#method.get), except that this function returns a properly formatter error instead of an empty optional.
pub fn get_required_header_param<'a>(protected: Option<&'a JsonObject>, unprotected: Option<&'a JsonObject>, key: &str) -> Result<&'a JsonValue> {
	Ok(get_header_param(protected, unprotected, key).ok_or_else(|| Error::missing_header_param(key))?)
}

/// Get and deserialize a required parameter from either header.
///
/// This function delegates to [`get_required`](#method.get_required) and deserializes the result into the desired type.
/// Deserialization errors are reported as [`Error::InvalidHeaderParam`].
pub fn parse_required_header_param<'a, T: serde::Deserialize<'a> + 'a>(protected: Option<&'a JsonObject>, unprotected: Option<&'a JsonObject>, key: &str) -> Result<T> {
	let value = get_required_header_param(protected, unprotected, key)?;
	let value = T::deserialize(value).map_err(|_| Error::invalid_header_param(key))?;
	Ok(value)
}
