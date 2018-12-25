//! Types for working with message headers.

use crate::{JsonValue, Result};
use crate::error;

/// A JWS message header.
pub type HeaderMap = std::collections::BTreeMap<String, JsonValue>;

/// The available message headers.
///
/// The message might have a protected header and/or an unprotected header.
/// However, it must always have atleast one of the two.
#[derive(Clone, Copy)]
pub enum AvailableHeaders<T> {
	Both{protected: T, unprotected: T},
	ProtectedOnly(T),
	UnprotectedOnly(T),
}

pub type Headers<'a>    = AvailableHeaders<&'a     HeaderMap>;
pub type HeadersMut<'a> = AvailableHeaders<&'a mut HeaderMap>;

impl<'a, T> std::ops::Deref for AvailableHeaders<&'a mut T> {
	type Target = AvailableHeaders<&'a T>;

	fn deref(&self) -> &Self::Target {
		// We're only changing the reference from mut to not mut, so should be safe.
		unsafe { &*(self as *const AvailableHeaders<&'a mut T> as *const AvailableHeaders<&'a T>) }
	}
}

impl<'a> Headers<'a> {
	/// Get the protected header, if it is available.
	pub fn protected(&self) -> Option<&'a HeaderMap> {
		match *self {
			AvailableHeaders::Both{protected, ..}      => Some(protected),
			AvailableHeaders::ProtectedOnly(protected) => Some(protected),
			AvailableHeaders::UnprotectedOnly(_)       => None,
		}
	}

	/// Get the unprotected header, if it is available.
	pub fn unprotected(&self) -> Option<&'a HeaderMap> {
		match *self {
			AvailableHeaders::Both{unprotected, ..}        => Some(unprotected),
			AvailableHeaders::UnprotectedOnly(unprotected) => Some(unprotected),
			AvailableHeaders::ProtectedOnly(_)             => None,
		}
	}

	/// Get a parameter from either the protected or unprotected header, depending on which are available and which has the parameter.
	///
	/// If a parameter is found in the protected header, the unprotected header is not consulted anymore.
	pub fn get(&self, key: &str) -> Option<&'a JsonValue> {
		match *self {
			AvailableHeaders::Both{protected, ..}          => protected.get(key),
			AvailableHeaders::ProtectedOnly(protected)     => protected.get(key),
			AvailableHeaders::UnprotectedOnly(unprotected) => unprotected.get(key),
		}
	}

	/// Get a required parameter from either header.
	///
	/// This is almost identical to [`get`](#method.get), except that this function returns a properly formatter error instead of an empty optional.
	pub fn get_required(&self, key: &str) -> Result<&'a JsonValue> {
		let value = self.get(key).ok_or_else(|| error::MissingHeaderParam(key.to_string()))?;
		Ok(value)
	}

	/// Get and deserialize a required parameter from either header.
	///
	/// This function delegates to [`get_required`](#method.get_required) and deserializes the result into the desired type.
	/// Deserialization errors are reported as [`error::InvalidHeaderParam`] errors.
	pub fn deserialize_required<T: serde::Deserialize<'a> + 'a>(&self, key: &str) -> Result<T> {
		let value = self.get_required(key)?;
		let value = T::deserialize(value).map_err(|_| error::InvalidHeaderParam(key.to_string()))?;
		Ok(value)
	}
}

impl<'a> HeadersMut<'a> {
	/// Insert a value into either of the available headers.
	///
	/// If the protected header is available, the value is inserted into that one.
	/// Otherwise, it is inserted into the unprotected header.
	///
	/// If the value is inserted into the protected header but the key exists in the unprotected header, it is removed from the unprotected header.
	pub fn insert<T>(&mut self, key: String, value: T) -> Option<JsonValue> where
		JsonValue: From<T>,
	{
		let value = JsonValue::from(value);

		match self {
			// Make sure to delete the key from both headers.
			AvailableHeaders::Both{protected, unprotected} => {
				let in_unprotected = unprotected.remove(&key);
				if let Some(old) = protected.insert(key, value) {
					Some(old)
				} else {
					in_unprotected
				}
			}
			AvailableHeaders::ProtectedOnly(protected)     => protected.insert(key, value),
			AvailableHeaders::UnprotectedOnly(unprotected) => unprotected.insert(key, value),
		}
	}

	/// Remove a key from all available headers.
	///
	/// This returns the erased value, if any.
	/// If the key exists in both headers, the value from the protected header is returned.
	pub fn remove<Q>(&mut self, key: &Q) -> Option<JsonValue> where
		String: std::borrow::Borrow<Q>,
		Q: Ord + ?Sized,
	{
		match self {
			// Make sure to delete the key from both headers.
			AvailableHeaders::Both{protected, unprotected} => {
				let protected   = protected.remove(key);
				let unprotected = unprotected.remove(key);
				if protected.is_some() {
					protected
				} else {
					unprotected
				}
			}
			AvailableHeaders::ProtectedOnly(protected)     => protected.remove(key),
			AvailableHeaders::UnprotectedOnly(unprotected) => unprotected.remove(key),
		}
	}
}
