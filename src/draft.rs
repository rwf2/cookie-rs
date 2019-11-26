//! This module contains types that represent cookie properties that are not yet
//! standardized. That is, _draft_ features.

use std::fmt;

/// The `SameSite` cookie attribute.
///
/// A cookie with a `SameSite` attribute is imposed restrictions on when it is
/// sent to the origin server in a cross-site request. If the `SameSite`
/// attribute is "Strict", then the cookie is never sent in cross-site requests.
/// If the `SameSite` attribute is "Lax", the cookie is only sent in cross-site
/// requests with "safe" HTTP methods, i.e, `GET`, `HEAD`, `OPTIONS`, `TRACE`.
/// If the `SameSite` attribute is not present (made explicit via the
/// `SameSite::None` variant), then the cookie will be sent as normal.
///
/// **Note:** This cookie attribute is an HTTP draft! Its meaning and definition
/// are subject to change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SameSite {
    /// The "Strict" `SameSite` attribute.
    Strict,
    /// The "Lax" `SameSite` attribute.
    Lax,
    /// The "None" `SameSite` attribute.
    None,
    /// No `SameSite` attribute
    Unset,
}

impl SameSite {
    /// Returns `true` if `self` is `SameSite::Strict` and `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::SameSite;
    ///
    /// let strict = SameSite::Strict;
    /// assert!(strict.is_strict());
    /// assert!(!strict.is_lax());
    /// assert!(!strict.is_none());
    /// assert!(!strict.is_unset());
    /// ```
    #[inline]
    pub fn is_strict(&self) -> bool {
        match *self {
            SameSite::Strict => true,
            SameSite::Lax | SameSite::None | SameSite::Unset => false,
        }
    }

    /// Returns `true` if `self` is `SameSite::Lax` and `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::SameSite;
    ///
    /// let lax = SameSite::Lax;
    /// assert!(lax.is_lax());
    /// assert!(!lax.is_strict());
    /// assert!(!lax.is_none());
    /// assert!(!lax.is_unset());
    /// ```
    #[inline]
    pub fn is_lax(&self) -> bool {
        match *self {
            SameSite::Lax => true,
            SameSite::Strict | SameSite::None | SameSite::Unset => false,
        }
    }

    /// Returns `true` if `self` is `SameSite::None` and `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::SameSite;
    ///
    /// let none = SameSite::None;
    /// assert!(none.is_none());
    /// assert!(!none.is_lax());
    /// assert!(!none.is_strict());
    /// assert!(!none.is_unset());
    /// ```
    #[inline]
    pub fn is_none(&self) -> bool {
        match *self {
            SameSite::None => true,
            SameSite::Lax | SameSite::Strict | SameSite::Unset => false
        }
    }

    /// Returns `true` if `self` is `SameSite::Unset` and `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::SameSite;
    ///
    /// let unset = SameSite::Unset;
    /// assert!(unset.is_unset());
    /// assert!(!unset.is_lax());
    /// assert!(!unset.is_strict());
    /// assert!(!unset.is_none());
    /// ```
    #[inline]
    pub fn is_unset(&self) -> bool {
        match *self {
            SameSite::Unset => true,
            SameSite::Lax | SameSite::Strict | SameSite::None => false
        }
    }
}

impl fmt::Display for SameSite {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SameSite::Strict => write!(f, "Strict"),
            SameSite::Lax => write!(f, "Lax"),
            SameSite::None => write!(f, "None"),
            SameSite::Unset => Ok(()),
        }
    }
}
