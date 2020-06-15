use std::fmt;

use crate::Cookie;

#[cfg(feature = "percent-encode")]
use crate::USERINFO_ENCODE_SET;
#[cfg(feature = "percent-encode")]
use percent_encoding::percent_encode;

/// Wrapper around `Cookie` whose `Display` implementation only prints the
/// name and value. Useful for `Cookie` headers.
///
/// A value of this type can be obtained via [`Cookie::plain()`]. This type
/// should only be used for its `Display` implementation.
///
/// # Example
///
/// ```rust
/// use cookie::Cookie;
///
/// let mut c = Cookie::new("name", "value");
/// c.set_domain("example.com");
/// assert_eq!(&c.plain().to_string(), "name=value");
/// ```
pub struct PlainCookie<'a, 'c: 'a>(pub(crate) &'a Cookie<'c>);

impl<'a, 'c: 'a> fmt::Display for PlainCookie<'a, 'c> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Write out the name/value pair without parameters.
        write!(f, "{}={}", self.0.name(), self.0.value())
    }
}

/// Wrapper around `Cookie` whose `Display` implementation only prints the
/// name and value and percent-encodes the cookie's name and value. Useful
/// for `Cookie` headers.
///
/// A value of this type can be obtained via [`Cookie::plain_encoded()`].
/// This type should only be used for its `Display` implementation.
///
/// # Example
///
/// ```rust
/// use cookie::Cookie;
///
/// let mut c = Cookie::new("my name", "this; value%?");
/// c.set_domain("example.com");
/// assert_eq!(&c.plain_encoded().to_string(), "my%20name=this%3B%20value%25%3F");
/// ```
#[cfg(feature = "percent-encode")]
#[cfg_attr(all(doc, not(doctest)), cfg(feature = "percent-encode"))]
pub struct PlainEncodedCookie<'a, 'c: 'a>(pub(crate) &'a Cookie<'c>);

#[cfg(feature = "percent-encode")]
impl<'a, 'c: 'a> fmt::Display for PlainEncodedCookie<'a, 'c> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Percent-encode the name and value.
        let name = percent_encode(self.0.name().as_bytes(), USERINFO_ENCODE_SET);
        let value = percent_encode(self.0.value().as_bytes(), USERINFO_ENCODE_SET);

        // Write out the name/value pair without parameters.
        write!(f, "{}={}", name, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SameSite;

    #[test]
    fn format_plain() {
        let cookie = Cookie::build("foo", "bar").finish();
        assert_eq!(cookie.plain().to_string(), "foo=bar");

        let cookie = Cookie::build("foo", "bar")
            .domain("example.com")
            .path("/")
            .max_age(time::Duration::seconds(10))
            .http_only(true)
            .same_site(SameSite::Lax)
            .finish();
        assert_eq!(cookie.plain().to_string(), "foo=bar");
    }

    #[test]
    #[cfg(feature = "percent-encode")]
    fn format_plain_encoded() {
        let cookie = Cookie::build("foo !?=", "bar;; a").finish();
        assert_eq!(
            cookie.plain_encoded().to_string(),
            "foo%20!%3F%3D=bar%3B%3B%20a"
        );

        let cookie = Cookie::build("foo !?=", "bar;; a")
            .domain("example.com")
            .path("/")
            .max_age(time::Duration::seconds(10))
            .http_only(true)
            .same_site(SameSite::Lax)
            .finish();
        assert_eq!(
            cookie.plain_encoded().to_string(),
            "foo%20!%3F%3D=bar%3B%3B%20a"
        );
    }
}
