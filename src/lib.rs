//! HTTP cookie parsing and cookie jar management.
//!
//! This crates provides the [`Cookie`] type, representing an HTTP cookie, and
//! the [`CookieJar`] type, which manages a collection of cookies for session
//! management, recording changes as they are made, and optional automatic
//! cookie encryption and signing.
//!
//! # Usage
//!
//! Add the following to the `[dependencies]` section of your `Cargo.toml`:
//!
//! ```toml
//! cookie = "0.18"
//! ```
//!
//! # Features
//!
//! This crate exposes several features. Only `percent-encode` is enabled by
//! default:
//!
//! * **`percent-encode`** _(enabled by default)_
//!
//!   Enables _percent encoding and decoding_ of names and values in cookies.
//!
//!   When this feature is enabled, the [`Cookie::encoded()`] and
//!   [`Cookie::parse_encoded()`] methods are available. The `encoded` method
//!   returns a wrapper around a `Cookie` whose `Display` implementation
//!   percent-encodes the name and value of the cookie. The `parse_encoded`
//!   method percent-decodes the name and value of a `Cookie` during parsing.
//!
//!   Without this feature, a `Cookie` can only be written via
//!   [`Cookie::unescaped()`], which does not encode or escape the name or
//!   value in any way.
//!
//! * **`signed`**
//!
//!   Enables _signed_ cookies via [`CookieJar::signed()`].
//!
//!   When this feature is enabled, the [`CookieJar::signed()`] method,
//!   [`SignedJar`] type, and [`Key`] type are available. The jar acts as "child
//!   jar"; operations on the jar automatically sign and verify cookies as they
//!   are added and retrieved from the parent jar.
//!
//! * **`private`**
//!
//!   Enables _private_ (authenticated, encrypted) cookies via
//!   [`CookieJar::private()`].
//!
//!   When this feature is enabled, the [`CookieJar::private()`] method,
//!   [`PrivateJar`] type, and [`Key`] type are available. The jar acts as "child
//!   jar"; operations on the jar automatically encrypt and decrypt/authenticate
//!   cookies as they are added and retrieved from the parent jar.
//!
//! * **`key-expansion`**
//!
//!   Enables _key expansion_ or _key derivation_ via [`Key::derive_from()`].
//!
//!   When this feature is enabled, and either `signed` or `private` are _also_
//!   enabled, the [`Key::derive_from()`] method is available. The method can be
//!   used to derive a `Key` structure appropriate for use with signed and
//!   private jars from cryptographically valid key material that is shorter in
//!   length than the full key.
//!
//! * **`secure`**
//!
//!   A meta-feature that simultaneously enables `signed`, `private`, and
//!   `key-expansion`.
//!
//! You can enable features via `Cargo.toml`:
//!
//! ```toml
//! [dependencies.cookie]
//! features = ["secure"]
//! ```

#![cfg_attr(all(nightly, doc), feature(doc_cfg))]

// Links to feature-gated items only resolve when the feature is enabled.
#![cfg_attr(
    not(all(
        feature = "percent-encode",
        feature = "private",
        feature = "signed",
        feature = "key-expansion",
    )),
    allow(rustdoc::broken_intra_doc_links)
)]

#![deny(missing_docs)]

mod builder;
mod date;
mod parse;
mod jar;
mod delta;
mod same_site;
mod expiration;

/// Implementation of [HTTP RFC6265 draft] cookie prefixes.
///
/// [HTTP RFC6265 draft]:
/// https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis#name-cookie-name-prefixes
pub mod prefix;

#[cfg(any(feature = "private", feature = "signed"))] #[macro_use] mod secure;
#[cfg(any(feature = "private", feature = "signed"))] pub use secure::*;

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use crate::parse::{parse_cookie, trim};
pub use crate::parse::ParseError;
pub use crate::builder::CookieBuilder;
pub use crate::jar::{CookieJar, Delta, Iter};
pub use crate::same_site::*;
pub use crate::expiration::*;

#[derive(Debug, Clone)]
enum CookieStr<'c> {
    /// An string derived from indexes (start, end).
    Indexed(usize, usize),
    /// A string derived from a concrete string.
    Concrete(Cow<'c, str>),
}

impl<'c> CookieStr<'c> {
    /// Creates an indexed `CookieStr` that holds the start and end indices of
    /// `needle` inside of `haystack`, if `needle` is a substring of `haystack`.
    /// Otherwise returns `None`.
    ///
    /// The `needle` can later be retrieved via `to_str()`.
    fn indexed(needle: &str, haystack: &str) -> Option<CookieStr<'static>> {
        let haystack_start = haystack.as_ptr() as usize;
        let needle_start = needle.as_ptr() as usize;

        if needle_start < haystack_start {
            return None;
        }

        if (needle_start + needle.len()) > (haystack_start + haystack.len()) {
            return None;
        }

        let start = needle_start - haystack_start;
        let end = start + needle.len();
        Some(CookieStr::Indexed(start, end))
    }

    /// Retrieves the string `self` corresponds to. If `self` is derived from
    /// indices, the corresponding subslice of `string` is returned. Otherwise,
    /// the concrete string is returned.
    ///
    /// # Panics
    ///
    /// Panics if `self` is an indexed string and `string` is None.
    fn to_str<'s>(&'s self, string: Option<&'s Cow<str>>) -> &'s str {
        match *self {
            CookieStr::Indexed(i, j) => {
                let s = string.expect("`Some` base string must exist when \
                    converting indexed str to str! (This is a module invariant.)");
                &s[i..j]
            },
            CookieStr::Concrete(ref cstr) => cstr,
        }
    }

    #[allow(clippy::ptr_arg)]
    fn to_raw_str<'s, 'b: 's>(&'s self, string: &'s Cow<'b, str>) -> Option<&'b str> {
        match *self {
            CookieStr::Indexed(i, j) => {
                match *string {
                    Cow::Borrowed(s) => Some(&s[i..j]),
                    Cow::Owned(_) => None,
                }
            },
            CookieStr::Concrete(_) => None,
        }
    }

    fn into_owned(self) -> CookieStr<'static> {
        use crate::CookieStr::*;

        match self {
            Indexed(a, b) => Indexed(a, b),
            Concrete(Cow::Owned(c)) => Concrete(Cow::Owned(c)),
            Concrete(Cow::Borrowed(c)) => Concrete(Cow::Owned(c.into())),
        }
    }
}

/// Truncates `string` at the first `;` or control character, if any. Neither
/// can appear in the value of a cookie attribute.
fn truncate_attribute(mut string: Cow<'_, str>) -> Cow<'_, str> {
    if let Some(i) = string.find(|c: char| c == ';' || c.is_ascii_control()) {
        match &mut string {
            Cow::Borrowed(s) => *s = &s[..i],
            Cow::Owned(s) => s.truncate(i),
        }
    }

    string
}

/// Representation of an HTTP cookie.
///
/// ## Constructing a `Cookie`
///
/// To construct a cookie with only a name/value, use [`Cookie::new()`]:
///
/// ```rust
/// use cookie::Cookie;
///
/// let cookie = Cookie::new("name", "value");
/// assert_eq!(cookie.name_value(), ("name", "value"));
/// ```
///
/// ## Building a `Cookie`
///
/// To construct more elaborate cookies, use [`Cookie::build()`] and
/// [`CookieBuilder`] methods. `Cookie::build()` accepts any type that
/// implements `T: Into<Cookie>`. See [`Cookie::build()`] for details.
///
/// ```rust
/// use cookie::Cookie;
///
/// let cookie = Cookie::build(("name", "value"))
///     .domain("www.rust-lang.org")
///     .path("/")
///     .secure(true)
///     .http_only(true);
///
/// # let mut jar = cookie::CookieJar::new();
/// jar.add(cookie);
/// jar.remove(Cookie::build("name").path("/"));
/// ```
///
/// ## Writing a `Cookie`
///
/// A `Cookie` does not implement `Display`. To write a cookie as a `Set-Cookie`
/// header value, use [`Cookie::encoded()`], which percent-encodes the name and
/// value. To read the cookie back, use [`Cookie::parse_encoded()`] or
/// [`Cookie::split_parse_encoded()`], which percent-decode the name and value.
///
/// ```rust
/// use cookie::Cookie;
///
/// # #[cfg(feature = "percent-encode")] {
/// let cookie = Cookie::build(("name", "a value")).path("/").build();
/// assert_eq!(cookie.encoded().to_string(), "name=a%20value; Path=/");
///
/// let cookie = Cookie::parse_encoded("name=a%20value; Path=/").unwrap();
/// assert_eq!(cookie.name_value(), ("name", "a value"));
/// # }
/// ```
///
/// [`Cookie::unescaped()`] writes the name and value without any encoding or
/// escaping. It is the counterpart to [`Cookie::parse()`] and
/// [`Cookie::split_parse()`]. This is dangerous! See [`Cookie::unescaped()`]
/// for details.
#[derive(Debug, Clone)]
pub struct Cookie<'c> {
    /// Storage for the cookie string. Only used if this structure was derived
    /// from a string that was subsequently parsed.
    cookie_string: Option<Cow<'c, str>>,
    /// The cookie's name.
    name: CookieStr<'c>,
    /// The cookie's value.
    value: CookieStr<'c>,
    /// The cookie's expiration, if any.
    expires: Option<Expiration>,
    /// The cookie's maximum age, if any.
    max_age: Option<Duration>,
    /// The cookie's domain, if any.
    domain: Option<CookieStr<'c>>,
    /// The cookie's path domain, if any.
    path: Option<CookieStr<'c>>,
    /// Whether this cookie was marked Secure.
    secure: Option<bool>,
    /// Whether this cookie was marked HttpOnly.
    http_only: Option<bool>,
    /// The draft `SameSite` attribute.
    same_site: Option<SameSite>,
    /// The draft `Partitioned` attribute.
    partitioned: Option<bool>,
}

impl<'c> Cookie<'c> {
    /// Creates a new `Cookie` with the given name and value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::Cookie;
    ///
    /// let cookie = Cookie::new("name", "value");
    /// assert_eq!(cookie.name_value(), ("name", "value"));
    ///
    /// // This is equivalent to `from` with a `(name, value)` tuple:
    /// let cookie = Cookie::from(("name", "value"));
    /// assert_eq!(cookie.name_value(), ("name", "value"));
    /// ```
    pub fn new<N, V>(name: N, value: V) -> Self
        where N: Into<Cow<'c, str>>,
              V: Into<Cow<'c, str>>
    {
        Cookie {
            cookie_string: None,
            name: CookieStr::Concrete(name.into()),
            value: CookieStr::Concrete(value.into()),
            expires: None,
            max_age: None,
            domain: None,
            path: None,
            secure: None,
            http_only: None,
            same_site: None,
            partitioned: None,
        }
    }

    /// Creates a new `Cookie` with the given name and an empty value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::Cookie;
    ///
    /// let cookie = Cookie::named("name");
    /// assert_eq!(cookie.name(), "name");
    /// assert!(cookie.value().is_empty());
    ///
    /// // This is equivalent to `from` with `"name`:
    /// let cookie = Cookie::from("name");
    /// assert_eq!(cookie.name(), "name");
    /// assert!(cookie.value().is_empty());
    /// ```
    #[deprecated(since = "0.18.0", note = "use `Cookie::build(name)` or `Cookie::from(name)`")]
    pub fn named<N>(name: N) -> Cookie<'c>
        where N: Into<Cow<'c, str>>
    {
        Cookie::new(name, "")
    }

    /// Creates a new [`CookieBuilder`] starting from a `base` cookie.
    ///
    /// Any type that implements `T: Into<Cookie>` can be used as a `base`:
    ///
    /// | `Into<Cookie>` Type              | Example                | Equivalent To              |
    /// |----------------------------------|------------------------|----------------------------|
    /// | `(K, V)`, `K, V: Into<Cow<str>>` | `("name", "value")`    | `Cookie::new(name, value)` |
    /// | `&str`, `String`, `Cow<str>`     | `"name"`               | `Cookie::new(name, "")`    |
    /// | [`CookieBuilder`]                | `Cookie::build("foo")` | [`CookieBuilder::build()`] |
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// // Use `(K, V)` as the base, setting a name and value.
    /// let b1 = Cookie::build(("name", "value")).path("/");
    /// assert_eq!(b1.inner().name_value(), ("name", "value"));
    /// assert_eq!(b1.inner().path(), Some("/"));
    ///
    /// // Use `&str` as the base, setting a name and empty value.
    /// let b2 = Cookie::build(("name"));
    /// assert_eq!(b2.inner().name_value(), ("name", ""));
    ///
    /// // Use `CookieBuilder` as the base, inheriting all properties.
    /// let b3 = Cookie::build(b1);
    /// assert_eq!(b3.inner().name_value(), ("name", "value"));
    /// assert_eq!(b3.inner().path(), Some("/"));
    /// ```
    pub fn build<C: Into<Cookie<'c>>>(base: C) -> CookieBuilder<'c> {
        CookieBuilder::from(base.into())
    }

    /// Parses a `Cookie` from the given HTTP cookie header value string. Does
    /// not perform any percent-decoding.
    ///
    /// This is the counterpart to [`Cookie::unescaped()`]. To parse a cookie
    /// written with [`Cookie::encoded()`], use [`Cookie::parse_encoded()`].
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let c = Cookie::parse("foo=bar%20baz; HttpOnly").unwrap();
    /// assert_eq!(c.name_value(), ("foo", "bar%20baz"));
    /// assert_eq!(c.http_only(), Some(true));
    /// assert_eq!(c.secure(), None);
    /// ```
    pub fn parse<S>(s: S) -> Result<Cookie<'c>, ParseError>
        where S: Into<Cow<'c, str>>
    {
        parse_cookie(s.into(), false)
    }

    /// Parses a `Cookie` from the given HTTP cookie header value string where
    /// the name and value fields are percent-encoded. Percent-decodes the
    /// name/value fields.
    ///
    /// This is the counterpart to [`Cookie::encoded()`].
    ///
    /// **Note:** Browsers do not decode a cookie's name. As such, browsers only
    /// enforce a cookie [`prefix`], i.e, `__Host-`, if the name has the prefix
    /// _before_ it is decoded. A name that only has a prefix _after_ it is
    /// decoded, such as `%5F%5FHost-name`, fails to parse with
    /// [`ParseError::EncodedPrefix`].
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::{Cookie, ParseError};
    ///
    /// let c = Cookie::parse_encoded("foo=bar%20baz; HttpOnly").unwrap();
    /// assert_eq!(c.name_value(), ("foo", "bar baz"));
    /// assert_eq!(c.http_only(), Some(true));
    /// assert_eq!(c.secure(), None);
    ///
    /// // Here, the name only has the `__Host-` prefix after decoding.
    /// let c = Cookie::parse_encoded("%5F%5FHost-foo=bar");
    /// assert_eq!(c, Err(ParseError::EncodedPrefix));
    /// ```
    #[cfg(feature = "percent-encode")]
    #[cfg_attr(all(nightly, doc), doc(cfg(feature = "percent-encode")))]
    pub fn parse_encoded<S>(s: S) -> Result<Cookie<'c>, ParseError>
        where S: Into<Cow<'c, str>>
    {
        parse_cookie(s.into(), true)
    }

    /// Parses the HTTP `Cookie` header, a series of cookie names and value
    /// separated by `;`, returning an iterator over the parse results. Each
    /// item returned by the iterator is a `Result<Cookie, ParseError>` of
    /// parsing one name/value pair. Empty cookie values (i.e, in `a=1;;b=2`)
    /// and any excess surrounding whitespace are ignored.
    ///
    /// Unlike [`Cookie::split_parse_encoded()`], this method _does **not**_
    /// percent-decode keys and values.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::Cookie;
    ///
    /// let string = "name=value; other=key%20value";
    /// # let values: Vec<_> = Cookie::split_parse(string).collect();
    /// # assert_eq!(values.len(), 2);
    /// # assert_eq!(values[0].as_ref().unwrap().name(), "name");
    /// # assert_eq!(values[1].as_ref().unwrap().name(), "other");
    /// for cookie in Cookie::split_parse(string) {
    ///     let cookie = cookie.unwrap();
    ///     match cookie.name() {
    ///         "name" => assert_eq!(cookie.value(), "value"),
    ///         "other" => assert_eq!(cookie.value(), "key%20value"),
    ///         _ => unreachable!()
    ///     }
    /// }
    /// ```
    #[inline(always)]
    pub fn split_parse<S>(string: S) -> SplitCookies<'c>
        where S: Into<Cow<'c, str>>
    {
        SplitCookies {
            string: string.into(),
            last: 0,
            decode: false,
        }
    }

    /// Parses the HTTP `Cookie` header, a series of cookie names and value
    /// separated by `;`, returning an iterator over the parse results. Each
    /// item returned by the iterator is a `Result<Cookie, ParseError>` of
    /// parsing one name/value pair. Empty cookie values (i.e, in `a=1;;b=2`)
    /// and any excess surrounding whitespace are ignored.
    ///
    /// Unlike [`Cookie::split_parse()`], this method _does_ percent-decode keys
    /// and values. See [`Cookie::parse_encoded()`] for details.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::Cookie;
    ///
    /// let string = "name=value; other=key%20value";
    /// # let v: Vec<_> = Cookie::split_parse_encoded(string).collect();
    /// # assert_eq!(v.len(), 2);
    /// # assert_eq!(v[0].as_ref().unwrap().name_value(), ("name", "value"));
    /// # assert_eq!(v[1].as_ref().unwrap().name_value(), ("other", "key value"));
    /// for cookie in Cookie::split_parse_encoded(string) {
    ///     let cookie = cookie.unwrap();
    ///     match cookie.name() {
    ///         "name" => assert_eq!(cookie.value(), "value"),
    ///         "other" => assert_eq!(cookie.value(), "key value"),
    ///         _ => unreachable!()
    ///     }
    /// }
    /// ```
    #[cfg(feature = "percent-encode")]
    #[cfg_attr(all(nightly, doc), doc(cfg(feature = "percent-encode")))]
    #[inline(always)]
    pub fn split_parse_encoded<S>(string: S) -> SplitCookies<'c>
        where S: Into<Cow<'c, str>>
    {
        SplitCookies {
            string: string.into(),
            last: 0,
            decode: true,
        }
    }

    /// Converts `self` into a `Cookie` with a static lifetime with as few
    /// allocations as possible.
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let c = Cookie::new("a", "b");
    /// let owned_cookie = c.into_owned();
    /// assert_eq!(owned_cookie.name_value(), ("a", "b"));
    /// ```
    pub fn into_owned(self) -> Cookie<'static> {
        Cookie {
            cookie_string: self.cookie_string.map(|s| s.into_owned().into()),
            name: self.name.into_owned(),
            value: self.value.into_owned(),
            expires: self.expires,
            max_age: self.max_age,
            domain: self.domain.map(|s| s.into_owned()),
            path: self.path.map(|s| s.into_owned()),
            secure: self.secure,
            http_only: self.http_only,
            same_site: self.same_site,
            partitioned: self.partitioned,
        }
    }

    /// Returns the name of `self`.
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let c = Cookie::new("name", "value");
    /// assert_eq!(c.name(), "name");
    /// ```
    #[inline]
    pub fn name(&self) -> &str {
        self.name.to_str(self.cookie_string.as_ref())
    }

    /// Returns the value of `self`.
    ///
    /// Does not strip surrounding quotes. See [`Cookie::value_trimmed()`] for a
    /// version that does.
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let c = Cookie::new("name", "value");
    /// assert_eq!(c.value(), "value");
    ///
    /// let c = Cookie::new("name", "\"value\"");
    /// assert_eq!(c.value(), "\"value\"");
    /// ```
    #[inline]
    pub fn value(&self) -> &str {
        self.value.to_str(self.cookie_string.as_ref())
    }

    /// Returns the value of `self` with surrounding double-quotes trimmed.
    ///
    /// This is _not_ the value of the cookie (_that_ is [`Cookie::value()`]).
    /// Instead, this is the value with a surrounding pair of double-quotes, if
    /// any, trimmed away. Quotes are only trimmed when they form a pair and
    /// never otherwise. The trimmed value is never used for other operations,
    /// such as equality checking, on `self`.
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    /// let c0 = Cookie::new("name", "value");
    /// assert_eq!(c0.value_trimmed(), "value");
    ///
    /// let c = Cookie::new("name", "\"value\"");
    /// assert_eq!(c.value_trimmed(), "value");
    /// assert!(c != c0);
    ///
    /// let c = Cookie::new("name", "\"value");
    /// assert_eq!(c.value(), "\"value");
    /// assert_eq!(c.value_trimmed(), "\"value");
    /// assert!(c != c0);
    ///
    /// let c = Cookie::new("name", "\"value\"\"");
    /// assert_eq!(c.value(), "\"value\"\"");
    /// assert_eq!(c.value_trimmed(), "value\"");
    /// assert!(c != c0);
    /// ```
    #[inline]
    pub fn value_trimmed(&self) -> &str {
        #[inline(always)]
        fn trim_quotes(s: &str) -> &str {
            if s.len() < 2 {
                return s;
            }

            let bytes = s.as_bytes();
            match (bytes.first(), bytes.last()) {
                (Some(b'"'), Some(b'"')) => &s[1..(s.len() - 1)],
                _ => s
            }
        }

        trim_quotes(self.value())
    }

    /// Returns the name and value of `self` as a tuple of `(name, value)`.
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let c = Cookie::new("name", "value");
    /// assert_eq!(c.name_value(), ("name", "value"));
    /// ```
    #[inline]
    pub fn name_value(&self) -> (&str, &str) {
        (self.name(), self.value())
    }

    /// Returns the name and [trimmed value](Cookie::value_trimmed()) of `self`
    /// as a tuple of `(name, trimmed_value)`.
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let c = Cookie::new("name", "\"value\"");
    /// assert_eq!(c.name_value_trimmed(), ("name", "value"));
    /// ```
    #[inline]
    pub fn name_value_trimmed(&self) -> (&str, &str) {
        (self.name(), self.value_trimmed())
    }

    /// Returns whether this cookie was marked `HttpOnly` or not. Returns
    /// `Some(true)` when the cookie was explicitly set (manually or parsed) as
    /// `HttpOnly`, `Some(false)` when `http_only` was manually set to `false`,
    /// and `None` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let c = Cookie::parse("name=value; httponly").unwrap();
    /// assert_eq!(c.http_only(), Some(true));
    ///
    /// let mut c = Cookie::new("name", "value");
    /// assert_eq!(c.http_only(), None);
    ///
    /// let mut c = Cookie::new("name", "value");
    /// assert_eq!(c.http_only(), None);
    ///
    /// // An explicitly set "false" value.
    /// c.set_http_only(false);
    /// assert_eq!(c.http_only(), Some(false));
    ///
    /// // An explicitly set "true" value.
    /// c.set_http_only(true);
    /// assert_eq!(c.http_only(), Some(true));
    /// ```
    #[inline]
    pub fn http_only(&self) -> Option<bool> {
        self.http_only
    }

    /// Returns whether this cookie was marked `Secure` or not. Returns
    /// `Some(true)` when the cookie was explicitly set (manually or parsed) as
    /// `Secure`, `Some(false)` when `secure` was manually set to `false`, and
    /// `None` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let c = Cookie::parse("name=value; Secure").unwrap();
    /// assert_eq!(c.secure(), Some(true));
    ///
    /// let mut c = Cookie::parse("name=value").unwrap();
    /// assert_eq!(c.secure(), None);
    ///
    /// let mut c = Cookie::new("name", "value");
    /// assert_eq!(c.secure(), None);
    ///
    /// // An explicitly set "false" value.
    /// c.set_secure(false);
    /// assert_eq!(c.secure(), Some(false));
    ///
    /// // An explicitly set "true" value.
    /// c.set_secure(true);
    /// assert_eq!(c.secure(), Some(true));
    /// ```
    #[inline]
    pub fn secure(&self) -> Option<bool> {
        self.secure
    }

    /// Returns the `SameSite` attribute of this cookie if one was specified.
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::{Cookie, SameSite};
    ///
    /// let c = Cookie::parse("name=value; SameSite=Lax").unwrap();
    /// assert_eq!(c.same_site(), Some(SameSite::Lax));
    /// ```
    #[inline]
    pub fn same_site(&self) -> Option<SameSite> {
        self.same_site
    }

    /// Returns whether this cookie was marked `Partitioned` or not. Returns
    /// `Some(true)` when the cookie was explicitly set (manually or parsed) as
    /// `Partitioned`, `Some(false)` when `partitioned` was manually set to `false`,
    /// and `None` otherwise.
    ///
    /// **Note:** This cookie attribute is an [HTTP draft]! Its meaning and
    /// definition are not standardized and therefore subject to change.
    ///
    /// [HTTP draft]: https://www.ietf.org/archive/id/draft-cutler-httpbis-partitioned-cookies-01.html
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let c = Cookie::parse("name=value; Partitioned").unwrap();
    /// assert_eq!(c.partitioned(), Some(true));
    ///
    /// let mut c = Cookie::parse("name=value").unwrap();
    /// assert_eq!(c.partitioned(), None);
    ///
    /// let mut c = Cookie::new("name", "value");
    /// assert_eq!(c.partitioned(), None);
    ///
    /// // An explicitly set "false" value.
    /// c.set_partitioned(false);
    /// assert_eq!(c.partitioned(), Some(false));
    ///
    /// // An explicitly set "true" value.
    /// c.set_partitioned(true);
    /// assert_eq!(c.partitioned(), Some(true));
    /// ```
    #[inline]
    pub fn partitioned(&self) -> Option<bool> {
        self.partitioned
    }

    /// Returns the specified max-age of the cookie if one was specified.
    ///
    /// **Note:** A parsed `Max-Age` can be as large as `i64::MAX` seconds. As
    /// such, adding a `Max-Age` to a `SystemTime` with `+` can overflow and
    /// panic. Use [`SystemTime::checked_add()`] instead.
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let c = Cookie::parse("name=value").unwrap();
    /// assert_eq!(c.max_age(), None);
    ///
    /// let c = Cookie::parse("name=value; Max-Age=3600").unwrap();
    /// assert_eq!(c.max_age().map(|age| age.as_secs()), Some(3600));
    /// ```
    #[inline]
    pub fn max_age(&self) -> Option<Duration> {
        self.max_age
    }

    /// Returns the `Path` of the cookie if one was specified.
    ///
    /// This does not consider whether the `Path` is valid; validation is left
    /// to higher-level libraries, as needed.
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let c = Cookie::parse("name=value").unwrap();
    /// assert_eq!(c.path(), None);
    ///
    /// let c = Cookie::parse("name=value; Path=/").unwrap();
    /// assert_eq!(c.path(), Some("/"));
    ///
    /// let c = Cookie::parse("name=value; path=/sub").unwrap();
    /// assert_eq!(c.path(), Some("/sub"));
    /// ```
    #[inline]
    pub fn path(&self) -> Option<&str> {
        match self.path {
            Some(ref c) => Some(c.to_str(self.cookie_string.as_ref())),
            None => None,
        }
    }

    /// Returns the `Domain` of the cookie if one was specified.
    ///
    /// This does not consider whether the `Domain` is valid; validation is left
    /// to higher-level libraries, as needed. However, if the `Domain` starts
    /// with a leading `.`, the leading `.` is stripped. Use
    /// [`Cookie::domain_verbatim()`] to access the current `Domain` without
    /// removing a leading `.`.
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let c = Cookie::parse("name=value").unwrap();
    /// assert_eq!(c.domain(), None);
    /// assert_eq!(c.domain_verbatim(), None);
    ///
    /// let c = Cookie::parse("name=value; Domain=crates.io").unwrap();
    /// assert_eq!(c.domain(), Some("crates.io"));
    /// assert_eq!(c.domain_verbatim(), Some("crates.io"));
    ///
    /// let c = Cookie::parse("name=value; Domain=.crates.io").unwrap();
    /// assert_eq!(c.domain(), Some("crates.io"));
    /// assert_eq!(c.domain_verbatim(), Some(".crates.io"));
    ///
    /// // Note that `..crates.io` is not a valid domain.
    /// let c = Cookie::parse("name=value; Domain=..crates.io").unwrap();
    /// assert_eq!(c.domain(), Some(".crates.io"));
    /// assert_eq!(c.domain_verbatim(), Some("..crates.io"));
    /// ```
    #[inline]
    pub fn domain(&self) -> Option<&str> {
        let domain = self.domain_verbatim()?;
        domain.strip_prefix('.').or(Some(domain))
    }

    /// Returns the [`Expiration`] of the cookie if one was specified.
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::{Cookie, Expiration};
    ///
    /// let c = Cookie::parse("name=value").unwrap();
    /// assert_eq!(c.expires(), None);
    ///
    /// // Here, `cookie.expires_datetime()` returns `None`.
    /// let c = Cookie::build(("name", "value")).expires(None).build();
    /// assert_eq!(c.expires(), Some(Expiration::Session));
    ///
    /// let expire_time = "Sat, 21 Oct 2017 07:28:00 GMT";
    /// let cookie_str = format!("name=value; Expires={}", expire_time);
    /// let c = Cookie::parse(cookie_str).unwrap();
    /// assert!(c.expires().is_some_and(|e| e.is_datetime()));
    /// ```
    #[inline]
    pub fn expires(&self) -> Option<Expiration> {
        self.expires
    }

    /// Returns the expiration date-time of the cookie if one was specified.
    ///
    /// # Example
    ///
    /// ```
    /// use std::time::{Duration, SystemTime};
    ///
    /// use cookie::Cookie;
    ///
    /// let c = Cookie::parse("name=value").unwrap();
    /// assert_eq!(c.expires_datetime(), None);
    ///
    /// // Here, `cookie.expires()` returns `Some`.
    /// let c = Cookie::build(("name", "value")).expires(None).build();
    /// assert_eq!(c.expires_datetime(), None);
    ///
    /// let expire_time = "Sat, 21 Oct 2017 07:28:00 GMT";
    /// let cookie_str = format!("name=value; Expires={}", expire_time);
    /// let c = Cookie::parse(cookie_str).unwrap();
    ///
    /// let expected = SystemTime::UNIX_EPOCH + Duration::from_secs(1508570880);
    /// assert_eq!(c.expires_datetime(), Some(expected));
    /// ```
    #[inline]
    pub fn expires_datetime(&self) -> Option<SystemTime> {
        self.expires.and_then(|e| e.datetime())
    }

    /// Sets the name of `self` to `name`.
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let mut c = Cookie::new("name", "value");
    /// assert_eq!(c.name(), "name");
    ///
    /// c.set_name("foo");
    /// assert_eq!(c.name(), "foo");
    /// ```
    pub fn set_name<N: Into<Cow<'c, str>>>(&mut self, name: N) {
        self.name = CookieStr::Concrete(name.into())
    }

    /// Sets the value of `self` to `value`.
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let mut c = Cookie::new("name", "value");
    /// assert_eq!(c.value(), "value");
    ///
    /// c.set_value("bar");
    /// assert_eq!(c.value(), "bar");
    /// ```
    pub fn set_value<V: Into<Cow<'c, str>>>(&mut self, value: V) {
        self.value = CookieStr::Concrete(value.into())
    }

    /// Sets the value of `http_only` in `self` to `value`.  If `value` is
    /// `None`, the field is unset.
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let mut c = Cookie::new("name", "value");
    /// assert_eq!(c.http_only(), None);
    ///
    /// c.set_http_only(true);
    /// assert_eq!(c.http_only(), Some(true));
    ///
    /// c.set_http_only(false);
    /// assert_eq!(c.http_only(), Some(false));
    ///
    /// c.set_http_only(None);
    /// assert_eq!(c.http_only(), None);
    /// ```
    #[inline]
    pub fn set_http_only<T: Into<Option<bool>>>(&mut self, value: T) {
        self.http_only = value.into();
    }

    /// Sets the value of `secure` in `self` to `value`. If `value` is `None`,
    /// the field is unset.
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let mut c = Cookie::new("name", "value");
    /// assert_eq!(c.secure(), None);
    ///
    /// c.set_secure(true);
    /// assert_eq!(c.secure(), Some(true));
    ///
    /// c.set_secure(false);
    /// assert_eq!(c.secure(), Some(false));
    ///
    /// c.set_secure(None);
    /// assert_eq!(c.secure(), None);
    /// ```
    #[inline]
    pub fn set_secure<T: Into<Option<bool>>>(&mut self, value: T) {
        self.secure = value.into();
    }

    /// Sets the value of `same_site` in `self` to `value`. If `value` is
    /// `None`, the field is unset. If `value` is `SameSite::None`, the "Secure"
    /// flag will be set when the cookie is written out unless `secure` is
    /// explicitly set to `false` via [`Cookie::set_secure()`] or the equivalent
    /// builder method.
    ///
    /// [HTTP draft]: https://tools.ietf.org/html/draft-west-cookie-incrementalism-00
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::{Cookie, SameSite};
    ///
    /// # #[cfg(feature = "percent-encode")] {
    /// let mut c = Cookie::new("name", "value");
    /// assert_eq!(c.same_site(), None);
    ///
    /// c.set_same_site(SameSite::None);
    /// assert_eq!(c.same_site(), Some(SameSite::None));
    /// assert_eq!(c.encoded().to_string(), "name=value; SameSite=None; Secure");
    ///
    /// c.set_secure(false);
    /// assert_eq!(c.encoded().to_string(), "name=value; SameSite=None");
    ///
    /// let mut c = Cookie::new("name", "value");
    /// assert_eq!(c.same_site(), None);
    ///
    /// c.set_same_site(SameSite::Strict);
    /// assert_eq!(c.same_site(), Some(SameSite::Strict));
    /// assert_eq!(c.encoded().to_string(), "name=value; SameSite=Strict");
    ///
    /// c.set_same_site(None);
    /// assert_eq!(c.same_site(), None);
    /// assert_eq!(c.encoded().to_string(), "name=value");
    /// # }
    /// ```
    #[inline]
    pub fn set_same_site<T: Into<Option<SameSite>>>(&mut self, value: T) {
        self.same_site = value.into();
    }

    /// Sets the value of `partitioned` in `self` to `value`. If `value` is
    /// `None`, the field is unset.
    ///
    /// **Note:** _Partitioned_ cookies require the `Secure` attribute to be
    /// set. As such, `Partitioned` cookies are always rendered with the
    /// `Secure` attribute, irrespective of the `Secure` attribute's setting.
    ///
    /// **Note:** This cookie attribute is an [HTTP draft]! Its meaning and
    /// definition are not standardized and therefore subject to change.
    ///
    /// [HTTP draft]: https://www.ietf.org/archive/id/draft-cutler-httpbis-partitioned-cookies-01.html
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// # #[cfg(feature = "percent-encode")] {
    /// let mut c = Cookie::new("name", "value");
    /// assert_eq!(c.partitioned(), None);
    /// assert!(!c.encoded().to_string().contains("Partitioned"));
    /// assert!(!c.encoded().to_string().contains("Secure"));
    ///
    /// c.set_partitioned(true);
    /// assert_eq!(c.partitioned(), Some(true));
    /// assert!(c.encoded().to_string().contains("Partitioned"));
    /// assert!(c.encoded().to_string().contains("Secure"));
    ///
    /// c.set_partitioned(false);
    /// assert_eq!(c.partitioned(), Some(false));
    /// assert!(!c.encoded().to_string().contains("Partitioned"));
    /// assert!(!c.encoded().to_string().contains("Secure"));
    ///
    /// c.set_partitioned(None);
    /// assert_eq!(c.partitioned(), None);
    /// assert!(!c.encoded().to_string().contains("Partitioned"));
    /// assert!(!c.encoded().to_string().contains("Secure"));
    /// # }
    /// ```
    #[inline]
    pub fn set_partitioned<T: Into<Option<bool>>>(&mut self, value: T) {
        self.partitioned = value.into();
    }

    /// Sets the value of `max_age` in `self` to `value`. If `value` is `None`,
    /// the field is unset.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::time::Duration;
    ///
    /// use cookie::Cookie;
    ///
    /// # fn main() {
    /// let mut c = Cookie::new("name", "value");
    /// assert_eq!(c.max_age(), None);
    ///
    /// let ten_hours = Duration::from_secs(10 * 60 * 60);
    /// c.set_max_age(ten_hours);
    /// assert_eq!(c.max_age(), Some(ten_hours));
    ///
    /// c.set_max_age(None);
    /// assert!(c.max_age().is_none());
    /// # }
    /// ```
    #[inline]
    pub fn set_max_age<D: Into<Option<Duration>>>(&mut self, value: D) {
        self.max_age = value.into();
    }

    /// Sets the `path` of `self` to `path`.
    ///
    /// A `Path` cannot contain a `;` or a control character. As such, `path` is
    /// truncated at the first `;` or control character, if any. This does not
    /// otherwise consider whether the `Path` is valid; validation is left to
    /// higher-level libraries, as needed.
    ///
    /// **Note:** A `Path` is only truncated when it is set. A parsed `Path` is
    /// left as it was parsed. As such, a parsed `Path` may contain a horizontal
    /// tab, the only control character allowed when parsing.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::Cookie;
    ///
    /// let mut c = Cookie::new("name", "value");
    /// assert_eq!(c.path(), None);
    ///
    /// c.set_path("/");
    /// assert_eq!(c.path(), Some("/"));
    ///
    /// // Everything from the first `;` or control character is removed.
    /// c.set_path("/sub; Domain=crates.io");
    /// assert_eq!(c.path(), Some("/sub"));
    ///
    /// // A parsed `Path` is left as it was parsed.
    /// let c = Cookie::parse("name=value; Path=/sub\tdir").unwrap();
    /// assert_eq!(c.path(), Some("/sub\tdir"));
    /// ```
    pub fn set_path<P: Into<Cow<'c, str>>>(&mut self, path: P) {
        self.path = Some(CookieStr::Concrete(truncate_attribute(path.into())));
    }

    /// Unsets the `path` of `self`.
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let mut c = Cookie::new("name", "value");
    /// assert_eq!(c.path(), None);
    ///
    /// c.set_path("/");
    /// assert_eq!(c.path(), Some("/"));
    ///
    /// c.unset_path();
    /// assert_eq!(c.path(), None);
    /// ```
    pub fn unset_path(&mut self) {
        self.path = None;
    }

    /// Sets the `domain` of `self` to `domain`.
    ///
    /// A `Domain` cannot contain a `;` or a control character. As such,
    /// `domain` is truncated at the first `;` or control character, if any.
    /// This does not otherwise consider whether the `Domain` is valid;
    /// validation is left to higher-level libraries, as needed.
    ///
    /// **Note:** A `Domain` is only truncated when it is set. A parsed `Domain`
    /// is left as it was parsed. As such, a parsed `Domain` may contain a
    /// horizontal tab, the only control character allowed when parsing.
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let mut c = Cookie::new("name", "value");
    /// assert_eq!(c.domain(), None);
    ///
    /// c.set_domain("rust-lang.org");
    /// assert_eq!(c.domain(), Some("rust-lang.org"));
    ///
    /// // Everything from the first `;` or control character is removed.
    /// c.set_domain("crates.io; Path=/");
    /// assert_eq!(c.domain(), Some("crates.io"));
    ///
    /// // A parsed `Domain` is left as it was parsed.
    /// let c = Cookie::parse("name=value; Domain=crates\t.io").unwrap();
    /// assert_eq!(c.domain(), Some("crates\t.io"));
    /// ```
    pub fn set_domain<D: Into<Cow<'c, str>>>(&mut self, domain: D) {
        self.domain = Some(CookieStr::Concrete(truncate_attribute(domain.into())));
    }

    /// Unsets the `domain` of `self`.
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let mut c = Cookie::new("name", "value");
    /// assert_eq!(c.domain(), None);
    ///
    /// c.set_domain("rust-lang.org");
    /// assert_eq!(c.domain(), Some("rust-lang.org"));
    ///
    /// c.unset_domain();
    /// assert_eq!(c.domain(), None);
    /// ```
    pub fn unset_domain(&mut self) {
        self.domain = None;
    }

    /// Sets the expires field of `self` to `time`. If `time` is `None`, an
    /// expiration of [`Session`](Expiration::Session) is set.
    ///
    /// A date-time later than Dec 31, 9999, 23:59:59 UTC is set to that
    /// date-time. A date-time earlier than the Unix epoch is written as the
    /// Unix epoch, as not every client can read an earlier date.
    ///
    /// # Example
    ///
    /// ```
    /// use std::time::{Duration, SystemTime};
    ///
    /// use cookie::{Cookie, Expiration};
    ///
    /// let mut c = Cookie::new("name", "value");
    /// assert_eq!(c.expires(), None);
    ///
    /// let one_week = Duration::from_secs(7 * 24 * 60 * 60);
    /// c.set_expires(SystemTime::now() + one_week);
    /// assert!(c.expires().is_some());
    ///
    /// c.set_expires(None);
    /// assert_eq!(c.expires(), Some(Expiration::Session));
    /// ```
    pub fn set_expires<T: Into<Expiration>>(&mut self, time: T) {
        // RFC 6265 requires dates not to exceed 9999 years.
        self.expires = Some(time.into()
            .map(|time| std::cmp::min(time, date::max_datetime())));
    }

    /// Unsets the `expires` of `self`.
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::{Cookie, Expiration};
    ///
    /// let mut c = Cookie::new("name", "value");
    /// assert_eq!(c.expires(), None);
    ///
    /// c.set_expires(None);
    /// assert_eq!(c.expires(), Some(Expiration::Session));
    ///
    /// c.unset_expires();
    /// assert_eq!(c.expires(), None);
    /// ```
    pub fn unset_expires(&mut self) {
        self.expires = None;
    }

    /// Makes `self` a "permanent" cookie by extending its expiration and max
    /// age 20 years into the future.
    ///
    /// # Panics
    ///
    /// Panics if the current time cannot be retrieved from the operating
    /// system. This is the case on platforms without a system clock, such as
    /// `wasm32-unknown-unknown`.
    ///
    /// For a non-panicking version, set the max-age and expiration directly:
    ///
    /// ```rust
    /// use std::time::{Duration, SystemTime};
    ///
    /// use cookie::Cookie;
    ///
    /// # let now = SystemTime::now();
    /// let twenty_years = Duration::from_secs(20 * 365 * 24 * 60 * 60);
    ///
    /// let mut c = Cookie::new("foo", "bar");
    /// c.set_max_age(twenty_years);
    ///
    /// // Here, `now` is the current time, retrieved by other means.
    /// c.set_expires(now + twenty_years);
    /// ```
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::time::Duration;
    ///
    /// use cookie::Cookie;
    ///
    /// # fn main() {
    /// let mut c = Cookie::new("foo", "bar");
    /// assert!(c.expires().is_none());
    /// assert!(c.max_age().is_none());
    ///
    /// c.make_permanent();
    /// assert!(c.expires().is_some());
    /// assert_eq!(c.max_age(), Some(Duration::from_secs(20 * 365 * 24 * 60 * 60)));
    /// # }
    /// ```
    pub fn make_permanent(&mut self) {
        let twenty_years = Duration::from_secs(20 * 365 * 24 * 60 * 60);
        self.set_max_age(twenty_years);
        self.set_expires(SystemTime::now() + twenty_years);
    }

    /// Make `self` a "removal" cookie by clearing its value, setting a max-age
    /// of `0`, and setting an expiration date of the Unix epoch: January 1,
    /// 1970.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::time::{Duration, SystemTime};
    ///
    /// use cookie::Cookie;
    ///
    /// # fn main() {
    /// let mut c = Cookie::build(("foo", "bar")).path("/").build();
    /// assert_eq!(c.value(), "bar");
    ///
    /// c.make_removal();
    /// assert_eq!(c.value(), "");
    /// assert_eq!(c.path(), Some("/"));
    /// assert_eq!(c.max_age(), Some(Duration::ZERO));
    /// assert_eq!(c.expires_datetime(), Some(SystemTime::UNIX_EPOCH));
    /// # }
    /// ```
    pub fn make_removal(&mut self) {
        self.set_value("");
        self.set_max_age(Duration::ZERO);
        self.set_expires(SystemTime::UNIX_EPOCH);
    }

    fn fmt_parameters(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(true) = self.http_only() {
            write!(f, "; HttpOnly")?;
        }

        if let Some(same_site) = self.same_site() {
            write!(f, "; SameSite={}", same_site)?;
        }

        if let Some(true) = self.partitioned() {
            write!(f, "; Partitioned")?;
        }

        if self.secure() == Some(true)
            || self.partitioned() == Some(true)
            || self.secure().is_none() && self.same_site() == Some(SameSite::None)
        {
            write!(f, "; Secure")?;
        }

        if let Some(path) = self.path() {
            write!(f, "; Path={}", path)?;
        }

        if let Some(domain) = self.domain() {
            write!(f, "; Domain={}", domain)?;
        }

        if let Some(max_age) = self.max_age() {
            // Not every client can read a `Max-Age` larger than `i64::MAX`.
            write!(f, "; Max-Age={}", max_age.as_secs().min(i64::MAX as u64))?;
        }

        if let Some(time) = self.expires_datetime() {
            write!(f, "; Expires={}", date::HttpDate(time))?;
        }

        Ok(())
    }

    /// Returns the name of `self` as a string slice of the raw string `self`
    /// was originally parsed from. If `self` was not originally parsed from a
    /// raw string, returns `None`.
    ///
    /// This method differs from [`Cookie::name()`] in that it returns a string
    /// with the same lifetime as the originally parsed string. This lifetime
    /// may outlive `self`. If a longer lifetime is not required, or you're
    /// unsure if you need a longer lifetime, use [`Cookie::name()`].
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let cookie_string = format!("{}={}", "foo", "bar");
    ///
    /// // `c` will be dropped at the end of the scope, but `name` will live on
    /// let name = {
    ///     let c = Cookie::parse(cookie_string.as_str()).unwrap();
    ///     c.name_raw()
    /// };
    ///
    /// assert_eq!(name, Some("foo"));
    /// ```
    #[inline]
    pub fn name_raw(&self) -> Option<&'c str> {
        self.cookie_string.as_ref()
            .and_then(|s| self.name.to_raw_str(s))
    }

    /// Returns the value of `self` as a string slice of the raw string `self`
    /// was originally parsed from. If `self` was not originally parsed from a
    /// raw string, returns `None`.
    ///
    /// This method differs from [`Cookie::value()`] in that it returns a
    /// string with the same lifetime as the originally parsed string. This
    /// lifetime may outlive `self`. If a longer lifetime is not required, or
    /// you're unsure if you need a longer lifetime, use [`Cookie::value()`].
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let cookie_string = format!("{}={}", "foo", "bar");
    ///
    /// // `c` will be dropped at the end of the scope, but `value` will live on
    /// let value = {
    ///     let c = Cookie::parse(cookie_string.as_str()).unwrap();
    ///     c.value_raw()
    /// };
    ///
    /// assert_eq!(value, Some("bar"));
    /// ```
    #[inline]
    pub fn value_raw(&self) -> Option<&'c str> {
        self.cookie_string.as_ref()
            .and_then(|s| self.value.to_raw_str(s))
    }

    /// Returns the `Path` of `self` as a string slice of the raw string `self`
    /// was originally parsed from. If `self` was not originally parsed from a
    /// raw string, or if `self` doesn't contain a `Path`, or if the `Path` has
    /// changed since parsing, returns `None`.
    ///
    /// This method differs from [`Cookie::path()`] in that it returns a
    /// string with the same lifetime as the originally parsed string. This
    /// lifetime may outlive `self`. If a longer lifetime is not required, or
    /// you're unsure if you need a longer lifetime, use [`Cookie::path()`].
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let cookie_string = format!("{}={}; Path=/", "foo", "bar");
    ///
    /// // `c` will be dropped at the end of the scope, but `path` will live on
    /// let path = {
    ///     let c = Cookie::parse(cookie_string.as_str()).unwrap();
    ///     c.path_raw()
    /// };
    ///
    /// assert_eq!(path, Some("/"));
    /// ```
    #[inline]
    pub fn path_raw(&self) -> Option<&'c str> {
        match (self.path.as_ref(), self.cookie_string.as_ref()) {
            (Some(path), Some(string)) => path.to_raw_str(string),
            _ => None,
        }
    }

    /// Returns the `Domain` of `self` as a string slice of the raw string
    /// `self` was originally parsed from. If `self` was not originally parsed
    /// from a raw string, or if `self` doesn't contain a `Domain`, or if the
    /// `Domain` has changed since parsing, returns `None`.
    ///
    /// Like [`Cookie::domain()`], this does not consider whether `Domain` is
    /// valid; validation is left to higher-level libraries, as needed. Unlike
    /// [`Cookie::domain()`] (but like [`Cookie::domain_verbatim()`]), this
    /// method **_does not_** remove a leading `.` if present. Callers may want
    /// to remove the leading prefix:
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let cookie_string = format!("{}={}; Domain=.crates.io", "foo", "bar");
    /// let c = Cookie::parse(cookie_string.as_str()).unwrap();
    /// assert_eq!(c.domain_raw(), Some(".crates.io"));
    /// assert_eq!(c.domain_verbatim(), Some(".crates.io"));
    /// assert_eq!(c.domain(), Some("crates.io"));
    ///
    /// let domain_raw = c.domain_raw();
    /// let domain = domain_raw.and_then(|d| d.strip_prefix('.')).or(domain_raw);
    /// assert_eq!(domain, Some("crates.io"));
    /// ```
    ///
    /// This method also differs from [`Cookie::domain()`] and
    /// [`Cookie::domain_verbatim()`] in that it returns a string with the same
    /// lifetime as the originally parsed string, and only returns `Some` if
    /// `Domain` has not changed since creation. This lifetime may outlive
    /// `self`. If a longer lifetime is not required, or you're unsure if you
    /// need a longer lifetime, use [`Cookie::domain()`].
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let cookie_string = format!("{}={}; Domain=.crates.io", "foo", "bar");
    ///
    /// //`c` will be dropped at the end of the scope, but `domain` will live on
    /// let domain = {
    ///     let c = Cookie::parse(cookie_string.as_str()).unwrap();
    ///     c.domain_raw()
    /// };
    ///
    /// assert_eq!(domain, Some(".crates.io"));
    /// ```
    #[inline]
    pub fn domain_raw(&self) -> Option<&'c str> {
        match (self.domain.as_ref(), self.cookie_string.as_ref()) {
            (Some(domain), Some(string)) => domain.to_raw_str(string),
            _ => None,
        }
    }

    /// Returns the `Domain` of the cookie if one was specified, exactly as
    /// currently stored.
    ///
    /// Like [`Cookie::domain()`], this does not consider whether the `Domain`
    /// is valid; validation is left to higher-level libraries.
    ///
    /// Unlike [`Cookie::domain()`], this method _*does not*_ strip a leading
    /// `.` from `Domain`. Always prefer using [`Cookie::domain()`].
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let mut c = Cookie::parse("name=value; Domain=.crates.io").unwrap();
    /// assert_eq!(c.domain(), Some("crates.io"));
    /// assert_eq!(c.domain_verbatim(), Some(".crates.io"));
    /// assert_eq!(c.domain_raw(), Some(".crates.io"));
    ///
    /// c.set_domain(".rust-lang.org");
    /// assert_eq!(c.domain(), Some("rust-lang.org"));
    /// assert_eq!(c.domain_verbatim(), Some(".rust-lang.org"));
    /// assert_eq!(c.domain_raw(), None);
    /// ```
    #[inline]
    pub fn domain_verbatim(&self) -> Option<&str> {
        match self.domain {
            Some(ref c) => Some(c.to_str(self.cookie_string.as_ref())),
            None => None,
        }
    }

    /// Wraps `self` in an encoded [`Display`]: a cost-free wrapper around
    /// `Cookie` whose [`fmt::Display`] implementation percent-encodes the name
    /// and value of the wrapped `Cookie`.
    ///
    /// This is the safe way to write a `Cookie`. No name or value, regardless
    /// of its contents, can alter the attributes of the written cookie.
    ///
    /// **Note:** A cookie written with this method must be read with
    /// [`Cookie::parse_encoded()`] or [`Cookie::split_parse_encoded()`]. If it
    /// is read with [`Cookie::parse()`], [`Cookie::split_parse()`], or
    /// [`str::parse()`] instead, its name and value remain percent-encoded. As
    /// such, a signed or private cookie read in this manner can fail to verify
    /// or decrypt.
    ///
    /// **Note:** The `Domain` is written as returned by [`Cookie::domain()`]:
    /// without a leading `.`. As such, a cookie with an invalid `Domain`, such
    /// as `..crates.io`, may be parsed back with a different `Domain`.
    ///
    /// The returned structure can be chained with [`Display::stripped()`] to
    /// display only the name and value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::Cookie;
    ///
    /// let mut c = Cookie::build(("my name", "this; value?")).secure(true).build();
    /// assert_eq!(&c.encoded().to_string(), "my%20name=this%3B%20value%3F; Secure");
    /// assert_eq!(&c.encoded().stripped().to_string(), "my%20name=this%3B%20value%3F");
    ///
    /// // The `Domain` is written without a leading `.`.
    /// let c = Cookie::build(("name", "value")).domain(".crates.io").build();
    /// assert_eq!(&c.encoded().to_string(), "name=value; Domain=crates.io");
    /// ```
    #[cfg(feature = "percent-encode")]
    #[cfg_attr(all(nightly, doc), doc(cfg(feature = "percent-encode")))]
    #[inline(always)]
    pub fn encoded<'a>(&'a self) -> Display<'a, 'c> {
        Display::new_encoded(self)
    }

    /// Wraps `self` in an unescaped [`Display`]: a cost-free wrapper around
    /// `Cookie` whose [`fmt::Display`] implementation writes the name and value
    /// of the wrapped `Cookie` exactly as they are, without any encoding or
    /// escaping.
    ///
    /// **Warning:** This method is dangerous! A `;` or control character in the
    /// name or value is written as-is. As such, if any part of the name or
    /// value is derived from untrusted input, an attacker can inject cookie
    /// attributes of their choosing, including `Domain`, `Path`, and `Max-Age`,
    /// into the written cookie. Always prefer using [`Cookie::encoded()`].
    ///
    /// This method _does **not**_ validate the name or value in any way. It is
    /// only safe to use when the name and value are known to contain neither a
    /// `;` nor a control character. This is _not_ the case for a signed cookie:
    /// the value of a signed cookie contains the original value, as-is. If
    /// you're unsure whether the name and value are safe, or you're unsure if
    /// you need this method, use [`Cookie::encoded()`].
    ///
    /// A cookie written with this method should be read with
    /// [`Cookie::parse()`] or [`Cookie::split_parse()`]. If it is read with
    /// [`Cookie::parse_encoded()`] or [`Cookie::split_parse_encoded()`]
    /// instead, a `%` followed by two hexadecimal digits in its name or value,
    /// such as `%25`, is decoded. As such, a signed cookie read in this manner
    /// can fail to verify.
    ///
    /// As with [`Cookie::encoded()`], the `Domain` is written without a leading
    /// `.`.
    ///
    /// The returned structure can be chained with [`Display::stripped()`] to
    /// display only the name and value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::Cookie;
    ///
    /// let c = Cookie::build(("name", "dmFsdWU=")).secure(true).build();
    /// assert_eq!(&c.unescaped().to_string(), "name=dmFsdWU=; Secure");
    /// assert_eq!(&c.unescaped().stripped().to_string(), "name=dmFsdWU=");
    ///
    /// // Nothing is escaped! This value injects a `Domain` attribute.
    /// let c = Cookie::new("name", "value; Domain=crates.io");
    /// assert_eq!(&c.unescaped().to_string(), "name=value; Domain=crates.io");
    ///
    /// let parsed = Cookie::parse(c.unescaped().to_string()).unwrap();
    /// assert_eq!(parsed.value(), "value");
    /// assert_eq!(parsed.domain(), Some("crates.io"));
    #[cfg_attr(feature = "percent-encode", doc = r##"
// Note: `encoded()` is only available when `percent-encode` is enabled.
assert_eq!(&c.encoded().to_string(), "name=value%3B%20Domain%3Dcrates.io");
"##)]
    /// ```
    #[inline(always)]
    pub fn unescaped<'a>(&'a self) -> Display<'a, 'c> {
        Display::new_unescaped(self)
    }
}

/// An iterator over cookie parse `Result`s: `Result<Cookie, ParseError>`.
///
/// Returned by [`Cookie::split_parse()`] and [`Cookie::split_parse_encoded()`].
pub struct SplitCookies<'c> {
    // The source string, which we split and parse.
    string: Cow<'c, str>,
    // The index where we last split off.
    last: usize,
    // Whether we should percent-decode when parsing.
    decode: bool,
}

impl<'c> Iterator for SplitCookies<'c> {
    type Item = Result<Cookie<'c>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.last < self.string.len() {
            let i = self.last;
            let j = self.string[i..]
                .find(';')
                .map(|k| i + k)
                .unwrap_or(self.string.len());

            self.last = j + 1;
            if trim(&self.string[i..j]).is_empty() {
                continue;
            }

            return Some(match self.string {
                Cow::Borrowed(s) => parse_cookie(trim(&s[i..j]), self.decode),
                Cow::Owned(ref s) => parse_cookie(trim(&s[i..j]).to_owned(), self.decode),
            })
        }

        None
    }
}

#[cfg(feature = "percent-encode")]
mod encoding {
    use percent_encoding::{AsciiSet, CONTROLS};

    /// https://url.spec.whatwg.org/#fragment-percent-encode-set
    const FRAGMENT: &AsciiSet = &CONTROLS
        .add(b' ')
        .add(b'"')
        .add(b'<')
        .add(b'>')
        .add(b'`');

    /// https://url.spec.whatwg.org/#path-percent-encode-set
    const PATH: &AsciiSet = &FRAGMENT
        .add(b'#')
        .add(b'?')
        .add(b'{')
        .add(b'}');

    /// https://url.spec.whatwg.org/#userinfo-percent-encode-set
    const USERINFO: &AsciiSet = &PATH
        .add(b'/')
        .add(b':')
        .add(b';')
        .add(b'=')
        .add(b'@')
        .add(b'[')
        .add(b'\\')
        .add(b']')
        .add(b'^')
        .add(b'|')
        .add(b'%');

    /// https://www.rfc-editor.org/rfc/rfc6265#section-4.1.1 + '(', ')'
    const COOKIE: &AsciiSet = &USERINFO
        .add(b'(')
        .add(b')')
        .add(b',');

    /// Percent-encode a cookie name or value with the proper encoding set.
    pub fn encode(string: &str) -> impl std::fmt::Display + '_ {
        percent_encoding::percent_encode(string.as_bytes(), COOKIE)
    }
}

/// Wrapper around `Cookie` whose `Display` implementation writes the cookie as
/// a `Set-Cookie` header value, either percent-encoding the cookie's name and
/// value or writing them as-is, and optionally skipping the cookie's parameters
/// (only displaying its name and value).
///
/// A value of this type can be obtained via [`Cookie::encoded()`] and
/// [`Cookie::unescaped()`], either of which can be chained with
/// [`Display::stripped()`]. This type should only be used for its `Display`
/// implementation.
///
/// # Example
///
/// ```rust
/// use cookie::Cookie;
///
/// let c = Cookie::build(("my name", "this; value%?")).secure(true).build();
/// assert_eq!(&c.unescaped().to_string(), "my name=this; value%?; Secure");
/// assert_eq!(&c.unescaped().stripped().to_string(), "my name=this; value%?");
#[cfg_attr(feature = "percent-encode", doc = r##"
// Note: `encoded()` is only available when `percent-encode` is enabled.
assert_eq!(&c.encoded().to_string(), "my%20name=this%3B%20value%25%3F; Secure");
assert_eq!(&c.encoded().stripped().to_string(), "my%20name=this%3B%20value%25%3F");
"##)]
/// ```
pub struct Display<'a, 'c: 'a> {
    cookie: &'a Cookie<'c>,
    #[cfg(feature = "percent-encode")]
    encode: bool,
    strip: bool,
}

impl<'a, 'c: 'a> fmt::Display for Display<'a, 'c> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        #[cfg(feature = "percent-encode")] {
            if self.encode {
                let name = encoding::encode(self.cookie.name());
                let value = encoding::encode(self.cookie.value());
                write!(f, "{}={}", name, value)?;
            } else {
                write!(f, "{}={}", self.cookie.name(), self.cookie.value())?;
            }
        }

        #[cfg(not(feature = "percent-encode"))] {
            write!(f, "{}={}", self.cookie.name(), self.cookie.value())?;
        }

        match self.strip {
            true => Ok(()),
            false => self.cookie.fmt_parameters(f)
        }
    }
}

impl<'a, 'c> Display<'a, 'c> {
    #[cfg(feature = "percent-encode")]
    fn new_encoded(cookie: &'a Cookie<'c>) -> Self {
        Display { cookie, strip: false, encode: true }
    }

    fn new_unescaped(cookie: &'a Cookie<'c>) -> Self {
        Display { cookie, strip: false, #[cfg(feature = "percent-encode")] encode: false }
    }

    /// Only display the name and value.
    #[inline]
    pub fn stripped(mut self) -> Self {
        self.strip = true;
        self
    }
}

/// Parses a `Cookie` via [`Cookie::parse()`].
///
/// **Note:** This _does **not**_ perform any percent-decoding. To parse a
/// cookie written with [`Cookie::encoded()`], use [`Cookie::parse_encoded()`].
///
/// # Example
///
/// ```rust
/// use cookie::Cookie;
///
/// let c: Cookie = "name=value%20here; HttpOnly".parse().unwrap();
/// assert_eq!(c.name_value(), ("name", "value%20here"));
/// assert_eq!(c.http_only(), Some(true));
/// ```
impl FromStr for Cookie<'static> {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Cookie<'static>, ParseError> {
        Cookie::parse(s).map(|c| c.into_owned())
    }
}

impl<'a, 'b> PartialEq<Cookie<'b>> for Cookie<'a> {
    fn eq(&self, other: &Cookie<'b>) -> bool {
        let so_far_so_good = self.name() == other.name()
            && self.value() == other.value()
            && self.http_only() == other.http_only()
            && self.secure() == other.secure()
            && self.partitioned() == other.partitioned()
            && self.same_site() == other.same_site()
            && self.max_age() == other.max_age()
            && self.expires() == other.expires();

        if !so_far_so_good {
            return false;
        }

        match (self.path(), other.path()) {
            (Some(a), Some(b)) if a.eq_ignore_ascii_case(b) => {}
            (None, None) => {}
            _ => return false,
        };

        match (self.domain(), other.domain()) {
            (Some(a), Some(b)) if a.eq_ignore_ascii_case(b) => {}
            (None, None) => {}
            _ => return false,
        };

        true
    }
}

impl<'a> From<&'a str> for Cookie<'a> {
    fn from(name: &'a str) -> Self {
        Cookie::new(name, "")
    }
}

impl From<String> for Cookie<'static> {
    fn from(name: String) -> Self {
        Cookie::new(name, "")
    }
}

impl<'a> From<Cow<'a, str>> for Cookie<'a> {
    fn from(name: Cow<'a, str>) -> Self {
        Cookie::new(name, "")
    }
}

impl<'a, N, V> From<(N, V)> for Cookie<'a>
    where N: Into<Cow<'a, str>>,
          V: Into<Cow<'a, str>>
{
    fn from((name, value): (N, V)) -> Self {
        Cookie::new(name, value)
    }
}

impl<'a> From<CookieBuilder<'a>> for Cookie<'a> {
    fn from(builder: CookieBuilder<'a>) -> Self {
        builder.build()
    }
}

impl<'a> AsRef<Cookie<'a>> for Cookie<'a> {
    fn as_ref(&self) -> &Cookie<'a> {
        self
    }
}

impl<'a> AsMut<Cookie<'a>> for Cookie<'a> {
    fn as_mut(&mut self) -> &mut Cookie<'a> {
        self
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};
    use crate::{Cookie, ParseError, SameSite};

    #[test]
    fn format() {
        let cookie = Cookie::new("foo", "bar");
        assert_eq!(&cookie.unescaped().to_string(), "foo=bar");

        let cookie = Cookie::build(("foo", "bar")).http_only(true).build();
        assert_eq!(&cookie.unescaped().to_string(), "foo=bar; HttpOnly");

        let cookie = Cookie::build(("foo", "bar")).max_age(Duration::from_secs(10)).build();
        assert_eq!(&cookie.unescaped().to_string(), "foo=bar; Max-Age=10");

        let cookie = Cookie::build(("foo", "bar")).secure(true).build();
        assert_eq!(&cookie.unescaped().to_string(), "foo=bar; Secure");

        let cookie = Cookie::build(("foo", "bar")).path("/").build();
        assert_eq!(&cookie.unescaped().to_string(), "foo=bar; Path=/");

        let cookie = Cookie::build(("foo", "bar")).domain("www.rust-lang.org").build();
        assert_eq!(&cookie.unescaped().to_string(), "foo=bar; Domain=www.rust-lang.org");

        let cookie = Cookie::build(("foo", "bar")).domain(".rust-lang.org").build();
        assert_eq!(&cookie.unescaped().to_string(), "foo=bar; Domain=rust-lang.org");

        let cookie = Cookie::build(("foo", "bar")).domain("rust-lang.org").build();
        assert_eq!(&cookie.unescaped().to_string(), "foo=bar; Domain=rust-lang.org");

        let expires = SystemTime::UNIX_EPOCH + Duration::from_secs(1445412480);
        let cookie = Cookie::build(("foo", "bar")).expires(expires).build();
        assert_eq!(&cookie.unescaped().to_string(),
                   "foo=bar; Expires=Wed, 21 Oct 2015 07:28:00 GMT");

        let cookie = Cookie::build(("foo", "bar")).same_site(SameSite::Strict).build();
        assert_eq!(&cookie.unescaped().to_string(), "foo=bar; SameSite=Strict");

        let cookie = Cookie::build(("foo", "bar")).same_site(SameSite::Lax).build();
        assert_eq!(&cookie.unescaped().to_string(), "foo=bar; SameSite=Lax");

        let mut cookie = Cookie::build(("foo", "bar")).same_site(SameSite::None).build();
        assert_eq!(&cookie.unescaped().to_string(), "foo=bar; SameSite=None; Secure");

        cookie.set_partitioned(true);
        assert_eq!(&cookie.unescaped().to_string(), "foo=bar; SameSite=None; Partitioned; Secure");

        cookie.set_same_site(None);
        assert_eq!(&cookie.unescaped().to_string(), "foo=bar; Partitioned; Secure");

        cookie.set_secure(false);
        assert_eq!(&cookie.unescaped().to_string(), "foo=bar; Partitioned; Secure");

        cookie.set_secure(None);
        assert_eq!(&cookie.unescaped().to_string(), "foo=bar; Partitioned; Secure");

        cookie.set_partitioned(None);
        assert_eq!(&cookie.unescaped().to_string(), "foo=bar");

        let mut c = Cookie::build(("foo", "bar")).same_site(SameSite::None).secure(false).build();
        assert_eq!(&c.unescaped().to_string(), "foo=bar; SameSite=None");
        c.set_secure(true);
        assert_eq!(&c.unescaped().to_string(), "foo=bar; SameSite=None; Secure");
    }

    #[test]
    fn attributes_truncated() {
        let cases = [
            ("/", "/"),
            ("", ""),
            ("/a b/c", "/a b/c"),
            ("/app; Domain=evil.example", "/app"),
            ("/app;v=2/x", "/app"),
            (";", ""),
            ("/a\r\nSet-Cookie: admin=1", "/a"),
            ("/a\nb", "/a"),
            ("/a\tb", "/a"),
            ("/a\0b", "/a"),
            ("/a\x7fb", "/a"),
            ("/caf\u{e9}; Secure", "/caf\u{e9}"),
        ];

        for (input, expected) in cases {
            let mut c = Cookie::new("foo", "bar");
            c.set_path(input);
            assert_eq!(c.path(), Some(expected), "borrowed {:?}", input);

            c.set_path(input.to_string());
            assert_eq!(c.path(), Some(expected), "owned {:?}", input);

            c.set_domain(input);
            assert_eq!(c.domain_verbatim(), Some(expected), "borrowed {:?}", input);

            c.set_domain(input.to_string());
            assert_eq!(c.domain_verbatim(), Some(expected), "owned {:?}", input);

            let c = Cookie::build(("foo", "bar")).path(input).domain(input).build();
            assert_eq!(c.path(), Some(expected), "builder {:?}", input);
            assert_eq!(c.domain_verbatim(), Some(expected), "builder {:?}", input);
        }
    }

    #[test]
    fn attributes_cannot_inject() {
        let c = Cookie::build(("sid", "abc"))
            .path("/app; Domain=evil.example; SameSite=None")
            .domain("example.com; Path=/; Max-Age=999999")
            .build();

        let string = c.unescaped().to_string();
        assert_eq!(string, "sid=abc; Path=/app; Domain=example.com");

        let parsed = Cookie::parse(string).unwrap();
        assert_eq!(parsed.path(), Some("/app"));
        assert_eq!(parsed.domain(), Some("example.com"));
        assert_eq!(parsed.same_site(), None);
        assert_eq!(parsed.max_age(), None);

        let c = Cookie::build(("sid", "abc")).path("/a\r\nSet-Cookie: admin=1").build();
        assert_eq!(c.unescaped().to_string(), "sid=abc; Path=/a");
    }

    #[test]
    fn format_removal() {
        let mut c = Cookie::build(("foo", "bar")).path("/").build();
        c.make_removal();

        let expected = "foo=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT";
        assert_eq!(c.unescaped().to_string(), expected);
    }

    #[test]
    fn make_permanent() {
        let twenty_years = Duration::from_secs(20 * 365 * 24 * 60 * 60);

        let before = SystemTime::now();
        let mut c = Cookie::new("foo", "bar");
        c.make_permanent();
        let after = SystemTime::now();

        // The cookie expires twenty years from when it was made permanent.
        let expires = c.expires_datetime().unwrap();
        assert_eq!(c.max_age(), Some(twenty_years));
        assert!(expires >= before + twenty_years);
        assert!(expires <= after + twenty_years);

        let c = Cookie::build(("foo", "bar")).permanent().build();
        assert_eq!(c.max_age(), Some(twenty_years));
        assert!(c.expires_datetime().unwrap() >= after + twenty_years);
    }

    #[test]
    fn format_stripped() {
        let c = Cookie::build(("foo", "bar")).path("/").secure(true).build();
        assert_eq!(c.unescaped().stripped().to_string(), "foo=bar");
        assert_eq!(c.unescaped().to_string(), "foo=bar; Secure; Path=/");
    }

    #[test]
    fn unescaped_is_not_escaped() {
        let c = Cookie::new("name", "value; Max-Age=86400; Domain=evil.example");
        let string = c.unescaped().to_string();
        assert_eq!(string, "name=value; Max-Age=86400; Domain=evil.example");

        let parsed = Cookie::parse(string).unwrap();
        assert_eq!(parsed.value(), "value");
        assert_eq!(parsed.max_age(), Some(Duration::from_secs(86400)));
        assert_eq!(parsed.domain(), Some("evil.example"));
    }

    #[test]
    #[cfg(feature = "percent-encode")]
    fn encoded_cannot_inject() {
        let values = [
            "value; Max-Age=86400; Domain=evil.example",
            "x\r\nSet-Cookie: admin=1",
            "a=b; Secure",
            "\0\x7f;",
        ];

        for value in values {
            let c = Cookie::build((value, value)).path("/").build();
            let string = c.encoded().to_string();
            assert!(!string.contains(|c: char| c.is_ascii_control()), "{:?}", string);
            assert_eq!(string.matches(';').count(), 1, "{:?}", string);
            assert!(string.ends_with("; Path=/"), "{:?}", string);

            let parsed = Cookie::parse_encoded(string).unwrap();
            assert_eq!(parsed.name_value(), (value, value));
            assert_eq!(parsed.path(), Some("/"));
            assert_eq!(parsed.domain(), None);
            assert_eq!(parsed.max_age(), None);
            assert_eq!(parsed.secure(), None);

            let stripped = c.encoded().stripped().to_string();
            assert!(!stripped.contains(';'), "{:?}", stripped);
        }
    }

    #[test]
    fn format_date_wraps() {
        // Dec 31, 9999, 23:59:59 UTC.
        let max = SystemTime::UNIX_EPOCH + Duration::from_secs(253402300799);
        let expected = "foo=bar; Expires=Fri, 31 Dec 9999 23:59:59 GMT";

        for extra in [0, 1, 1000 * 24 * 60 * 60, 1 << 40] {
            // Not every platform can represent every date.
            let Some(expires) = max.checked_add(Duration::from_secs(extra)) else { continue };
            let cookie = Cookie::build(("foo", "bar")).expires(expires).build();
            assert_eq!(cookie.expires_datetime(), Some(max));
            assert_eq!(&cookie.unescaped().to_string(), expected);
        }

        let mut cookie = Cookie::new("foo", "bar");
        cookie.set_max_age(Duration::MAX);
        assert_eq!(cookie.unescaped().to_string(), format!("foo=bar; Max-Age={}", i64::MAX));

        cookie.set_max_age(Duration::from_secs(i64::MAX as u64));
        assert_eq!(cookie.unescaped().to_string(), format!("foo=bar; Max-Age={}", i64::MAX));

        cookie.set_max_age(Duration::from_secs(i64::MAX as u64 - 1));
        assert_eq!(cookie.unescaped().to_string(), format!("foo=bar; Max-Age={}", i64::MAX - 1));
    }

    #[test]
    fn format_date_before_epoch() {
        let expected = "foo=bar; Expires=Thu, 01 Jan 1970 00:00:00 GMT";
        for secs in [0, 1, 365 * 24 * 60 * 60, 11_644_473_600, 60_589_296_000, 1 << 40] {
            // Not every platform can represent dates before the Unix epoch.
            let before = Duration::from_secs(secs);
            let Some(expires) = SystemTime::UNIX_EPOCH.checked_sub(before) else { continue };
            let cookie = Cookie::build(("foo", "bar")).expires(expires).build();
            assert_eq!(cookie.expires_datetime(), Some(expires));
            assert_eq!(&cookie.unescaped().to_string(), expected);

            let parsed = Cookie::parse(expected).unwrap();
            assert_eq!(parsed.expires_datetime(), Some(SystemTime::UNIX_EPOCH));
        }

        // A date before the Unix epoch is read but is written as the epoch.
        let cookie = Cookie::parse("foo=bar; Expires=Fri, 01 Jan 1965 00:00:00 GMT").unwrap();
        assert!(cookie.expires_datetime().is_some_and(|t| t <= SystemTime::UNIX_EPOCH));
        assert_eq!(&cookie.unescaped().to_string(), expected);
    }

    #[test]
    fn cookie_string_long_lifetimes() {
        let cookie_string = "bar=baz; Path=/subdir; HttpOnly; Domain=crates.io".to_owned();
        let (name, value, path, domain) = {
            // Create a cookie passing a slice
            let c = Cookie::parse(cookie_string.as_str()).unwrap();
            (c.name_raw(), c.value_raw(), c.path_raw(), c.domain_raw())
        };

        assert_eq!(name, Some("bar"));
        assert_eq!(value, Some("baz"));
        assert_eq!(path, Some("/subdir"));
        assert_eq!(domain, Some("crates.io"));
    }

    #[test]
    fn domain_accessors() {
        let mut c = Cookie::parse("bar=baz; Domain=.crates.io").unwrap();
        assert_eq!(c.domain(), Some("crates.io"));
        assert_eq!(c.domain_verbatim(), Some(".crates.io"));
        assert_eq!(c.domain_raw(), Some(".crates.io"));

        c.set_domain(".rust-lang.org");
        assert_eq!(c.domain(), Some("rust-lang.org"));
        assert_eq!(c.domain_verbatim(), Some(".rust-lang.org"));
        assert_eq!(c.domain_raw(), None);
    }

    #[test]
    fn owned_cookie_string() {
        let cookie_string = "bar=baz; Path=/subdir; HttpOnly; Domain=crates.io".to_owned();
        let (name, value, path, domain) = {
            // Create a cookie passing an owned string
            let c = Cookie::parse(cookie_string).unwrap();
            (c.name_raw(), c.value_raw(), c.path_raw(), c.domain_raw())
        };

        assert_eq!(name, None);
        assert_eq!(value, None);
        assert_eq!(path, None);
        assert_eq!(domain, None);
    }

    #[test]
    fn owned_cookie_struct() {
        let cookie_string = "bar=baz; Path=/subdir; HttpOnly; Domain=crates.io";
        let (name, value, path, domain) = {
            // Create an owned cookie
            let c = Cookie::parse(cookie_string).unwrap().into_owned();

            (c.name_raw(), c.value_raw(), c.path_raw(), c.domain_raw())
        };

        assert_eq!(name, None);
        assert_eq!(value, None);
        assert_eq!(path, None);
        assert_eq!(domain, None);
    }

    #[test]
    #[cfg(feature = "percent-encode")]
    fn format_encoded() {
        let cookie = Cookie::new("foo !%?=", "bar;;, a");
        let cookie_str = cookie.encoded().to_string();
        assert_eq!(&cookie_str, "foo%20!%25%3F%3D=bar%3B%3B%2C%20a");

        let cookie = Cookie::parse_encoded(cookie_str).unwrap();
        assert_eq!(cookie.name_value(), ("foo !%?=", "bar;;, a"));
    }

    #[test]
    #[cfg(feature = "percent-encode")]
    fn format_encoded_characters() {
        // The characters of an RFC 2616 `token`, sans the `%`. RFC 6265 allows
        // these, and only these, in both a name and a value.
        let is_allowed = |c: char| {
            c.is_ascii_alphanumeric() || "!#$&'*+-.^_`|~".contains(c)
        };

        // Of those, we encode `#`, `^`, `` ` ``, and `|` as well.
        let is_written = |c: char| is_allowed(c) && !"#^`|".contains(c);

        for c in (0..128u8).map(char::from) {
            let string = c.to_string();
            let cookie = Cookie::new(string.clone(), string.clone());
            let written = cookie.encoded().to_string();
            let expected = match is_written(c) {
                true => format!("{0}={0}", c),
                false => format!("%{0:02X}=%{0:02X}", c as u8),
            };

            assert_eq!(written, expected, "{:?}", c);
            assert!(written.chars().all(|c| is_allowed(c) || "%=".contains(c)));

            let cookie = Cookie::parse_encoded(written).unwrap();
            assert_eq!(cookie.name_value(), (&*string, &*string), "{:?}", c);
        }
    }

    #[test]
    fn split_parse() {
        let cases = [
            ("", vec![]),
            (";;", vec![]),
            ("name=value", vec![("name", "value")]),
            ("a=%20", vec![("a", "%20")]),
            ("a=d#$%^&*()_", vec![("a", "d#$%^&*()_")]),
            ("  name=value  ", vec![("name", "value")]),
            ("name=value  ", vec![("name", "value")]),
            ("name=value;;other=key", vec![("name", "value"), ("other", "key")]),
            ("name=value;  ;other=key", vec![("name", "value"), ("other", "key")]),
            ("name=value ;  ;other=key", vec![("name", "value"), ("other", "key")]),
            ("name=value ;  ; other=key", vec![("name", "value"), ("other", "key")]),
            ("name=value ;  ; other=key ", vec![("name", "value"), ("other", "key")]),
            ("name=value ;  ; other=key;; ", vec![("name", "value"), ("other", "key")]),
            (";name=value ;  ; other=key ", vec![("name", "value"), ("other", "key")]),
            (";a=1 ;  ; b=2 ", vec![("a", "1"), ("b", "2")]),
            (";a=1 ;  ; b= ", vec![("a", "1"), ("b", "")]),
            (";a=1 ;  ; =v ; c=", vec![("a", "1"), ("c", "")]),
            (" ;   a=1 ;  ; =v ; ;;c=", vec![("a", "1"), ("c", "")]),
            (" ;   a=1 ;  ; =v ; ;;c===  ", vec![("a", "1"), ("c", "==")]),
        ];

        for (string, expected) in cases {
            let actual: Vec<_> = Cookie::split_parse(string)
                .filter_map(|parse| parse.ok())
                .map(|c| (c.name_raw().unwrap(), c.value_raw().unwrap()))
                .collect();

            assert_eq!(expected, actual);
        }
    }

    #[test]
    fn split_parse_whitespace() {
        // Only spaces and horizontal tabs are whitespace.
        let string = " \t a=1 \t ; \t ; \t b=2 \t ";
        let cookies: Vec<_> = Cookie::split_parse(string).collect();
        let expected = [Ok(Cookie::new("a", "1")), Ok(Cookie::new("b", "2"))];
        assert_eq!(cookies, expected);

        for space in ['\u{85}', '\u{a0}', '\u{2003}', '\u{2028}', '\u{3000}'] {
            let string = format!("a=1;{0}b=2{0};{0}; c=3", space);
            let b = Cookie::new(format!("{0}b", space), format!("2{0}", space));
            let expected = [
                Ok(Cookie::new("a", "1")),
                Ok(b),
                Err(ParseError::MissingPair),
                Ok(Cookie::new("c", "3")),
            ];

            // Check both a borrowed and an owned string.
            let borrowed = Cookie::split_parse(&*string).collect::<Vec<_>>();
            let owned = Cookie::split_parse(string.clone()).collect::<Vec<_>>();
            assert_eq!(borrowed, expected);
            assert_eq!(owned, expected);
        }
    }

    #[test]
    #[cfg(feature = "percent-encode")]
    fn split_parse_encoded() {
        let cases = [
            ("", vec![]),
            (";;", vec![]),
            ("name=val%20ue", vec![("name", "val ue")]),
            ("foo%20!%25%3F%3D=bar%3B%3B%2C%20a", vec![("foo !%?=", "bar;;, a")]),
            (
                "name=val%20ue ; ; foo%20!%25%3F%3D=bar%3B%3B%2C%20a",
                vec![("name", "val ue"), ("foo !%?=", "bar;;, a")]
            ),
        ];

        for (string, expected) in cases {
            let cookies: Vec<_> = Cookie::split_parse_encoded(string)
                .filter_map(|parse| parse.ok())
                .collect();

            let actual: Vec<_> = cookies.iter()
                .map(|c| c.name_value())
                .collect();

            assert_eq!(expected, actual);
        }
    }
}
