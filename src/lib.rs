// #![deny(missing_docs)]
// #![cfg_attr(test, deny(warnings))]

//! HTTP Cookie parsing and Cookie Jar management.
//!
//! This crates provides the [Cookie](struct.Cookie.html) type, which directly
//! maps to an HTTP cookie, and the [CookieJar](struct.CookieJar.html) type,
//! which allows for simple management of many cookies as well as encryption and
//! signing of cookies for session management.
//!
//! # Usage
//!
//! Add the following to the `[dependencies]` section of your `Cargo.toml`:
//!
//! ```ignore
//! cookie = "0.6"
//! ```
//!
//! Then add the following line to your crate root:
//!
//! ```ignore
//! extern crate cookie;
//! ```
//!
//! # Features
//!
//! This crates can be configured at compile-time through the following Cargo
//! features:
//!
//!
//! * **secure** (enabled by default)
//!
//!   Enables signing and encryption of cookies.
//!
//!   When this feature is enabled, signed and encrypted cookies jars will
//!   encrypt and/or sign any cookies added to them. When this feature is
//!   disabled, those cookies will be added in plaintext.
//!
//! * **percent-encode** (disabled by default)
//!
//!   Enables percent encoding and decoding of names and values in cookies.
//!
//!   When this feature is enabled, cookie name and values will be
//!   percent-encoded when `to_string` is called on a `Cookie` and
//!   percent-decoded when a cookie is parsed using `parse` or `parse_static`.
//!   When this feature is disabled, cookie names and values will not be
//!   modified in any way.
//!
//! You can enable features via the `Cargo.toml` file:
//!
//! ```ignore
//! [dependencies.cookie]
//! features = ["secure", "percent-encode"]
//! ```

extern crate time;
#[cfg(feature = "percent-encode")]
extern crate url;

mod builder;
mod jar;
mod parse;

use std::borrow::Cow;
use std::ascii::AsciiExt;
use std::fmt;
use std::str::FromStr;

use time::{Tm, Duration};
#[cfg(feature = "percent-encode")]
use url::percent_encoding::{USERINFO_ENCODE_SET, percent_encode};

use parse::parse_cookie;
pub use parse::ParseError;

pub use builder::CookieBuilder;
pub use jar::CookieJar;

#[derive(Debug, Clone)]
enum CookieStr {
    /// An string derived from indexes (start, end).
    Indexed(usize, usize),
    /// A string derived from a concrete string.
    Concrete(Cow<'static, str>),
}

impl CookieStr {
    /// Whether this string is derived from indexes or not.
    pub fn is_indexed(&self) -> bool {
        match *self {
            CookieStr::Indexed(..) => true,
            CookieStr::Concrete(..) => false,
        }
    }

    /// Retrieves the string `self` corresponds to. If `self` is derived from
    /// indexes, the corresponding subslice of `string` is returned. Otherwise,
    /// the concrete string is returned.
    ///
    /// # Panics
    ///
    /// Panics if `self` is an indexed string and `string` is None.
    pub fn to_str<'s>(&'s self, string: Option<&'s Cow<str>>) -> &'s str {
        if self.is_indexed() && string.is_none() {
            panic!("Cannot convert indexed str to str without base string!")
        }

        match *self {
            CookieStr::Indexed(i, j) => &string.unwrap()[i..j],
            CookieStr::Concrete(ref cstr) => &*cstr,
        }
    }
}

/// Representation of an HTTP cookie.
///
/// # Constructing a `Cookie`
///
/// To construct a cookie with only a name/value, use the [new](#method.new)
/// method:
///
/// ```rust
/// use cookie::Cookie;
///
/// let cookie = Cookie::new("name", "value");
/// assert_eq!(&cookie.to_string(), "name=value");
/// ```
///
/// To construct more elaborate cookies, use the [build](#method.build) method
/// and [CookieBuilder](struct.CookieBuilder.html) methods:
///
/// ```rust
/// use cookie::Cookie;
///
/// let cookie = Cookie::build("name", "value")
///     .domain("www.rust-lang.org")
///     .path("/")
///     .secure(true)
///     .http_only(true)
///     .finish();
/// ```
#[derive(Debug, Clone)]
pub struct Cookie<'c> {
    /// Storage for the cookie string. Only used if this structure was derived
    /// from a string that was subsequently parsed.
    cookie_string: Option<Cow<'c, str>>,
    /// The cookie's name.
    name: CookieStr,
    /// The cookie's value.
    value: CookieStr,
    /// The cookie's experiation, if any.
    expires: Option<Tm>,
    /// The cookie's maximum age, if any.
    max_age: Option<Duration>,
    /// The cookie's domain, if any.
    domain: Option<CookieStr>,
    /// The cookie's path domain, if any.
    path: Option<CookieStr>,
    /// Whether this cookie was marked secure.
    secure: bool,
    /// Whether this cookie was marked httponly.
    http_only: bool,
}

impl Cookie<'static> {
    /// Creates a new `Cookie` with the given name and value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::Cookie;
    ///
    /// let cookie = Cookie::new("name", "value");
    /// assert_eq!(cookie.name_value(), ("name", "value"));
    /// ```
    #[inline(always)]
    pub fn new<N, V>(name: N, value: V) -> Cookie<'static>
        where N: Into<Cow<'static, str>>,
              V: Into<Cow<'static, str>>
    {
        Cookie {
            cookie_string: None,
            name: CookieStr::Concrete(name.into()),
            value: CookieStr::Concrete(value.into()),
            expires: None,
            max_age: None,
            domain: None,
            path: None,
            secure: false,
            http_only: false,
        }
    }

    /// Parses a `Cookie` from a `String` without any allocation.
    ///
    /// Prefer to use this method instead of [parse](#method.parse) when the
    /// source string is a `String` to avoid allocations while retrieving a
    /// `Cookie` with a `static` lifetime.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::Cookie;
    ///
    /// let cookie = Cookie::parse_static("name=value".to_string()).unwrap();
    /// assert_eq!(cookie.name_value(), ("name", "value"));
    /// ```
    pub fn parse_static<S>(string: S) -> Result<Self, ParseError>
        where S: Into<Cow<'static, str>>
    {
        let storage = string.into();

        // We use `unsafe` here to convince Rust to move `storage` while a
        // borrow to it "exists". The word "exists" is placed in quotes because
        // this piece of code ensures that a borrow _does not_ exist when the
        // move is made. This is because the field which holds the reference,
        // `cookie_string`, is overwritten by `storage` when it is moved into
        // `cookie_string`. This move invalidates the borrow, and safety is
        // preserved.
        //
        // This safety can be violated if the borrow passed into `parse` is
        // stored in any other field aside from `cookie_string`. The safety
        // invariant can thus be stated as follows: this function is safe iff
        // the call to `Cookie::parse` stores the borrow in its first argument
        // in at most one field of `Cookie`: `cookie_string`.
        let parsed_cookie = unsafe {
            let str_ptr: *const str = &*storage;
            Cookie::parse(&*str_ptr)?
        };

        Ok(Cookie { cookie_string: Some(storage), ..parsed_cookie })
    }

    /// Creates a new `CookieBuilder` instance from the given key and value
    /// strings.
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let c = Cookie::build("foo", "bar").finish();
    /// assert_eq!(c.name_value(), ("foo", "bar"));
    /// ```
    #[inline(always)]
    pub fn build<N, V>(name: N, value: V) -> CookieBuilder
        where N: Into<Cow<'static, str>>,
              V: Into<Cow<'static, str>>
    {
        CookieBuilder::new(name, value)
    }
}

impl<'c> Cookie<'c> {
    /// Parses a `Cookie` from the given HTTP cookie header value string.
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let c = Cookie::parse("foo=bar; HttpOnly").unwrap();
    /// assert_eq!(c.name_value(), ("foo", "bar"));
    /// assert_eq!(c.http_only(), true);
    /// ```
    #[inline]
    pub fn parse(s: &'c str) -> Result<Cookie<'c>, ParseError> {
        parse_cookie(s)
    }

    /// Converts `self` into a `Cookie` with a static lifetime. This method
    /// results in at most one allocation.
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
    #[inline]
    pub fn into_owned(mut self) -> Cookie<'static> {
        self.cookie_string = match self.cookie_string {
            Some(storage) => Some(Cow::Owned(storage.into_owned())),
            None => None,
        };

        // We use `unsafe` here to convince Rust that the lifetime of `self` is
        // in fact `static`. We know that the lifetime is indeed `static`
        // because the only non-static field in `self`, `cookie_string`, will
        // contain a `static` item after the assignment above.
        //
        // This safety can be violated if any other field aside from
        // `cookie_string` can possible hold a non-static reference. The safety
        // invariant can thus be stated as follows: this function is safe iff
        // `self` has exactly one field, `cookie_string`, with a potentially
        // non-static lifetime.
        unsafe { ::std::mem::transmute(self) }
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
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let c = Cookie::new("name", "value");
    /// assert_eq!(c.value(), "value");
    /// ```
    #[inline]
    pub fn value(&self) -> &str {
        self.value.to_str(self.cookie_string.as_ref())
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
    #[inline(always)]
    pub fn name_value(&self) -> (&str, &str) {
        (self.name(), self.value())
    }

    /// Returns whether this cookie was marked `HttpOnly` or not.
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let c = Cookie::parse("name=value; httponly").unwrap();
    /// assert_eq!(c.http_only(), true);
    /// ```
    #[inline]
    pub fn http_only(&self) -> bool {
        self.http_only
    }

    /// Returns whether this cookie was marked `Secure` or not.
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let c = Cookie::parse("name=value; Secure").unwrap();
    /// assert_eq!(c.secure(), true);
    /// ```
    #[inline]
    pub fn secure(&self) -> bool {
        self.secure
    }

    /// Returns the specified max-age of the cookie if one was specified.
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
    /// assert_eq!(c.max_age().map(|age| age.num_hours()), Some(1));
    /// ```
    #[inline]
    pub fn max_age(&self) -> Option<Duration> {
        self.max_age
    }

    /// Returns the `Path` of the cookie if one was specified.
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
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let c = Cookie::parse("name=value").unwrap();
    /// assert_eq!(c.domain(), None);
    ///
    /// let c = Cookie::parse("name=value; Domain=crates.io").unwrap();
    /// assert_eq!(c.domain(), Some("crates.io"));
    /// ```
    #[inline]
    pub fn domain(&self) -> Option<&str> {
        match self.domain {
            Some(ref c) => Some(c.to_str(self.cookie_string.as_ref())),
            None => None,
        }
    }

    /// Returns the `Expires` time of the cookie if one was specified.
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let c = Cookie::parse("name=value").unwrap();
    /// assert_eq!(c.expires(), None);
    ///
    /// let expire_time = "Wed, 21 Oct 2017 07:28:00 GMT";
    /// let cookie_str = format!("name=value; Expires={}", expire_time);
    /// let c = Cookie::parse_static(cookie_str).unwrap();
    /// assert_eq!(c.expires().map(|t| t.tm_year), Some(117));
    /// ```
    #[inline]
    pub fn expires(&self) -> Option<Tm> {
        self.expires
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
    #[inline(always)]
    pub fn set_name<N: Into<Cow<'static, str>>>(&mut self, name: N) {
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
    #[inline(always)]
    pub fn set_value<V: Into<Cow<'static, str>>>(&mut self, value: V) {
        self.value = CookieStr::Concrete(value.into())
    }

    /// Sets the value of `http_only` in `self` to `value`.
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let mut c = Cookie::new("name", "value");
    /// assert_eq!(c.http_only(), false);
    ///
    /// c.set_http_only(true);
    /// assert_eq!(c.http_only(), true);
    /// ```
    #[inline(always)]
    pub fn set_http_only(&mut self, value: bool) {
        self.http_only = value;
    }

    /// Sets the value of `secure` in `self` to `value`.
    ///
    /// # Example
    ///
    /// ```
    /// use cookie::Cookie;
    ///
    /// let mut c = Cookie::new("name", "value");
    /// assert_eq!(c.secure(), false);
    ///
    /// c.set_secure(true);
    /// assert_eq!(c.secure(), true);
    /// ```
    #[inline(always)]
    pub fn set_secure(&mut self, value: bool) {
        self.secure = value;
    }

    /// Sets the value of `max_age` in `self` to `value`.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate cookie;
    /// extern crate time;
    ///
    /// use cookie::Cookie;
    /// use time::Duration;
    ///
    /// # fn main() {
    /// let mut c = Cookie::new("name", "value");
    /// assert_eq!(c.max_age(), None);
    ///
    /// c.set_max_age(Duration::hours(10));
    /// assert_eq!(c.max_age(), Some(Duration::hours(10)));
    /// # }
    /// ```
    #[inline(always)]
    pub fn set_max_age(&mut self, value: Duration) {
        self.max_age = Some(value);
    }

    /// Sets the `path` of `self` to `path`.
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
    /// ```
    #[inline(always)]
    pub fn set_path<P: Into<Cow<'static, str>>>(&mut self, path: P) {
        self.path = Some(CookieStr::Concrete(path.into()));
    }

    /// Sets the `domain` of `self` to `domain`.
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
    /// ```
    #[inline(always)]
    pub fn set_domain<D: Into<Cow<'static, str>>>(&mut self, domain: D) {
        self.domain = Some(CookieStr::Concrete(domain.into()));
    }

    /// Sets the expires field of `self` to `time`.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate cookie;
    /// extern crate time;
    ///
    /// use cookie::Cookie;
    ///
    /// # fn main() {
    /// let mut c = Cookie::new("name", "value");
    /// assert_eq!(c.expires(), None);
    ///
    /// let mut now = time::now();
    /// now.tm_year += 1;
    ///
    /// c.set_expires(now);
    /// assert!(c.expires().is_some())
    /// # }
    /// ```
    #[inline(always)]
    pub fn set_expires(&mut self, time: Tm) {
        self.expires = Some(time);
    }
}

impl<'a, 'b> PartialEq<Cookie<'b>> for Cookie<'a> {
    fn eq(&self, other: &Cookie<'b>) -> bool {
        let so_far_so_good = self.name() == other.name()
            && self.value() == other.value()
            && self.http_only() == other.http_only()
            && self.secure() == other.secure()
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

impl<'c> fmt::Display for Cookie<'c> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Percent encode if the percent-encode feature is set.
        #[cfg(feature = "percent-encode")]
        let name = percent_encode(self.name().as_bytes(), USERINFO_ENCODE_SET);
        #[cfg(feature = "percent-encode")]
        let value = percent_encode(self.value().as_bytes(), USERINFO_ENCODE_SET);

        // Don't percent encode if the feature isn't set.
        #[cfg(not(feature = "percent-encode"))]
        let (name, value) = self.name_value();

        // Write out the compile-time determined name and value.
        write!(f, "{}={}", name, value)?;

        if self.http_only() {
            write!(f, "; HttpOnly")?;
        }

        if self.secure() {
            write!(f, "; Secure")?;
        }

        if let Some(path) = self.path() {
            write!(f, "; Path={}", path)?;
        }

        if let Some(domain) = self.domain() {
            write!(f, "; Domain={}", domain)?;
        }

        if let Some(max_age) = self.max_age() {
            write!(f, "; Max-Age={}", max_age.num_seconds())?;
        }

        if let Some(time) = self.expires() {
            write!(f, "; Expires={}", time.rfc822())?;
        }

        Ok(())
    }
}

impl FromStr for Cookie<'static> {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Cookie<'static>, ParseError> {
        Cookie::parse(s).map(|c| c.into_owned())
    }
}

#[cfg(test)]
mod tests {
    use ::Cookie;
    use ::time::{strptime, Duration};

    #[test]
    fn format() {
        let cookie = Cookie::new("foo", "bar");
        assert_eq!(&cookie.to_string(), "foo=bar");

        let cookie = Cookie::build("foo", "bar")
            .http_only(true).finish();
        assert_eq!(&cookie.to_string(), "foo=bar; HttpOnly");

        let cookie = Cookie::build("foo", "bar")
            .max_age(Duration::seconds(10)).finish();
        assert_eq!(&cookie.to_string(), "foo=bar; Max-Age=10");

        let cookie = Cookie::build("foo", "bar")
            .secure(true).finish();
        assert_eq!(&cookie.to_string(), "foo=bar; Secure");

        let cookie = Cookie::build("foo", "bar")
            .path("/").finish();
        assert_eq!(&cookie.to_string(), "foo=bar; Path=/");

        let cookie = Cookie::build("foo", "bar")
            .domain("www.rust-lang.org").finish();
        assert_eq!(&cookie.to_string(), "foo=bar; Domain=www.rust-lang.org");

        let time_str = "Wed, 21 Oct 2015 07:28:00 GMT";
        let expires = strptime(time_str, "%a, %d %b %Y %H:%M:%S %Z").unwrap();
        let cookie = Cookie::build("foo", "bar")
            .expires(expires).finish();
        assert_eq!(&cookie.to_string(),
                   "foo=bar; Expires=Wed, 21 Oct 2015 07:28:00 GMT");
    }

    #[test]
    #[cfg(feature = "percent-encode")]
    fn format_encoded() {
        let cookie = Cookie::build("foo !?=", "bar;; a").finish();
        let cookie_str = cookie.to_string();
        assert_eq!(&cookie_str, "foo%20!%3F%3D=bar%3B%3B%20a");

        let cookie = Cookie::parse_static(cookie_str).unwrap();
        assert_eq!(cookie.name_value(), ("foo !?=", "bar;; a"));
    }
}
