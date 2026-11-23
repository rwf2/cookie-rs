use std::borrow::Cow;
use std::error::Error;
use std::str::Utf8Error;
use std::time::Duration;
use std::fmt;

#[allow(unused_imports, deprecated)]
use std::ascii::AsciiExt;

#[cfg(feature = "percent-encode")]
use percent_encoding::percent_decode;

use crate::{Cookie, SameSite, CookieStr};

/// Enum corresponding to a parsing error.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum ParseError {
    /// The cookie did not contain a name/value pair.
    MissingPair,
    /// The cookie's name was empty.
    EmptyName,
    /// Decoding the cookie's name or value resulted in invalid UTF-8.
    Utf8Error(Utf8Error),
    /// The cookie contains an invalid control character: %x00-08 / %x0A-1F /
    /// %x7F character (CTL characters excluding HTAB).
    InvalidControl,
    /// The cookie's name contained a percent-encoded cookie prefix.
    EncodedPrefix,
}

impl ParseError {
    /// Returns a description of this error as a string
    pub fn as_str(&self) -> &'static str {
        match *self {
            ParseError::MissingPair => "the cookie is missing a name/value pair",
            ParseError::EmptyName => "the cookie's name is empty",
            ParseError::Utf8Error(_) => {
                "decoding the cookie's name or value resulted in invalid UTF-8"
            }
            ParseError::InvalidControl => "cookie contains an invalid control character",
            ParseError::EncodedPrefix => {
                "decoding the cookie's name resulted in a cookie prefix"
            }
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<Utf8Error> for ParseError {
    fn from(error: Utf8Error) -> ParseError {
        ParseError::Utf8Error(error)
    }
}

impl Error for ParseError {
    fn description(&self) -> &str {
        self.as_str()
    }
}

/// Trims whitespace, as defined by RFC 6265, from both ends of `string`. Only
/// spaces and horizontal tabs are whitespace.
pub(crate) fn trim(string: &str) -> &str {
    string.trim_matches([' ', '\t'])
}

#[cfg(feature = "percent-encode")]
fn name_val_decoded(
    name: &str,
    val: &str
) -> Result<Option<(CookieStr<'static>, CookieStr<'static>)>, ParseError> {
    // The cookie prefixes spec'd in RFC 6265bis followed by those spec'd in
    // https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-layered-cookies.
    const PREFIXES: [&str; 4] = ["__Host-", "__Secure-", "__Http-", "__Host-Http-"];

    let has_prefix = |name: &str, prefix: &str| name.get(..prefix.len())
        .is_some_and(|start| start.eq_ignore_ascii_case(prefix));

    let decoded_name = percent_decode(name.as_bytes()).decode_utf8()?;
    let decoded_value = percent_decode(val.as_bytes()).decode_utf8()?;

    // From RFC 6265bis 5.6: browsers do not decode a cookie's name. A name
    // that has a prefix only after decoding was thus never held to the
    // prefix's requirements, so we fail to parse it.
    if PREFIXES.iter().any(|p| has_prefix(&decoded_name, p) && !has_prefix(name, p)) {
        return Err(ParseError::EncodedPrefix);
    }

    if let (&Cow::Borrowed(_), &Cow::Borrowed(_)) = (&decoded_name, &decoded_value) {
         Ok(None)
    } else {
        let name = CookieStr::Concrete(Cow::Owned(decoded_name.into()));
        let val = CookieStr::Concrete(Cow::Owned(decoded_value.into()));
        Ok(Some((name, val)))
    }
}

#[cfg(not(feature = "percent-encode"))]
fn name_val_decoded(
    _: &str,
    _: &str
) -> Result<Option<(CookieStr<'static>, CookieStr<'static>)>, ParseError> {
    unreachable!("This function should never be called with 'percent-encode' disabled!")
}

// This function does the real parsing but _does not_ set the `cookie_string` in
// the returned cookie object. This only exists so that the borrow to `s` is
// returned at the end of the call, allowing the `cookie_string` field to be
// set in the outer `parse` function.
fn parse_inner<'c>(s: &str, decode: bool) -> Result<Cookie<'c>, ParseError> {
    let mut attributes = s.split(';');

    // Determine the name = val.
    let key_value = attributes.next().expect("first str::split().next() returns Some");
    let (name, value) = match key_value.find('=') {
        Some(i) => (trim(&key_value[..i]), trim(&key_value[(i + 1)..])),
        None => return Err(ParseError::MissingPair)
    };

    if name.is_empty() {
        return Err(ParseError::EmptyName);
    }

    // If there is nothing to decode, or we're not decoding, use indexes.
    let indexed_names = |s, name, value| {
        let name = CookieStr::indexed(name, s).expect("name sub");
        let value = CookieStr::indexed(value, s).expect("value sub");
        (name, value)
    };

    // Create a cookie with all of the defaults. We'll fill things in while we
    // iterate through the parameters below.
    let (name, value) = if decode {
        match name_val_decoded(name, value)? {
            Some((name, value)) => (name, value),
            None => indexed_names(s, name, value)
        }
    } else {
        indexed_names(s, name, value)
    };

    let mut cookie: Cookie<'c> = Cookie {
        name, value,
        cookie_string: None,
        expires: None,
        max_age: None,
        domain: None,
        path: None,
        secure: None,
        http_only: None,
        same_site: None,
        partitioned: None,
    };

    for attr in attributes {
        let (key, value) = match attr.find('=') {
            Some(i) => (trim(&attr[..i]), Some(trim(&attr[(i + 1)..]))),
            None => (trim(attr), None),
        };

        match (&*key.to_ascii_lowercase(), value) {
            ("secure", _) => cookie.secure = Some(true),
            ("httponly", _) => cookie.http_only = Some(true),
            ("max-age", Some(mut v)) => cookie.max_age = {
                let is_negative = v.starts_with('-');
                if is_negative {
                    v = &v[1..];
                }

                if v.is_empty() || !v.chars().all(|d| d.is_ascii_digit()) {
                    continue
                }

                // From RFC 6265 5.2.2: neg values indicate that the earliest
                // expiration should be used, so set the max age to 0 seconds.
                if is_negative {
                    Some(Duration::ZERO)
                } else {
                    // We write a `Max-Age` of at most `i64::MAX`, so we read
                    // one of at most `i64::MAX`. Parsing fails on overflow.
                    let max = i64::MAX as u64;
                    let secs = v.parse::<u64>().map_or(max, |secs| secs.min(max));
                    Some(Duration::from_secs(secs))
                }
            },
            ("domain", Some(d)) if !d.is_empty() => {
                cookie.domain = Some(CookieStr::indexed(d, s).expect("domain sub"));
            },
            ("path", Some(v)) => {
                cookie.path = Some(CookieStr::indexed(v, s).expect("path sub"));
            },
            ("samesite", Some(v)) => {
                if v.eq_ignore_ascii_case("strict") {
                    cookie.same_site = Some(SameSite::Strict);
                } else if v.eq_ignore_ascii_case("lax") {
                    cookie.same_site = Some(SameSite::Lax);
                } else if v.eq_ignore_ascii_case("none") {
                    cookie.same_site = Some(SameSite::None);
                } else {
                    // We do nothing here, for now. When/if the `SameSite`
                    // attribute becomes standard, the spec says that we should
                    // ignore this cookie, i.e, fail to parse it, when an
                    // invalid value is passed in. The draft is at
                    // http://httpwg.org/http-extensions/draft-ietf-httpbis-cookie-same-site.html.
                }
            }
            ("partitioned", _) => cookie.partitioned = Some(true),
            ("expires", Some(v)) => {
                if let Some(time) = crate::date::parse(v) {
                    cookie.expires = Some(time.into())
                }
            }
            _ => {
                // We're going to be permissive here. If we have no idea what
                // this is, then it's something nonstandard. We're not going to
                // store it (because it's not compliant), but we're also not
                // going to emit an error.
            }
        }
    }

    Ok(cookie)
}

pub(crate) fn parse_cookie<'c, S>(cow: S, decode: bool) -> Result<Cookie<'c>, ParseError>
    where S: Into<Cow<'c, str>>
{
    let s = cow.into();
    if s.as_bytes().iter().any(|b| matches!(b, 0x00..=0x08 | 0x0A..=0x1F | 0x7F)) {
        return Err(ParseError::InvalidControl);
    }

    let mut cookie = parse_inner(&s, decode)?;
    cookie.cookie_string = Some(s);
    Ok(cookie)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};
    use crate::{Cookie, ParseError, SameSite};

    fn datetime(timestamp: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp)
    }

    macro_rules! assert_eq_parse {
        ($string:expr, $expected:expr) => (
            let cookie = match Cookie::parse($string) {
                Ok(cookie) => cookie,
                Err(e) => panic!("Failed to parse {:?}: {:?}", $string, e)
            };

            assert_eq!(cookie, $expected);
        )
    }

    macro_rules! assert_ne_parse {
        ($string:expr, $expected:expr) => (
            let cookie = match Cookie::parse($string) {
                Ok(cookie) => cookie,
                Err(e) => panic!("Failed to parse {:?}: {:?}", $string, e)
            };

            assert_ne!(cookie, $expected);
        )
    }

    #[test]
    fn parse_same_site() {
        let expected = Cookie::build(("foo", "bar")).same_site(SameSite::Lax);
        assert_eq_parse!("foo=bar; SameSite=Lax", expected);
        assert_eq_parse!("foo=bar; SameSite=lax", expected);
        assert_eq_parse!("foo=bar; SameSite=LAX", expected);
        assert_eq_parse!("foo=bar; samesite=Lax", expected);
        assert_eq_parse!("foo=bar; SAMESITE=Lax", expected);

        let expected = Cookie::build(("foo", "bar")).same_site(SameSite::Strict);
        assert_eq_parse!("foo=bar; SameSite=Strict", expected);
        assert_eq_parse!("foo=bar; SameSITE=Strict", expected);
        assert_eq_parse!("foo=bar; SameSite=strict", expected);
        assert_eq_parse!("foo=bar; SameSite=STrICT", expected);
        assert_eq_parse!("foo=bar; SameSite=STRICT", expected);

        let expected = Cookie::build(("foo", "bar")).same_site(SameSite::None);
        assert_eq_parse!("foo=bar; SameSite=None", expected);
        assert_eq_parse!("foo=bar; SameSITE=none", expected);
        assert_eq_parse!("foo=bar; SameSite=NOne", expected);
        assert_eq_parse!("foo=bar; SameSite=nOne", expected);

        let expected = Cookie::new("foo", "bar");
        assert_eq_parse!("foo=bar; SameSite", expected);
        assert_eq_parse!("foo=bar; SameSite=", expected);
        assert_eq_parse!("foo=bar; SameSite=invalid", expected);
        assert_ne_parse!("foo=bar; SameSite=Lax", expected);
        assert_ne_parse!("foo=bar; SameSite=Strict", expected);
        assert_ne_parse!("foo=bar; SameSite=None", expected);
    }

    #[test]
    fn parse() {
        assert!(Cookie::parse("bar").is_err());
        assert!(Cookie::parse("=bar").is_err());
        assert!(Cookie::parse(" =bar").is_err());
        assert!(Cookie::parse("foo=").is_ok());

        let expected = Cookie::new("foo", "bar=baz");
        assert_eq_parse!("foo=bar=baz", expected);

        let expected = Cookie::new("foo", "\"\"bar\"\"");
        assert_eq_parse!("foo=\"\"bar\"\"", expected);

        let expected = Cookie::new("foo", "\"bar");
        assert_eq_parse!("foo=  \"bar", expected);
        assert_eq_parse!("foo=\"bar  ", expected);
        assert_ne_parse!("foo=\"\"bar\"", expected);
        assert_ne_parse!("foo=\"\"bar  \"", expected);
        assert_ne_parse!("foo=\"\"bar  \"  ", expected);

        let expected = Cookie::new("foo", "bar\"");
        assert_eq_parse!("foo=bar\"", expected);
        assert_ne_parse!("foo=\"bar\"\"", expected);
        assert_ne_parse!("foo=\"  bar\"\"", expected);
        assert_ne_parse!("foo=\"  bar\"  \"  ", expected);

        let expected = Cookie::build(("foo", "bar")).partitioned(true).build();
        assert_eq_parse!("foo=bar; partitioned", expected);
        assert_eq_parse!("foo=bar; Partitioned", expected);
        assert_eq_parse!("foo=bar; PARTITIONED", expected);
        assert_ne_parse!("foo=bar", expected);
        assert_ne_parse!("foo=bar; partition", expected);

        let mut expected = Cookie::new("foo", "bar");
        assert_eq_parse!("foo=bar", expected);
        assert_eq_parse!("foo = bar", expected);
        assert_eq_parse!(" foo=bar ", expected);
        assert_eq_parse!(" foo=bar ;Domain=", expected);
        assert_eq_parse!(" foo=bar ;Domain= ", expected);
        assert_eq_parse!(" foo=bar ;Ignored", expected);
        assert_ne_parse!("foo=\"bar\"", expected);
        assert_ne_parse!(" foo=\"bar   \" ", expected);

        let mut unexpected = Cookie::build(("foo", "bar")).http_only(false).build();
        assert_ne_parse!(" foo=bar ;HttpOnly", unexpected);
        assert_ne_parse!(" foo=bar; httponly", unexpected);

        expected.set_http_only(true);
        assert_eq_parse!(" foo=bar ;HttpOnly", expected);
        assert_eq_parse!(" foo=bar ;httponly", expected);
        assert_eq_parse!(" foo=bar ;HTTPONLY=whatever", expected);
        assert_eq_parse!(" foo=bar ; sekure; HTTPONLY", expected);

        expected.set_secure(true);
        assert_eq_parse!(" foo=bar ;HttpOnly; Secure", expected);
        assert_eq_parse!(" foo=bar ;HttpOnly; Secure=aaaa", expected);

        unexpected.set_http_only(true);
        unexpected.set_secure(true);
        assert_ne_parse!(" foo=bar ;HttpOnly; skeure", unexpected);
        assert_ne_parse!(" foo=bar ;HttpOnly; =secure", unexpected);
        assert_ne_parse!(" foo=bar ;HttpOnly;", unexpected);

        unexpected.set_secure(false);
        assert_ne_parse!(" foo=bar ;HttpOnly; secure", unexpected);
        assert_ne_parse!(" foo=bar ;HttpOnly; secure", unexpected);
        assert_ne_parse!(" foo=bar ;HttpOnly; secure", unexpected);

        expected.set_max_age(Duration::ZERO);
        assert_eq_parse!(" foo=bar ;HttpOnly; Secure; Max-Age=0", expected);
        assert_eq_parse!(" foo=bar ;HttpOnly; Secure; Max-Age = 0 ", expected);
        assert_eq_parse!(" foo=bar ;HttpOnly; Secure; Max-Age=-1", expected);
        assert_eq_parse!(" foo=bar ;HttpOnly; Secure; Max-Age = -1 ", expected);

        expected.set_max_age(Duration::from_secs(60));
        assert_eq_parse!(" foo=bar ;HttpOnly; Secure; Max-Age=60", expected);
        assert_eq_parse!(" foo=bar ;HttpOnly; Secure; Max-Age =   60 ", expected);

        expected.set_max_age(Duration::from_secs(4));
        assert_eq_parse!(" foo=bar ;HttpOnly; Secure; Max-Age=4", expected);
        assert_eq_parse!(" foo=bar ;HttpOnly; Secure; Max-Age = 4 ", expected);

        unexpected.set_secure(true);
        unexpected.set_max_age(Duration::from_secs(60));
        assert_ne_parse!(" foo=bar ;HttpOnly; Secure; Max-Age=122", unexpected);
        assert_ne_parse!(" foo=bar ;HttpOnly; Secure; Max-Age = 38 ", unexpected);
        assert_ne_parse!(" foo=bar ;HttpOnly; Secure; Max-Age=51", unexpected);
        assert_ne_parse!(" foo=bar ;HttpOnly; Secure; Max-Age = -1 ", unexpected);
        assert_ne_parse!(" foo=bar ;HttpOnly; Secure; Max-Age = 0", unexpected);

        expected.set_path("/");
        assert_eq_parse!("foo=bar;HttpOnly; Secure; Max-Age=4; Path=/", expected);
        assert_eq_parse!("foo=bar;HttpOnly; Secure; Max-Age=4;Path=/", expected);

        expected.set_path("/foo");
        assert_eq_parse!("foo=bar;HttpOnly; Secure; Max-Age=4; Path=/foo", expected);
        assert_eq_parse!("foo=bar;HttpOnly; Secure; Max-Age=4;Path=/foo", expected);
        assert_eq_parse!("foo=bar;HttpOnly; Secure; Max-Age=4;path=/foo", expected);
        assert_eq_parse!("foo=bar;HttpOnly; Secure; Max-Age=4;path = /foo", expected);

        unexpected.set_max_age(Duration::from_secs(4));
        unexpected.set_path("/bar");
        assert_ne_parse!("foo=bar;HttpOnly; Secure; Max-Age=4; Path=/foo", unexpected);
        assert_ne_parse!("foo=bar;HttpOnly; Secure; Max-Age=4;Path=/baz", unexpected);

        expected.set_domain("www.foo.com");
        assert_eq_parse!(" foo=bar ;HttpOnly; Secure; Max-Age=4; Path=/foo; \
            Domain=www.foo.com", expected);

        expected.set_domain("foo.com");
        assert_eq_parse!(" foo=bar ;HttpOnly; Secure; Max-Age=4; Path=/foo; \
            Domain=foo.com", expected);
        assert_eq_parse!(" foo=bar ;HttpOnly; Secure; Max-Age=4; Path=/foo; \
            Domain=FOO.COM", expected);

        expected.set_domain(".foo.com");
        assert_eq_parse!(" foo=bar ;HttpOnly; Secure; Max-Age=4; Path=/foo; \
            Domain=.foo.com", expected);
        assert_eq_parse!(" foo=bar ;HttpOnly; Secure; Max-Age=4; Path=/foo; \
            Domain=.FOO.COM", expected);

        unexpected.set_path("/foo");
        unexpected.set_domain("bar.com");
        assert_ne_parse!(" foo=bar ;HttpOnly; Secure; Max-Age=4; Path=/foo; \
            Domain=foo.com", unexpected);
        assert_ne_parse!(" foo=bar ;HttpOnly; Secure; Max-Age=4; Path=/foo; \
            Domain=FOO.COM", unexpected);

        // Wed, 21 Oct 2015 07:28:00 GMT
        let expires = datetime(1445412480);
        expected.set_expires(expires);
        assert_eq_parse!(" foo=bar ;HttpOnly; Secure; Max-Age=4; Path=/foo; \
            Domain=foo.com; Expires=Wed, 21 Oct 2015 07:28:00 GMT", expected);

        unexpected.set_domain("foo.com");
        let bad_expires = datetime(1445412481);
        unexpected.set_expires(bad_expires);
        assert_ne_parse!(" foo=bar ;HttpOnly; Secure; Max-Age=4; Path=/foo; \
            Domain=foo.com; Expires=Wed, 21 Oct 2015 07:28:00 GMT", unexpected);
    }

    #[test]
    fn parse_invalid_control_characters() {
        let cases = [
            "fo\0o=bar",
            "foo=ba\x08r",
            "foo=bar\n",
            "foo=bar\r\n",
            "foo=bar; Path=/\x1f",
            "foo=bar\x7f",
        ];

        for case in cases {
            assert_eq!(Cookie::parse(case), Err(ParseError::InvalidControl));
        }

        // Every control character except the horizontal tab is invalid.
        for byte in (0x00u8..=0x08).chain(0x0A..=0x1F).chain([0x7F]) {
            let c = byte as char;
            let cases = [
                format!("fo{}o=bar", c),
                format!("foo=ba{}r", c),
                format!("foo=bar{}", c),
                format!("foo=bar; Path=/{}", c),
                format!("foo=bar; HttpOnly{}", c),
            ];

            for case in cases {
                let result = Cookie::parse(case);
                assert_eq!(result, Err(ParseError::InvalidControl));
            }
        }

        let expected = Cookie::build(("foo", "bar"))
            .path("/")
            .http_only(true)
            .build();
        assert_eq_parse!("\tfoo\t=\tbar\t;\tPath\t=\t/\t;\tHttpOnly\t", expected);
    }

    #[test]
    fn parse_whitespace() {
        // Only spaces and horizontal tabs are whitespace.
        let expected = Cookie::build(("foo", "bar")).path("/").build();
        assert_eq_parse!(" \t foo \t = \t bar \t ; \t Path \t = \t / \t ", expected);

        for space in ['\u{85}', '\u{a0}', '\u{2003}', '\u{2028}', '\u{3000}'] {
            let cookie = Cookie::parse(format!("{0}foo{0}={0}bar{0}", space)).unwrap();
            let (name, value) = (format!("{0}foo{0}", space), format!("{0}bar{0}", space));
            assert_eq!(cookie.name_value(), (&*name, &*value));

            let cookie = Cookie::parse(format!("foo=bar;{0}Path{0}=/", space)).unwrap();
            assert_eq!(cookie.path(), None);

            let cookie = Cookie::parse(format!("foo=bar; Path={0}/{0}", space)).unwrap();
            assert_eq!(cookie.path(), Some(&*format!("{0}/{0}", space)));

            let string = format!("foo=bar;{0}HttpOnly; Secure{0}", space);
            let cookie = Cookie::parse(string).unwrap();
            assert_eq!((cookie.http_only(), cookie.secure()), (None, None));
        }
    }

    #[test]
    fn parse_max_age() {
        let ignored = ["", " ", "-", "+1", "1.5", "1e3", "0x10", "--1", "1-", "1 0", "abc"];
        for max_age in ignored {
            let cookie = Cookie::parse(format!("foo=bar; Max-Age={}", max_age)).unwrap();
            assert_eq!(cookie.max_age(), None, "{:?}", max_age);
        }

        let valid = [("0", 0), ("00", 0), ("1", 1), ("010", 10), (" 60 ", 60), ("-0", 0), ("-1", 0)];
        for (max_age, seconds) in valid {
            let cookie = Cookie::parse(format!("foo=bar; Max-Age={}", max_age)).unwrap();
            assert_eq!(cookie.max_age(), Some(Duration::from_secs(seconds)), "{:?}", max_age);
        }
    }

    #[test]
    fn parse_abbreviated_years() {
        let tests = [
            ("foo=bar; expires=Thu, 10-Sep-20 20:00:00 GMT", 1599768000), // 2020
            ("foo=bar; expires=Thu, 10-Sep-68 20:00:00 GMT", 3114532800), // 2068
            ("foo=bar; expires=Thu, 10-Sep-69 20:00:00 GMT", 3146068800), // 2069
            ("foo=bar; expires=Thu, 10-Sep-99 20:00:00 GMT", 936993600), // 1999
            ("foo=bar; expires=Thu, 10-Sep-2069 20:00:00 GMT", 3146068800), // 2069
            ("foo=bar; expires=Thu, 10-Sep-00 20:00:00 GMT", 968616000), // 2000
            ("foo=bar; expires=Thu, 10-Sep-70 20:00:00 GMT", 21844800), // 1970
        ];

        for (cookie_str, timestamp) in tests {
            let cookie = Cookie::parse(cookie_str).unwrap();
            assert_eq!(cookie.expires_datetime(), Some(datetime(timestamp)));
        }

        // RFC 6265 requires a year to be 2 to 4 digits.
        let cookie = Cookie::parse("foo=bar; expires=Thu, 10-Sep-0 20:00:00 GMT").unwrap();
        assert_eq!(cookie.expires(), None);
    }

    #[test]
    fn parse_variant_date_fmts() {
        // Sun, 06 Nov 1994 08:49:37 GMT
        let expected = datetime(784111777);
        let strings = [
            "foo=bar; expires=Sun, 06 Nov 1994 08:49:37 GMT",
            "foo=bar; expires=06 Nov 1994 08:49:37 GMT",
            "foo=bar; expires=Sunday, 06-Nov-94 08:49:37 GMT",
            "foo=bar; expires=06-Nov-94 08:49:37 GMT",
            "foo=bar; expires=Sun Nov  6 08:49:37 1994",
            "foo=bar; expires=Nov  6 08:49:37 1994",
            "foo=bar; expires=06-Nov-1994 08:49:37 GMT",
        ];

        for cookie_str in strings {
            let cookie = Cookie::parse(cookie_str).unwrap();
            assert_eq!(cookie.expires_datetime(), Some(expected));
        }
    }

    #[test]
    fn parse_invalid_dates() {
        let strings = [
            "foo=bar; expires=",
            "foo=bar; expires=tomorrow",
            "foo=bar; expires=Tue, 31 Sep 2015 07:28:00 GMT",
            "foo=bar; expires=Wed, 21 Oct 1600 07:28:00 GMT",
            "foo=bar; expires=2015-10-21T07:28:00Z",
        ];

        for cookie_str in strings {
            let cookie = Cookie::parse(cookie_str).unwrap();
            assert_eq!(cookie.name_value(), ("foo", "bar"));
            assert_eq!(cookie.expires(), None);
        }
    }

    #[test]
    fn parse_very_large_max_ages() {
        let mut expected = Cookie::build(("foo", "bar"))
            .max_age(Duration::from_secs(i64::MAX as u64))
            .build();

        let string = format!("foo=bar; Max-Age={}", 1u128 << 100);
        assert_eq_parse!(&string, expected);

        expected.set_max_age(Duration::ZERO);
        assert_eq_parse!("foo=bar; Max-Age=-129", expected);

        let string = format!("foo=bar; Max-Age=-{}", 1u128 << 100);
        assert_eq_parse!(&string, expected);

        let string = format!("foo=bar; Max-Age=-{}", i64::MAX);
        assert_eq_parse!(&string, expected);

        let string = format!("foo=bar; Max-Age={}", i64::MAX);
        expected.set_max_age(Duration::from_secs(i64::MAX as u64));
        assert_eq_parse!(&string, expected);

        let string = format!("foo=bar; Max-Age={}", i64::MAX as u64 + 1);
        assert_eq_parse!(&string, expected);

        let string = format!("foo=bar; Max-Age={}", u64::MAX);
        assert_eq_parse!(&string, expected);

        let string = format!("foo=bar; Max-Age={}", i64::MAX - 1);
        expected.set_max_age(Duration::from_secs(i64::MAX as u64 - 1));
        assert_eq_parse!(&string, expected);

        // What is parsed is written, and parsed again, as the same `Max-Age`.
        for max_age in [0, 60, i64::MAX as u128, u64::MAX as u128, 1 << 100] {
            let cookie = Cookie::parse(format!("foo=bar; Max-Age={}", max_age)).unwrap();
            let string = cookie.unescaped().to_string();
            assert_eq!(Cookie::parse(string).unwrap().max_age(), cookie.max_age());
        }
    }

    #[test]
    fn odd_characters() {
        let expected = Cookie::new("foo", "b%2Fr");
        assert_eq_parse!("foo=b%2Fr", expected);
    }

    #[test]
    #[cfg(feature = "percent-encode")]
    fn parse_encoded_prefix() {
        let cases = [
            "%5F%5FHost-foo", "_%5FHost-foo", "__%48ost-foo", "__Host%2Dfoo",
            "%5f%5fhost-foo", "%5F%5FSecure-foo", "__Secur%65-foo",
            "__%53ecure-foo", "%5F_SECURE%2Dfoo", "%5F%5FHttp-foo",
            "__Http%2Dfoo", "__%68TTP-foo", "%5F%5FHost-Http-foo",
            "__Host-%48ttp-foo", "__Host-Http%2Dfoo", "__host-%68TTP-foo",
        ];

        for case in cases {
            let string = format!("{}=bar", case);
            assert_eq!(Cookie::parse_encoded(string), Err(ParseError::EncodedPrefix));

            let string = format!(" {} = b%20r; Path=/", case);
            assert_eq!(Cookie::parse_encoded(string), Err(ParseError::EncodedPrefix));

            // Without decoding, the name has no prefix.
            let cookie = Cookie::parse(format!("{}=bar", case)).unwrap();
            assert_eq!(cookie.name_value(), (case, "bar"));
        }

        // The prefix, if any, is present before decoding.
        let cases = [
            ("__Host-f%6Fo", "__Host-foo"), ("__Secure-f%6Fo", "__Secure-foo"),
            ("__Http-f%6Fo", "__Http-foo"), ("__Host-Http-f%6Fo", "__Host-Http-foo"),
            ("__host-f%6Fo", "__host-foo"), ("__SECURE-%66oo", "__SECURE-foo"),
            ("__HOST-HTTP-%66oo", "__HOST-HTTP-foo"), ("x%5F%5FHost-foo", "x__Host-foo"),
            ("%5F%5FHos-foo", "__Hos-foo"), ("_%5FSecure_foo", "__Secure_foo"),
            ("__Host-Httpx%2Dfoo", "__Host-Httpx-foo"), ("%20__Host-foo", " __Host-foo"),
            ("f%6Fo", "foo"), ("%5F%5F", "__"),
        ];

        for (string, name) in cases {
            let cookie = Cookie::parse_encoded(format!("{}=b%20r", string)).unwrap();
            assert_eq!(cookie.name_value(), (name, "b r"));
        }

        // The remaining cookies are unaffected.
        let cookies = Cookie::split_parse_encoded("a=1; %5F%5FHost-foo=bar; b=2")
            .map(|cookie| cookie.map(|c| c.name().to_string()))
            .collect::<Vec<_>>();

        let expected = [Ok("a".into()), Err(ParseError::EncodedPrefix), Ok("b".into())];
        assert_eq!(cookies, expected);
    }

    #[test]
    #[cfg(feature = "percent-encode")]
    fn encoded_prefix_roundtrips() {
        for prefix in ["__Host-", "__Secure-", "__Http-", "__Host-Http-", "__HOST-"] {
            let name = format!("{}my name", prefix);
            let string = Cookie::new(name.clone(), "a value").encoded().to_string();
            assert!(string.starts_with(prefix));

            let cookie = Cookie::parse_encoded(string).unwrap();
            assert_eq!(cookie.name_value(), (&*name, "a value"));
        }
    }

    #[test]
    #[cfg(feature = "percent-encode")]
    fn odd_characters_encoded() {
        let expected = Cookie::new("foo", "b/r");
        let cookie = match Cookie::parse_encoded("foo=b%2Fr") {
            Ok(cookie) => cookie,
            Err(e) => panic!("Failed to parse: {:?}", e)
        };

        assert_eq!(cookie, expected);
    }

    #[test]
    fn do_not_panic_on_large_max_ages() {
        let max_seconds = Duration::MAX.as_secs();
        let expected = Cookie::build(("foo", "bar"))
            .max_age(Duration::from_secs(i64::MAX as u64));

        let too_many_seconds = (max_seconds as u128) + 1;
        assert_eq_parse!(format!(" foo=bar; Max-Age={:?}", too_many_seconds), expected);
    }
}
