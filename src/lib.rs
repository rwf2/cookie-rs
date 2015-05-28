#![doc(html_root_url = "http://alexcrichton.com/cookie-rs")]
#![cfg_attr(test, deny(warnings))]

extern crate url;
extern crate time;

use std::ascii::AsciiExt;
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

pub use jar::CookieJar;
mod jar;

#[derive(PartialEq, Clone, Debug)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub expires: Option<time::Tm>,
    pub max_age: Option<u64>,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub secure: bool,
    pub httponly: bool,
    pub custom: BTreeMap<String, String>,
}


impl Cookie {
    pub fn new(name: String, value: String) -> Cookie {
        Cookie {
            name: name,
            value: value,
            expires: None,
            max_age: None,
            domain: None,
            path: Some("/".to_string()),
            secure: false,
            httponly: false,
            custom: BTreeMap::new(),
        }
    }

    pub fn parse(s: &str) -> Result<Cookie, ()> {
        macro_rules! unwrap_or_skip{ ($e:expr) => (
            match $e { Some(s) => s, None => continue, }
        ) }

        let mut c = Cookie::new(String::new(), String::new());
        let mut pairs = s.trim().split(';');
        let keyval = match pairs.next() { Some(s) => s, _ => return Err(()) };
        let (name, value) = try!(split(keyval));
        let name = url::percent_encoding::percent_decode(name.as_bytes());
        if name.is_empty() {
            return Err(());
        }
        let value = url::percent_encoding::percent_decode(value.as_bytes());
        c.name = try!(String::from_utf8(name).map_err(|_| ()));
        c.value = try!(String::from_utf8(value).map_err(|_| ()));

        for attr in pairs {
            let trimmed = attr.trim();
            match &trimmed.to_ascii_lowercase()[..] {
                "secure" => c.secure = true,
                "httponly" => c.httponly = true,
                _ => {
                    let (k, v) = unwrap_or_skip!(split(trimmed).ok());
                    match &k.to_ascii_lowercase()[..] {
                        "max-age" => c.max_age = Some(unwrap_or_skip!(v.parse().ok())),
                        "domain" => {
                            if v.is_empty() {
                                continue;
                            }

                            let domain = if v.chars().next() == Some('.') {
                                &v[1..]
                            } else {
                                v
                            };
                            c.domain = Some(domain.to_ascii_lowercase());
                        }
                        "path" => c.path = Some(v.to_string()),
                        "expires" => {
                            // Try strptime with three date formats according to
                            // http://tools.ietf.org/html/rfc2616#section-3.3.1
                            // Try additional ones as encountered in the real world.
                            let tm = time::strptime(v, "%a, %d %b %Y %H:%M:%S %Z").or_else(|_| {
                                time::strptime(v, "%A, %d-%b-%y %H:%M:%S %Z")
                            }).or_else(|_| {
                                time::strptime(v, "%a, %d-%b-%Y %H:%M:%S %Z")
                            }).or_else(|_| {
                                time::strptime(v, "%a %b %d %H:%M:%S %Y")
                            });
                            let tm = unwrap_or_skip!(tm.ok());
                            c.expires = Some(tm);
                        }
                        _ => { c.custom.insert(k.to_string(), v.to_string()); }
                    }
                }
            }
        }

        return Ok(c);

        fn split<'a>(s: &'a str) -> Result<(&'a str, &'a str), ()> {
            macro_rules! try {
                ($e:expr) => (match $e { Some(s) => s, None => return Err(()) })
            }
            let mut parts = s.trim().splitn(2, '=');
            let first = try!(parts.next()).trim();
            let second = try!(parts.next()).trim();
            Ok((first, second))
        }
    }

    pub fn pair(&self) -> AttrVal {
        AttrVal(&self.name, &self.value)
    }
}

pub struct AttrVal<'a>(pub &'a str, pub &'a str);

impl<'a> fmt::Display for AttrVal<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let AttrVal(ref attr, ref val) = *self;
        write!(f, "{}={}", attr, url::percent_encoding::percent_encode(
            val.as_bytes(),
            url::percent_encoding::DEFAULT_ENCODE_SET)
        )
    }
}

impl fmt::Display for Cookie {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(AttrVal(&self.name, &self.value).fmt(f));
        if self.httponly { try!(write!(f, "; HttpOnly")); }
        if self.secure { try!(write!(f, "; Secure")); }
        match self.path {
            Some(ref s) => try!(write!(f, "; Path={}", s)),
            None => {}
        }
        match self.domain {
            Some(ref s) => try!(write!(f, "; Domain={}", s)),
            None => {}
        }
        match self.max_age {
            Some(n) => try!(write!(f, "; Max-Age={}", n)),
            None => {}
        }
        match self.expires {
            Some(ref t) => try!(write!(f, "; Expires={}", t.rfc822())),
            None => {}
        }

        for (k, v) in self.custom.iter() {
            try!(write!(f, "; {}", AttrVal(&k, &v)));
        }
        Ok(())
    }
}

impl FromStr for Cookie {
    type Err = ();
    fn from_str(s: &str) -> Result<Cookie, ()> {
        Cookie::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::Cookie;

    #[test]
    fn parse() {
        assert!(Cookie::parse("bar").is_err());
        assert!(Cookie::parse("=bar").is_err());
        assert!(Cookie::parse(" =bar").is_err());
        assert!(Cookie::parse("foo=").is_ok());
        let mut expected = Cookie::new("foo".to_string(), "bar".to_string());
        assert_eq!(Cookie::parse("foo=bar").ok().unwrap(), expected);
        assert_eq!(Cookie::parse("foo = bar").ok().unwrap(), expected);
        assert_eq!(Cookie::parse(" foo=bar ").ok().unwrap(), expected);
        assert_eq!(Cookie::parse(" foo=bar ;Domain=").ok().unwrap(), expected);
        assert_eq!(Cookie::parse(" foo=bar ;Domain= ").ok().unwrap(), expected);
        assert_eq!(Cookie::parse(" foo=bar ;Ignored").ok().unwrap(), expected);
        expected.httponly = true;
        assert_eq!(Cookie::parse(" foo=bar ;HttpOnly").ok().unwrap(), expected);
        assert_eq!(Cookie::parse(" foo=bar ;httponly").ok().unwrap(), expected);
        assert_eq!(Cookie::parse(" foo=bar ;HTTPONLY").ok().unwrap(), expected);
        assert_eq!(Cookie::parse(" foo=bar ; sekure; HTTPONLY").ok().unwrap(), expected);
        expected.secure = true;
        assert_eq!(Cookie::parse(" foo=bar ;HttpOnly; Secure").ok().unwrap(), expected);
        expected.max_age = Some(4);
        assert_eq!(Cookie::parse(" foo=bar ;HttpOnly; Secure; \
                                  Max-Age=4").ok().unwrap(), expected);
        assert_eq!(Cookie::parse(" foo=bar ;HttpOnly; Secure; \
                                  Max-Age = 4 ").ok().unwrap(), expected);
        expected.path = Some("/foo".to_string());
        assert_eq!(Cookie::parse(" foo=bar ;HttpOnly; Secure; \
                                  Max-Age=4; Path=/foo").ok().unwrap(), expected);
        expected.domain = Some("foo.com".to_string());
        assert_eq!(Cookie::parse(" foo=bar ;HttpOnly; Secure; \
                                  Max-Age=4; Path=/foo; \
                                  Domain=foo.com").ok().unwrap(), expected);
        assert_eq!(Cookie::parse(" foo=bar ;HttpOnly; Secure; \
                                  Max-Age=4; Path=/foo; \
                                  Domain=FOO.COM").ok().unwrap(), expected);
        expected.custom.insert("wut".to_string(), "lol".to_string());
        assert_eq!(Cookie::parse(" foo=bar ;HttpOnly; Secure; \
                                  Max-Age=4; Path=/foo; \
                                  Domain=foo.com; wut=lol").ok().unwrap(), expected);

        assert_eq!(expected.to_string(),
                   "foo=bar; HttpOnly; Secure; Path=/foo; Domain=foo.com; \
                    Max-Age=4; wut=lol");
    }

    #[test]
    fn odd_characters() {
        let expected = Cookie::new("foo".to_string(), "b/r".to_string());
        assert_eq!(Cookie::parse("foo=b%2Fr").ok().unwrap(), expected);
    }

    #[test]
    fn pair() {
        let cookie = Cookie::new("foo".to_string(), "bar".to_string());
        assert_eq!(cookie.pair().to_string(), "foo=bar".to_string());
    }
}
