#![feature(macro_rules)]
#![crate_type = "lib"]

extern crate url;
extern crate time;
extern crate openssl;
extern crate serialize;

use std::collections::TreeMap;
use std::fmt;
use std::from_str::FromStr;

pub use jar::CookieJar;

mod jar;

#[deriving(PartialEq, Clone)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub expires: Option<time::Tm>,
    pub max_age: Option<u64>,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub secure: bool,
    pub httponly: bool,
    pub custom: TreeMap<String, String>,
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
            custom: TreeMap::new(),
        }
    }

    pub fn parse(s: &str) -> Result<Cookie, ()> {
        macro_rules! try_option( ($e:expr) => (
            match $e { Some(s) => s, None => return Err(()) }
        ) )

        let mut c = Cookie::new(String::new(), String::new());
        let mut pairs = s.trim().split(';');
        let keyval = try_option!(pairs.next());
        let (name, value) = try!(split(keyval));
        c.name = try!(url::decode_component(name).map_err(|_| ()));
        c.value = try!(url::decode_component(value).map_err(|_| ()));

        for attr in pairs {
            match attr.trim() {
                "Secure" => c.secure = true,
                "HttpOnly" => c.httponly = true,
                s => {
                    let (k, v) = try!(split(s));
                    match k {
                        "Max-Age" => c.max_age = Some(try_option!(from_str(v))),
                        "Domain" => c.domain = Some(v.to_string()),
                        "Path" => c.path = Some(v.to_string()),
                        "Expires" => {
                            let fmt = "%a, %d %b %Y %H:%M:%S %Z";
                            let tm = try_option!(time::strptime(v, fmt).ok());
                            c.expires = Some(tm);
                        }
                        _ => { c.custom.insert(k.to_string(), v.to_string()); }
                    }
                }
            }
        }

        return Ok(c);

        fn split<'a>(s: &'a str) -> Result<(&'a str, &'a str), ()> {
            let mut parts = s.trim().splitn('=', 1);
            Ok((try_option!(parts.next()), try_option!(parts.next())))
        }
    }
}

impl fmt::Show for Cookie {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(f, "{}={}", self.name,
                    url::encode_component(self.value.as_slice())));
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
            try!(write!(f, "; {}={}", k, url::encode_component(v.as_slice())));
        }
        Ok(())
    }
}

impl FromStr for Cookie {
    fn from_str(s: &str) -> Option<Cookie> {
        Cookie::parse(s).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::Cookie;

    #[test]
    fn parse() {
        let mut expected = Cookie::new("foo".to_string(), "bar".to_string());
        assert_eq!(Cookie::parse("foo=bar").unwrap(), expected);
        assert_eq!(Cookie::parse(" foo=bar ").unwrap(), expected);
        expected.httponly = true;
        assert_eq!(Cookie::parse(" foo=bar ;HttpOnly").unwrap(), expected);
        expected.secure = true;
        assert_eq!(Cookie::parse(" foo=bar ;HttpOnly; Secure").unwrap(), expected);
        expected.max_age = Some(4);
        assert_eq!(Cookie::parse(" foo=bar ;HttpOnly; Secure; \
                                  Max-Age=4").unwrap(), expected);
        expected.path = Some("/foo".to_string());
        assert_eq!(Cookie::parse(" foo=bar ;HttpOnly; Secure; \
                                  Max-Age=4; Path=/foo").unwrap(), expected);
        expected.domain = Some("foo.com".to_string());
        assert_eq!(Cookie::parse(" foo=bar ;HttpOnly; Secure; \
                                  Max-Age=4; Path=/foo; \
                                  Domain=foo.com").unwrap(), expected);
        expected.custom.insert("wut".to_string(), "lol".to_string());
        assert_eq!(Cookie::parse(" foo=bar ;HttpOnly; Secure; \
                                  Max-Age=4; Path=/foo; \
                                  Domain=foo.com; wut=lol").unwrap(), expected);

        assert_eq!(expected.to_string().as_slice(),
                   "foo=bar; HttpOnly; Secure; Path=/foo; Domain=foo.com; \
                    Max-Age=4; wut=lol");
    }

    #[test]
    fn odd_characters() {
        let expected = Cookie::new("foo".to_string(), "b/r".to_string());
        assert_eq!(Cookie::parse("foo=b%2Fr").unwrap(), expected);
    }
}
