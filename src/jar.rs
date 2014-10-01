//! A cookie jar implementation for storing a set of cookies.
//!
//! This CookieJar type can be used to manage a session of cookies by keeping
//! track of cookies that are added and deleted over time. It provides a method,
//! `delta`, which will calculate the number of `Set-Cookie` headers that need
//! to be sent back to a client which tracks the changes in the lifetime of the
//! jar itself.
//!
//! A cookie jar can also be borrowed to a child cookie jar with new
//! functionality such as automatically signing cookies, storing permanent
//! cookies, etc. This functionality can also be chaned together.

use std::collections::{HashMap, HashSet};
use std::cell::RefCell;
use time;
use serialize::hex::{ToHex, FromHex};

use openssl::crypto::{hmac, hash, memcmp};

use Cookie;

/// A jar of cookies for managing a session
///
/// # Example
///
/// ```
/// # extern crate cookie;
/// # fn main() {
/// use cookie::{Cookie, CookieJar};
///
/// let c = CookieJar::new(b"signing-key");
///
/// // Add a cookie to this jar
/// c.add(Cookie::new("key".to_string(), "value".to_string()));
///
/// // Remove the added cookie
/// c.remove("test");
///
/// // Add a signed cookie to the jar
/// c.signed().add(Cookie::new("key".to_string(), "value".to_string()));
///
/// // Add a permanently signed cookie to the jar
/// c.permanent().signed()
///  .add(Cookie::new("key".to_string(), "value".to_string()));
/// # }
/// ```
pub struct CookieJar<'a> {
    flavor: Flavor<'a>,
}

enum Flavor<'a> {
    FlavorChild(Child<'a>),
    FlavorRoot(Root),
}

struct Child<'a> {
    parent: &'a CookieJar<'a>,
    read: Read,
    write: Write,
}

type Read = fn(&Root, Cookie) -> Option<Cookie>;
type Write = fn(&Root, Cookie) -> Cookie;

struct Root {
    orig_map: HashMap<String, Cookie>,
    new_map: RefCell<HashMap<String, Cookie>>,
    removed_cookies: RefCell<HashSet<String>>,
    key: Vec<u8>,
}

impl<'a> CookieJar<'a> {
    /// Creates a new empty cookie jar with the given signing key.
    ///
    /// The given key is used to sign cookies in the signed cookie jar.
    pub fn new(key: &[u8]) -> CookieJar<'static> {
        CookieJar {
            flavor: FlavorRoot(Root {
                orig_map: HashMap::new(),
                new_map: RefCell::new(HashMap::new()),
                removed_cookies: RefCell::new(HashSet::new()),
                key: key.to_vec(),
            })
        }
    }

    fn root<'a>(&'a self) -> &'a Root {
        let mut cur = self;
        loop {
            match cur.flavor {
                FlavorChild(ref child) => cur = child.parent,
                FlavorRoot(ref me) => return me,
            }
        }
    }

    /// Adds an original cookie from a request.
    ///
    /// This method only works on the root cookie jar and is not intended for
    /// use during the lifetime of a request, it is intended to initialize a
    /// cookie jar from an incoming request.
    pub fn add_original(&mut self, cookie: Cookie) {
        match self.flavor {
            FlavorChild(..) => fail!("can't add an original cookie to a child jar!"),
            FlavorRoot(ref mut root) => {
                let name = cookie.name.clone();
                root.orig_map.insert(name, cookie);
            }
        }
    }

    /// Adds a new cookie to this cookie jar.
    ///
    /// If this jar is a child cookie jar, this will walk up the chain of
    /// borrowed jars, modifying the cookie as it goes along.
    pub fn add(&self, mut cookie: Cookie) {
        let mut cur = self;
        let root = self.root();
        loop {
            match cur.flavor {
                FlavorChild(ref child) => {
                    cookie = (child.write)(root, cookie);
                    cur = child.parent;
                }
                FlavorRoot(..) => break,
            }
        }
        let name = cookie.name.clone();
        root.removed_cookies.borrow_mut().remove(&name);
        root.new_map.borrow_mut().insert(name, cookie);
    }

    /// Removes a cookie from this cookie jar.
    pub fn remove(&self, cookie: &str) {
        let root = self.root();
        let cookie = cookie.to_string();
        root.new_map.borrow_mut().remove(&cookie);
        root.removed_cookies.borrow_mut().insert(cookie);
    }

    /// Finds a cookie inside of this cookie jar.
    ///
    /// The cookie is subject to modification by any of the child cookie jars
    /// that are currently borrowed. A copy of the cookie is returned.
    pub fn find(&self, name: &str) -> Option<Cookie> {
        let name = name.to_string();
        let root = self.root();
        if root.removed_cookies.borrow().contains(&name) {
            return None
        }
        let mut ret = root.new_map.borrow().find(&name)
                          .or_else(|| root.orig_map.find(&name))
                          .map(|c| c.clone());
        let mut cur = self;
        loop {
            match (&cur.flavor, ret) {
                (_, None) => return None,
                (&FlavorChild(Child { read, parent, .. }), Some(cookie)) => {
                    ret = read(root, cookie);
                    cur = parent;
                }
                (&FlavorRoot(..), Some(cookie)) => return Some(cookie),
            }
        }
    }

    /// Creates a child signed cookie jar.
    ///
    /// All cookies read from the child jar will require a valid signature and
    /// all cookies written will be signed automatically.
    pub fn signed<'a>(&'a self) -> CookieJar<'a> {
        return CookieJar {
            flavor: FlavorChild(Child {
                parent: self,
                read: design,
                write: sign,
            })
        };

        // If a SHA1 HMAC is good enough for rails, it's probably good enough
        // for us as well:
        //
        // https://github.com/rails/rails/blob/master/activesupport/lib
        //                   /active_support/message_verifier.rb#L70
        fn sign(root: &Root, mut cookie: Cookie) -> Cookie {
            let signature = dosign(root, cookie.value.as_slice());
            cookie.value.push_str("--");
            cookie.value.push_str(signature.as_slice().to_hex().as_slice());
            cookie
        }

        fn design(root: &Root, mut cookie: Cookie) -> Option<Cookie> {
            let len = {
                let mut parts = cookie.value.as_slice().split_str("--");
                let signature = match parts.last() {
                    Some(sig) => sig,
                    _ => return None,
                };
                if signature.len() == cookie.value.len() { return None }
                let text = cookie.value.as_slice().slice_to(cookie.value.len() -
                                                            signature.len() - 2);
                let actual = match signature.from_hex() {
                    Ok(sig) => sig, Err(..) => return None,
                };
                let expected = dosign(root, text);
                if !memcmp::eq(expected.as_slice(), actual.as_slice()) {
                    return None
                }
                text.len()
            };
            cookie.value.truncate(len);
            Some(cookie)
        }

        fn dosign(root: &Root, val: &str) -> Vec<u8> {
            let mut hmac = hmac::HMAC(hash::SHA1, root.key.as_slice());
            hmac.update(val.as_bytes());
            hmac.final()
        }
    }

    /// Creates a child jar for permanent cookie storage.
    ///
    /// All cookies written to the child jar will have an expiration date 20
    /// years into the future to ensure they stick around for a long time.
    pub fn permanent<'a>(&'a self) -> CookieJar<'a> {
        return CookieJar {
            flavor: FlavorChild(Child {
                parent: self,
                read: read,
                write: write,
            })
        };

        fn read(_root: &Root, cookie: Cookie) -> Option<Cookie> {
            Some(cookie)
        }

        fn write(_root: &Root, mut cookie: Cookie) -> Cookie {
            // Expire 20 years in the future
            cookie.max_age = Some(3600 * 24 * 365 * 20);
            let mut now = time::now();
            now.tm_year += 20;
            cookie.expires = Some(now);
            cookie
        }
    }

    /// Calculates the changes that have occurred to this cookie jar over time,
    /// returning a vector of `Set-Cookie` headers.
    pub fn delta(&self) -> Vec<String> {
        let mut ret = Vec::new();
        let root = self.root();
        for cookie in root.removed_cookies.borrow().iter() {
            let mut c = Cookie::new(cookie.clone(), String::new());
            c.max_age = Some(0);
            let mut now = time::now();
            now.tm_year -= 1;
            c.expires = Some(now);
            ret.push(c.to_string());
        }
        for (_, cookie) in root.new_map.borrow().iter() {
            ret.push(cookie.to_string());
        }
        return ret;
    }
}

#[cfg(test)]
mod test {
    use {Cookie, CookieJar};

    #[test]
    fn simple() {
        let c = CookieJar::new(b"foo");

        c.add(Cookie::new("test".to_string(), "".to_string()));
        c.add(Cookie::new("test2".to_string(), "".to_string()));
        c.remove("test");

        assert!(c.find("test").is_none());
        assert!(c.find("test2").is_some());
    }

    #[test]
    fn signed() {
        let c = CookieJar::new(b"foo");

        c.signed().add(Cookie::new("test".to_string(), "test".to_string()));
        assert!(c.find("test").unwrap().value.as_slice() != "test");
        assert!(c.signed().find("test").unwrap().value.as_slice() == "test");

        let mut cookie = c.find("test").unwrap();
        cookie.value.push('l');
        c.add(cookie);
        assert!(c.signed().find("test").is_none());

        let mut cookie = c.find("test").unwrap();
        cookie.value = "foobar".to_string();
        c.add(cookie);
        assert!(c.signed().find("test").is_none());
    }

    #[test]
    fn permanent() {
        let c = CookieJar::new(b"foo");

        c.permanent().add(Cookie::new("test".to_string(), "test".to_string()));

        let cookie = c.find("test").unwrap();
        assert_eq!(cookie.value.as_slice(), "test");
        assert_eq!(c.permanent().find("test").unwrap().value.as_slice(), "test");
        assert!(cookie.expires.is_some());
        assert!(cookie.max_age.is_some());
    }

    #[test]
    fn chained() {
        let c = CookieJar::new(b"foo");

        c.permanent().signed()
         .add(Cookie::new("test".to_string(), "test".to_string()));

        let cookie = c.signed().find("test").unwrap();
        assert_eq!(cookie.value.as_slice(), "test");
        assert!(cookie.expires.is_some());
        assert!(cookie.max_age.is_some());
    }
}
