use std::collections::{HashMap, HashSet};
use std::cell::RefCell;
use time;
use serialize::hex::{ToHex, FromHex};

use openssl::crypto::{hmac, hash};

use Cookie;

pub struct CookieJar<'a> {
    flavor: Flavor<'a>,
}

enum Flavor<'a> {
    Child(Child<'a>),
    Root(Root),
}

struct Child<'a> {
    root: &'a Root,
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
    pub fn new(key: &[u8]) -> CookieJar<'static> {
        CookieJar {
            flavor: Root(Root {
                orig_map: HashMap::new(),
                new_map: RefCell::new(HashMap::new()),
                removed_cookies: RefCell::new(HashSet::new()),
                key: key.to_owned(),
            })
        }
    }

    fn root<'a>(&'a self) -> (&'a Root, Read, Write) {
        return match self.flavor {
            Child(ref child) => (child.root, child.read, child.write),
            Root(ref me) => (me, default_read, default_write),
        };

        fn default_read(_: &Root, cookie: Cookie) -> Option<Cookie> {
            Some(cookie)
        }
        fn default_write(_: &Root, cookie: Cookie) -> Cookie { cookie }
    }

    pub fn add_original(&mut self, cookie: Cookie) {
        match self.flavor {
            Child(..) => fail!("can't add an original cookie to a child jar!"),
            Root(ref mut root) => {
                let name = cookie.name.clone();
                root.orig_map.insert(name, cookie);
            }
        }
    }

    pub fn add(&self, cookie: Cookie) {
        let name = cookie.name.clone();
        let (root, _, write) = self.root();
        let cookie = write(root, cookie);
        root.removed_cookies.borrow_mut().remove(&name);
        root.new_map.borrow_mut().insert(name, cookie);
    }

    pub fn remove(&self, cookie: &str) {
        let (root, _, _) = self.root();
        let cookie = cookie.to_string();
        root.new_map.borrow_mut().remove(&cookie);
        root.removed_cookies.borrow_mut().insert(cookie);
    }

    pub fn find<'a>(&'a self, name: &str) -> Option<Cookie> {
        let name = name.to_string();
        let (root, read, _) = self.root();
        if root.removed_cookies.borrow().contains(&name) {
            return None
        }
        let ret = root.new_map.borrow().find(&name)
                      .or_else(|| root.orig_map.find(&name))
                      .map(|c| c.clone());
        ret.and_then(|c| read(root, c))
    }

    pub fn signed<'a>(&'a self) -> CookieJar<'a> {
        return CookieJar {
            flavor: Child(Child {
                root: self.root().val0(),
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
                if signature.from_hex().ok() != Some(dosign(root, text)) {
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

    pub fn delta(&self) -> Vec<String> {
        let mut ret = Vec::new();
        let (root, _, _) = self.root();
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
        cookie.value.push_char('l');
        c.add(cookie);
        assert!(c.signed().find("test").is_none());

        let mut cookie = c.find("test").unwrap();
        cookie.value = "foobar".to_string();
        c.add(cookie);
        assert!(c.signed().find("test").is_none());
    }
}
