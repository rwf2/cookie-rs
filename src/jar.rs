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
//! cookies, etc. This functionality can also be chained together.


use std::collections::{HashMap, HashSet};
use std::cell::RefCell;
use std::fmt;
use time;

use Cookie;

/// A jar of cookies for managing a session
///
/// # Example
///
/// ```
/// use cookie::{Cookie, CookieJar};
///
/// let c = CookieJar::new(b"f8f9eaf1ecdedff5e5b749c58115441e");
///
/// // Add a cookie to this jar
/// c.add(Cookie::new("key".to_string(), "value".to_string()));
///
/// // Remove the added cookie
/// c.remove("key");
///
/// ```
pub struct CookieJar<'a> {
    flavor: Flavor<'a>,
}

enum Flavor<'a> {
    Child(Child<'a>),
    Root(Root),
}

struct Child<'a> {
    parent: &'a CookieJar<'a>,
    read: Read,
    write: Write,
}

type Read = fn(&Root, Cookie) -> Option<Cookie>;
type Write = fn(&Root, Cookie) -> Cookie;

#[cfg(feature = "secure")]
struct SecureKeys {
    key256: [u8; 256 / 8],
    key512: [u8; 512 / 8],
}

struct Root {
    map: RefCell<HashMap<String, Cookie>>,
    new_cookies: RefCell<HashSet<String>>,
    removed_cookies: RefCell<HashSet<String>>,
    #[cfg(feature = "secure")]
    keys: SecureKeys,
}

/// Iterator over the cookies in a cookie jar
pub struct Iter<'a> {
    jar: &'a CookieJar<'a>,
    keys: Vec<String>,
}

impl<'a> CookieJar<'a> {
    /// Creates a new empty cookie jar with the given secret.
    ///
    /// The given secret is used to generate keys which are used to sign
    /// cookies in the signed cookie jar.
    pub fn new(secret: &[u8]) -> CookieJar<'static> {
        CookieJar::_new(secret)
    }

    #[cfg(feature = "secure")]
    fn _new(secret: &[u8]) -> CookieJar<'static> {
        let (key256, key512) = secure::generate_keys(secret);
        CookieJar {
            flavor: Flavor::Root(Root {
                map: RefCell::new(HashMap::new()),
                new_cookies: RefCell::new(HashSet::new()),
                removed_cookies: RefCell::new(HashSet::new()),
                keys: SecureKeys {
                    key256: key256,
                    key512: key512,
                },
            })
        }
    }
    #[cfg(not(feature = "secure"))]
    fn _new(_secret: &[u8]) -> CookieJar<'static> {
        CookieJar {
            flavor: Flavor::Root(Root {
                map: RefCell::new(HashMap::new()),
                new_cookies: RefCell::new(HashSet::new()),
                removed_cookies: RefCell::new(HashSet::new()),
            })
        }
    }

    fn root<'b>(&'b self) -> &'b Root {
        let mut cur = self;
        loop {
            match cur.flavor {
                Flavor::Child(ref child) => cur = child.parent,
                Flavor::Root(ref me) => return me,
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
            Flavor::Child(..) => panic!("can't add an original cookie to a child jar!"),
            Flavor::Root(ref mut root) => {
                let name = cookie.name.clone();
                root.map.borrow_mut().insert(name, cookie);
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
                Flavor::Child(ref child) => {
                    cookie = (child.write)(root, cookie);
                    cur = child.parent;
                }
                Flavor::Root(..) => break,
            }
        }
        let name = cookie.name.clone();
        root.map.borrow_mut().insert(name.clone(), cookie);
        root.removed_cookies.borrow_mut().remove(&name);
        root.new_cookies.borrow_mut().insert(name);
    }

    /// Removes a cookie from this cookie jar.
    pub fn remove(&self, cookie: &str) {
        let root = self.root();
        let cookie = cookie.to_string();
        root.map.borrow_mut().remove(&cookie);
        root.new_cookies.borrow_mut().remove(&cookie);
        root.removed_cookies.borrow_mut().insert(cookie);
    }

    /// Clears all cookies from this cookie jar.
    pub fn clear(&self) {
        let root = self.root();
        let all_cookies: Vec<_> = root.map.borrow().keys().map(|n| n.to_owned()).collect();
        root.map.borrow_mut().clear();
        root.new_cookies.borrow_mut().clear();
        root.removed_cookies.borrow_mut().extend(all_cookies);
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
        root.map.borrow().get(&name).and_then(|c| self.try_read(root, c.clone()))
    }

    /// Creates a child signed cookie jar.
    ///
    /// All cookies read from the child jar will require a valid signature and
    /// all cookies written will be signed automatically.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use cookie::{Cookie, CookieJar};
    /// let c = CookieJar::new(b"f8f9eaf1ecdedff5e5b749c58115441e");
    ///
    /// // Add a signed cookie to the jar
    /// c.signed().add(Cookie::new("key".to_string(), "value".to_string()));
    ///
    /// // Add a permanently signed cookie to the jar
    /// c.permanent().signed()
    ///  .add(Cookie::new("key".to_string(), "value".to_string()));
    /// ```
    #[cfg(feature = "secure")]
    pub fn signed<'b>(&'b self) -> CookieJar<'b> {
        return CookieJar {
            flavor: Flavor::Child(Child {
                parent: self,
                read: design,
                write: sign,
            })
        };

        fn design(root: &Root, cookie: Cookie) -> Option<Cookie> {
            secure::design(&root.keys.key512, cookie)
        }
        fn sign(root: &Root, cookie: Cookie) -> Cookie {
            secure::sign(&root.keys.key512, cookie)
        }
    }

    /// Creates a child encrypted cookie jar.
    ///
    /// All cookies read from the child jar must be encrypted and signed by a
    /// valid key and all cookies written will be encrypted and signed
    /// automatically.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use cookie::{Cookie, CookieJar};
    /// let c = CookieJar::new(b"f8f9eaf1ecdedff5e5b749c58115441e");
    ///
    /// // Add a signed and encrypted cookie to the jar
    /// c.encrypted().add(Cookie::new("key".to_string(), "value".to_string()));
    ///

    /// // Add a permanently signed and encrypted cookie to the jar
    /// c.permanent().encrypted()
    ///  .add(Cookie::new("key".to_string(), "value".to_string()));
    /// ```
    #[cfg(feature = "secure")]
    pub fn encrypted<'b>(&'b self) -> CookieJar<'b> {
        return CookieJar {
            flavor: Flavor::Child(Child {
                parent: self,
                read: read,
                write: write,
            })
        };
        fn read(root: &Root, cookie: Cookie) -> Option<Cookie> {
            secure::design_and_decrypt(&root.keys.key256, cookie).ok()
        }
        fn write(root: &Root, cookie: Cookie) -> Cookie {
            secure::encrypt_and_sign(&root.keys.key256, cookie)
        }
    }

    /// Creates a child jar for permanent cookie storage.
    ///
    /// All cookies written to the child jar will have an expiration date 20
    /// years into the future to ensure they stick around for a long time.
    pub fn permanent<'b>(&'b self) -> CookieJar<'b> {
        return CookieJar {
            flavor: Flavor::Child(Child {
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
    pub fn delta(&self) -> Vec<Cookie> {
        let mut ret = Vec::new();
        let root = self.root();
        for cookie in root.removed_cookies.borrow().iter() {
            let mut c = Cookie::new(cookie.clone(), String::new());
            c.max_age = Some(0);
            let mut now = time::now();
            now.tm_year -= 1;
            c.expires = Some(now);
            ret.push(c);
        }
        let map = root.map.borrow();
        for cookie in root.new_cookies.borrow().iter() {
            ret.push(map.get(cookie).unwrap().clone());
        }
        return ret;
    }

    fn try_read(&self, root: &Root, mut cookie: Cookie) -> Option<Cookie> {
        let mut jar = self;
        loop {
            match jar.flavor {
                Flavor::Child(Child { read, parent, .. }) => {
                    cookie = match read(root, cookie) {
                        Some(c) => c, None => return None,
                    };
                    jar = parent;
                }
                Flavor::Root(..) => return Some(cookie),
            }
        }
    }

    /// Return an iterator over the cookies in this jar.
    ///
    /// This iterator will only yield valid cookies for this jar. For example if
    /// this is an encrypted child jar then only valid encrypted cookies will be
    /// yielded. If the root cookie jar is iterated over then all cookies will
    /// be yielded.
    pub fn iter(&self) -> Iter {
        let map = self.root().map.borrow();
        Iter { jar: self, keys: map.keys().cloned().collect() }
    }
}

impl<'a> fmt::Debug for CookieJar<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let root = self.root();
        try!(write!(f, "CookieJar {{"));
        let mut first = true;
        for (name, cookie) in &*root.map.borrow() {
            if !first {
                try!(write!(f, ", "));
            }
            first = false;
            try!(write!(f, "{:?}: {:?}", name, cookie));
        }
        try!(write!(f, " }}"));
        Ok(())
    }
}

impl<'a> Iterator for Iter<'a> {
    type Item = Cookie;

    fn next(&mut self) -> Option<Cookie> {
        loop {
            let key = match self.keys.pop() {
                Some(v) => v,
                None => return None,
            };
            let root = self.jar.root();
            let map = root.map.borrow();
            let cookie = match map.get(&key) {
                Some(cookie) => cookie.clone(),
                None => continue,
            };
            match self.jar.try_read(root, cookie) {
                Some(cookie) => return Some(cookie),
                None => {}
            }
        }
    }
}

#[cfg(feature = "secure")]
mod secure {
    extern crate ring;
    extern crate rustc_serialize;

    use Cookie;
    use self::ring::{aead, digest, hmac, rand, pbkdf2};
    use self::rustc_serialize::base64::{ToBase64, FromBase64, STANDARD};

    /// Algorithm used to sign the cookie value
    static SIGNING_ALGORITHM: &'static digest::Algorithm = &digest::SHA1;
    /// Separator between cookie value and signature
    static SIGNATURE_SEPARATOR: &'static str = "--";
    /// Key length (in bytes) used for signing
    const SIGNING_KEY_LEN: usize = 512 / 8;

    /// Algorithm used to encrypt the cookie value
    static ENCRYPTION_ALGORITHM: &'static aead::Algorithm =
        &aead::CHACHA20_POLY1305;
    /// Separator between sealed cookie value and nonce
    static SEALED_NONCE_SEPARATOR: &'static str = "--";
    /// Key length (in bytes) used for encryption
    const ENCRYPTION_KEY_LEN: usize = 256 / 8;

    /// Number of iterations for PBKDF2 when deriving keys
    const PBKDF2_ITERATIONS: usize = 10_000;

    pub fn sign(key: &[u8], mut cookie: Cookie) -> Cookie {
        assert_eq!(key.len(), SIGNING_KEY_LEN);
        let signing_key = hmac::SigningKey::new(SIGNING_ALGORITHM, key);
        let signature = hmac::sign(&signing_key, cookie.value.as_bytes());
        cookie.value.push_str(SIGNATURE_SEPARATOR);
        cookie.value.push_str(&signature.as_ref().to_base64(STANDARD));
        cookie
    }

    fn split_value(val: &str) -> Option<(&str, Vec<u8>)> {
        let parts = val.split(SIGNATURE_SEPARATOR);
        let ext = match parts.last() {
            Some(ext) => ext,
            _ => return None,
        };
        let val_len = val.len();
        if ext.len() == val_len { return None }
        let text = &val[..val_len - ext.len() - 2];
        let ext = match ext.from_base64() {
            Ok(sig) => sig, Err(..) => return None,
        };

        Some((text, ext))
    }

    pub fn design(key: &[u8], mut cookie: Cookie) -> Option<Cookie> {
        assert_eq!(key.len(), SIGNING_KEY_LEN);
        let signed_value = cookie.value;
        let (text, signature) = match split_value(&signed_value) {
            Some(pair) => pair, None => return None
        };
        let verification_key =
            hmac::VerificationKey::new(SIGNING_ALGORITHM, key);
        let is_valid_signature = hmac::verify(
            &verification_key, text.as_bytes(), &signature).is_ok();
        if is_valid_signature {
            cookie.value = text.to_owned();
            Some(cookie)
        } else {
            None
        }
    }

    pub fn encrypt_and_sign(key: &[u8], mut cookie: Cookie) -> Cookie {
        assert_eq!(key.len(), ENCRYPTION_KEY_LEN);
        let sealing_key = aead::SealingKey::new(ENCRYPTION_ALGORITHM, key)
            .expect("could not create aead sealing key");
        let value_len = cookie.value.as_bytes().len();
        let overhead_len = ENCRYPTION_ALGORITHM.max_overhead_len();

        // Prepare bytes to be sealed
        let in_out_len = cookie.value.as_bytes().len() + overhead_len;
        let mut in_out = vec![0; in_out_len];
        in_out[..value_len].clone_from_slice(cookie.value.as_bytes());

        // Initialize nonce
        let mut nonce = vec![0; ENCRYPTION_ALGORITHM.nonce_len()];
        let system_random = rand::SystemRandom::new();
        system_random.fill(&mut nonce)
            .expect("could not generate random nonce");

        // Seal the plaintext cookie value
        let out_len = aead::seal_in_place(
            &sealing_key, &nonce, &mut in_out, overhead_len, &[])
                .expect("could not seal");
        let sealed = &in_out[..out_len];
        
        // Build the final cookie value, combining sealed and nonce
        cookie.value = build_encrypted(sealed, &nonce);

        cookie
    }

    /// Given sealed and nonce bytes, build an encrypted cookie value
    fn build_encrypted(sealed: &[u8], nonce: &[u8]) -> String {
        let mut encrypted = sealed.to_base64(STANDARD);
        encrypted.push_str(SEALED_NONCE_SEPARATOR);
        encrypted.push_str(&nonce.to_base64(STANDARD));
        encrypted
    }

    /// Given an encrypted cookie value, split it into sealed and nonce bytes
    fn split_encrypted(encrypted: &str) -> Result<(Vec<u8>, Vec<u8>), ()> {
        let mut parts =
            encrypted.splitn(2, SEALED_NONCE_SEPARATOR)
                .filter_map(|n| n.from_base64().ok());
        match (parts.next(), parts.next()) {
            (Some(in_out), Some(nonce)) => Ok((in_out, nonce)),
            (_, _)=> Err(()),
        }
    }

    pub fn design_and_decrypt(key: &[u8], mut cookie: Cookie)
        -> Result<Cookie, ()>
    {
        assert_eq!(key.len(), ENCRYPTION_KEY_LEN);
        let (mut in_out, nonce) = try!(split_encrypted(&cookie.value));
        let opening_key = aead::OpeningKey::new(ENCRYPTION_ALGORITHM, key)
            .expect("could not create aead opening key");
        let out_len = try!(
            aead::open_in_place(&opening_key, &nonce, 0, &mut in_out, &[])
                .map_err(|_| ()));
        let decrypted = try!(
            String::from_utf8(in_out[..out_len].into()).map_err(|_| ()));
        cookie.value = decrypted;
        Ok(cookie)
    }

    pub fn generate_keys(secret: &[u8]) -> ([u8; 32], [u8; 64]) {
        let mut key256 = [0; 256 / 8];
        let mut key512 = [0; 512 / 8];
        pbkdf2::derive(
            &pbkdf2::HMAC_SHA256, PBKDF2_ITERATIONS, &[], secret, &mut key256);
        pbkdf2::derive(
            &pbkdf2::HMAC_SHA512, PBKDF2_ITERATIONS, &[], secret, &mut key512);
        (key256, key512)
    }
}

#[cfg(test)]
mod test {
    use {Cookie, CookieJar};

    #[cfg(feature = "secure")]
    const SHORT_KEY: &'static [u8] = b"foo";

    const KEY: &'static [u8] = b"f8f9eaf1ecdedff5e5b749c58115441e";

    #[cfg(feature = "secure")]
    const LONG_KEY: &'static [u8] =
        b"ff8f9eaf1ecdedff5e5b749c58115441ef8f9eaf1ecdedff5e5b749c58115441ef\
          9eaf1ecdedff5e5b749c58115441e8f9eaf1ecdedff5e5b749c58115441eef8f9a";

    #[test]
    fn short_key() {
        CookieJar::new(b"foo");
    }

    #[test]
    fn simple() {
        let c = CookieJar::new(KEY);

        c.add(Cookie::new("test".to_string(), "".to_string()));
        c.add(Cookie::new("test2".to_string(), "".to_string()));
        c.remove("test");

        assert!(c.find("test").is_none());
        assert!(c.find("test2").is_some());

        c.add(Cookie::new("test3".to_string(), "".to_string()));
        c.clear();

        assert!(c.find("test").is_none());
        assert!(c.find("test2").is_none());
        assert!(c.find("test3").is_none());
    }

    macro_rules! secure_behaviour {
        ($c:ident, $secure:ident) => ({
            $c.$secure().add(Cookie::new("test".to_string(), "test".to_string()));
            assert!($c.find("test").unwrap().value != "test");
            assert!($c.$secure().find("test").unwrap().value == "test");

            let mut cookie = $c.find("test").unwrap();
            cookie.value.push('l');
            $c.add(cookie);
            assert!($c.$secure().find("test").is_none());

            let mut cookie = $c.find("test").unwrap();
            cookie.value = "foobar".to_string();
            $c.add(cookie);
            assert!($c.$secure().find("test").is_none());
        })
    }

    #[cfg(feature = "secure")]
    #[test]
    fn signed() {
        let c = CookieJar::new(KEY);
        secure_behaviour!(c, signed);

        let c = CookieJar::new(SHORT_KEY);
        secure_behaviour!(c, signed);

        let c = CookieJar::new(LONG_KEY);
        secure_behaviour!(c, signed);
    }

    #[cfg(feature = "secure")]
    #[test]
    fn encrypted() {
        let c = CookieJar::new(KEY);
        secure_behaviour!(c, encrypted);

        let c = CookieJar::new(SHORT_KEY);
        secure_behaviour!(c, encrypted);

        let c = CookieJar::new(LONG_KEY);
        secure_behaviour!(c, encrypted);
    }

    #[test]
    fn permanent() {
        let c = CookieJar::new(KEY);

        c.permanent().add(Cookie::new("test".to_string(), "test".to_string()));

        let cookie = c.find("test").unwrap();
        assert_eq!(cookie.value, "test");
        assert_eq!(c.permanent().find("test").unwrap().value, "test");
        assert!(cookie.expires.is_some());
        assert!(cookie.max_age.is_some());
    }

    #[cfg(features = "secure")]
    #[test]
    fn chained() {
        let c = CookieJar::new(KEY);

        c.permanent().signed()
         .add(Cookie::new("test".to_string(), "test".to_string()));

        let cookie = c.signed().find("test").unwrap();
        assert_eq!(cookie.value, "test");
        assert!(cookie.expires.is_some());
        assert!(cookie.max_age.is_some());
    }

    #[cfg(features = "secure")]
    #[test]
    fn iter() {
        let mut c = CookieJar::new(KEY);

        c.add_original(Cookie::new("original".to_string(),
                                   "original".to_string()));

        c.add(Cookie::new("test".to_string(), "test".to_string()));
        c.add(Cookie::new("test2".to_string(), "test2".to_string()));
        c.add(Cookie::new("test3".to_string(), "test3".to_string()));
        c.add(Cookie::new("test4".to_string(), "test4".to_string()));

        c.signed()
         .add(Cookie::new("signed".to_string(), "signed".to_string()));

        c.encrypted()
         .add(Cookie::new("encrypted".to_string(), "encrypted".to_string()));

        c.remove("test");

        let cookies = c.iter().collect::<Vec<_>>();
        assert_eq!(cookies.len(), 6);

        let encrypted_cookies = c.encrypted().iter().collect::<Vec<_>>();
        assert_eq!(encrypted_cookies.len(), 1);
        assert_eq!(encrypted_cookies[0].name, "encrypted");

        let signed_cookies = c.signed().iter().collect::<Vec<_>>();
        assert_eq!(signed_cookies.len(), 2);
        assert!(signed_cookies[0].name == "signed" ||
                signed_cookies[1].name == "signed");
    }
}
