use secure::ring::aead::{seal_in_place, open_in_place, Algorithm, AES_256_GCM};
use secure::ring::aead::{OpeningKey, SealingKey};
use secure::ring::rand::SystemRandom;

use secure::rustc_serialize::base64::{ToBase64, FromBase64, STANDARD};

use {Cookie, CookieJar};

// Keep these in sync, and keep the key len synced with the `private` docs.
static ALGO: &'static Algorithm = &AES_256_GCM;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const BASE64_NONCE_LEN: usize = 16;

/// Extends `CookieJar` with a `private` method to retrieve a private child jar.
pub trait Private<'a, 'k> {
    /// Returns a `PrivateJar` with `self` as its parent jar using the key `key`
    /// to sign/encrypt and verify/decrypt cookies added/retrieved from the
    /// child jar. The key must be exactly 32 bytes. For security, the key
    /// _must_ be cryptographically random.
    ///
    /// Any modifications to the child jar will be reflected on the parent jar,
    /// and any retrievals from the child jar will be made from the parent jar.
    ///
    /// This trait is only available when the `secure` feature is enabled.
    ///
    /// # Panics
    ///
    /// Panics if `key` is not exactly 32 bytes long.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::{Cookie, CookieJar, Private};
    ///
    /// // We use a bogus key for demonstration purposes.
    /// let key: Vec<_> = (0..32).collect();
    ///
    /// // Add a private (signed + encrypted) cookie.
    /// let mut jar = CookieJar::new();
    /// jar.private(&key).add(Cookie::new("private", "text"));
    ///
    /// // The cookie's contents are encrypted.
    /// assert_ne!(jar.get("private").unwrap().value(), "text");
    ///
    /// // They can be decrypted and verified through the child jar.
    /// assert_eq!(jar.private(&key).get("private").unwrap().value(), "text");
    ///
    /// // A tampered with cookie does not validate but still exists.
    /// let mut cookie = jar.get("private").unwrap().clone();
    /// jar.add(Cookie::new("private", cookie.value().to_string() + "!"));
    /// assert!(jar.private(&key).get("private").is_none());
    /// assert!(jar.get("private").is_some());
    /// ```
    fn private(&'a mut self, &'k [u8]) -> PrivateJar<'a, 'k>;
}

impl<'a, 'k> Private<'a, 'k> for CookieJar {
    fn private(&'a mut self, key: &'k [u8]) -> PrivateJar<'a, 'k> {
        if key.len() != KEY_LEN {
            panic!("bad key length: expected {} bytes, found {}", KEY_LEN, key.len());
        }

        PrivateJar { parent: self, key: key }
    }
}

/// A child cookie jar that provides authenticated encryption for its cookies.
///
/// A _private_ child jar signs and encrypts all the cookies added to it and
/// verifies and decrypts cookies retrieved from it. Any cookies stored in a
/// `PrivateJar` are simultaneously assured confidentiality, integrity, and
/// authenticity. In other words, clients cannot discover nor tamper with the
/// contents of a cookie, nor can they fabricate cookie data.
///
/// This type is only available when the `secure` feature is enabled.
pub struct PrivateJar<'a, 'k> {
    parent: &'a mut CookieJar,
    key: &'k [u8]
}

impl<'a, 'k> PrivateJar<'a, 'k> {
    /// Given a sealed value `str` where the nonce is prepended to `value`,
    /// verifies and decrypts the sealed value and returns it. If there's an
    /// problem, returns an `Err` with a string describing the issue.
    ///
    /// # Panics
    ///
    /// Panics if `value.len()` < BASE64_NONCE_LEN.
    fn unseal(&self, value: &str) -> Result<String, &'static str> {
        let (nonce_s, sealed_s) = value.split_at(BASE64_NONCE_LEN);
        let nonce = nonce_s.from_base64().map_err(|_| "bad nonce base64")?;
        let mut sealed = sealed_s.from_base64().map_err(|_| "bad sealed base64")?;
        let key = OpeningKey::new(ALGO, self.key).expect("opening key");

        let out_len = open_in_place(&key, &nonce, 0, &mut sealed, &[])
            .map_err(|_| "invalid key/nonce/value: bad seal")?;

        unsafe { sealed.set_len(out_len); }
        String::from_utf8(sealed).map_err(|_| "bad unsealed utf8")
    }

    /// Returns a reference to the `Cookie` inside this jar with the name `name`
    /// and authenticates and decrypts the cookie's value, returning a `Cookie`
    /// with the decrypted value. If the cookie cannot be found, or the cookie
    /// fails to authenticate or decrypt, `None` is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::{CookieJar, Cookie, Private};
    ///
    /// # let key: Vec<_> = (0..32).collect();
    /// let mut jar = CookieJar::new();
    /// let mut private_jar = jar.private(&key);
    /// assert!(private_jar.get("name").is_none());
    ///
    /// private_jar.add(Cookie::new("name", "value"));
    /// assert_eq!(private_jar.get("name").unwrap().value(), "value");
    /// ```
    pub fn get(&self, name: &str) -> Option<Cookie<'static>> {
        if let Some(cookie_ref) = self.parent.get(name) {
            let mut cookie = cookie_ref.clone();
            if cookie.value().len() <= BASE64_NONCE_LEN {
                return None;
            }

            if let Ok(value) = self.unseal(cookie.value()) {
                cookie.set_value(value);
                return Some(cookie);
            }
        }

        None
    }

    /// Adds `cookie` to the parent jar. The cookie's value is encrypted with
    /// authenticated encryption assuring confidentiality, integrity, and
    /// authenticity.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::{CookieJar, Cookie, Private};
    ///
    /// # let key: Vec<_> = (0..32).collect();
    /// let mut jar = CookieJar::new();
    /// jar.private(&key).add(Cookie::new("name", "value"));
    ///
    /// assert_ne!(jar.get("name").unwrap().value(), "value");
    /// assert_eq!(jar.private(&key).get("name").unwrap().value(), "value");
    /// ```
    pub fn add(&mut self, mut cookie: Cookie<'static>) {
        // Generate the nonce.
        let mut nonce = [0; NONCE_LEN];
        SystemRandom::new().fill(&mut nonce).expect("couldn't randomly fill nonce");

        // Create the `SealingKey` structure.
        let key = SealingKey::new(ALGO, self.key).expect("sealing key creation");

        // Setup the input and output for the sealing operation.
        let overhead = ALGO.max_overhead_len();
        let mut in_out = {
            let cookie_val = cookie.value().as_bytes();
            let mut in_out = vec![0; cookie_val.len() + overhead];
            in_out[..cookie_val.len()].copy_from_slice(cookie_val);
            in_out
        };

        // Perform the actual operation and get the output.
        let out_len = seal_in_place(&key, &nonce, &mut in_out, overhead, &[])
            .expect("sealing failed!");
        let sealed_output = &in_out[..out_len];
        let encrypted_value = sealed_output.to_base64(STANDARD);

        // Build the final cookie value, combining output and nonce.
        let mut new_value = nonce.to_base64(STANDARD);
        new_value.push_str(&encrypted_value);
        cookie.set_value(new_value);

        // Add the sealed cookie to the parent.
        self.parent.add(cookie);
    }

    /// Removes `cookie` from the parent jar.
    ///
    /// For correct removal, the passed in `cookie` must contain the same `path`
    /// and `domain` as the cookie that was initially set.
    ///
    /// See [CookieJar::remove](struct.CookieJar.html#method.remove) for more
    /// details.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::{CookieJar, Cookie, Private};
    ///
    /// # let key: Vec<_> = (0..32).collect();
    /// let mut jar = CookieJar::new();
    /// let mut private_jar = jar.private(&key);
    ///
    /// private_jar.add(Cookie::new("name", "value"));
    /// assert!(private_jar.get("name").is_some());
    ///
    /// private_jar.remove(Cookie::named("name"));
    /// assert!(private_jar.get("name").is_none());
    /// ```
    pub fn remove(&mut self, cookie: Cookie<'static>) {
        self.parent.remove(cookie);
    }
}

#[cfg(test)]
mod test {
    use super::Private;
    use {CookieJar, Cookie};

    #[test]
    fn simple() {
        let key: Vec<u8> = (0..super::KEY_LEN as u8).collect();
        let mut jar = CookieJar::new();
        assert_simple_behaviour!(jar, jar.private(&key));
    }

    #[test]
    fn private() {
        let key: Vec<u8> = (0..super::KEY_LEN as u8).collect();
        let mut jar = CookieJar::new();
        assert_secure_behaviour!(jar, jar.private(&key));
    }
}
