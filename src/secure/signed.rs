use secure::ring::digest::{SHA256, Algorithm};
use secure::ring::hmac::{SigningKey, sign, verify_with_own_key as verify};

use secure::rustc_serialize::base64::{ToBase64, FromBase64, STANDARD};

use {Cookie, CookieJar};

// Keep these three in sync, and keep the key len synced with the `signed` docs.
static HMAC_DIGEST: &'static Algorithm = &SHA256;
const BASE64_DIGEST_LEN: usize = 44;
const KEY_LEN: usize = 32;

/// A child cookie jar that authenticates its cookies.
///
/// A _signed_ child jar signs all the cookies added to it and verifies cookies
/// retrieved from it. Any cookies stored in a `SignedJar` are assured integrity
/// and authenticity. In other words, clients cannot tamper with the contents of
/// a cookie nor can they fabricate cookie values, but the data is visible in
/// plaintext.
///
/// This type is only available when the `secure` feature is enabled.
pub struct SignedJar<'a> {
    parent: &'a mut CookieJar,
    key: SigningKey
}

impl<'a> SignedJar<'a> {
    /// Creates a new child `SignedJar` with parent `parent` and key `key`. This
    /// method is typically called indirectly via the `signed` method of
    /// `CookieJar`.
    ///
    /// # Panics
    ///
    /// Panics if `key` is not exactly 32 bytes long.
    #[doc(hidden)]
    pub fn new(parent: &'a mut CookieJar, key: &[u8]) -> SignedJar<'a> {
        if key.len() != KEY_LEN {
            panic!("bad key length: expected {} bytes, found {}", KEY_LEN, key.len());
        }

        SignedJar { parent: parent, key: SigningKey::new(HMAC_DIGEST, key) }
    }

    /// Given a signed value `str` where the signature is prepended to `value`,
    /// verifies the signed value and returns it. If there's a problem, returns
    /// an `Err` with a string describing the issue.
    fn verify(&self, cookie_value: &str) -> Result<String, &'static str> {
        if cookie_value.len() < BASE64_DIGEST_LEN {
            return Err("length of value is <= BASE64_DIGEST_LEN");
        }

        let (digest_str, value) = cookie_value.split_at(BASE64_DIGEST_LEN);
        let sig = digest_str.from_base64().map_err(|_| "bad base64 digest")?;

        verify(&self.key, value.as_bytes(), &sig)
            .map(|_| value.to_string())
            .map_err(|_| "value did not verify")
    }

    /// Returns a reference to the `Cookie` inside this jar with the name `name`
    /// and verifies the authenticity and integrity of the cookie's value,
    /// returning a `Cookie` with the authenticated value. If the cookie cannot
    /// be found, or the cookie fails to verify, `None` is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::{CookieJar, Cookie};
    ///
    /// # let key: Vec<_> = (0..32).collect();
    /// let mut jar = CookieJar::new();
    /// let mut signed_jar = jar.signed(&key);
    /// assert!(signed_jar.get("name").is_none());
    ///
    /// signed_jar.add(Cookie::new("name", "value"));
    /// assert_eq!(signed_jar.get("name").unwrap().value(), "value");
    /// ```
    pub fn get(&self, name: &str) -> Option<Cookie<'static>> {
        if let Some(cookie_ref) = self.parent.get(name) {
            let mut cookie = cookie_ref.clone();
            if let Ok(value) = self.verify(cookie.value()) {
                cookie.set_value(value);
                return Some(cookie);
            }
        }

        None
    }

    /// Adds `cookie` to the parent jar. The cookie's value is signed assuring
    /// integrity and authenticity.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::{CookieJar, Cookie};
    ///
    /// # let key: Vec<_> = (0..32).collect();
    /// let mut jar = CookieJar::new();
    /// jar.signed(&key).add(Cookie::new("name", "value"));
    ///
    /// assert_ne!(jar.get("name").unwrap().value(), "value");
    /// assert!(jar.get("name").unwrap().value().contains("value"));
    /// assert_eq!(jar.signed(&key).get("name").unwrap().value(), "value");
    /// ```
    pub fn add(&mut self, mut cookie: Cookie<'static>) {
        let digest = sign(&self.key, cookie.value().as_bytes());
        let mut new_value = digest.as_ref().to_base64(STANDARD);
        new_value.push_str(cookie.value());
        cookie.set_value(new_value);

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
    /// use cookie::{CookieJar, Cookie};
    ///
    /// # let key: Vec<_> = (0..32).collect();
    /// let mut jar = CookieJar::new();
    /// let mut signed_jar = jar.signed(&key);
    ///
    /// signed_jar.add(Cookie::new("name", "value"));
    /// assert!(signed_jar.get("name").is_some());
    ///
    /// signed_jar.remove(Cookie::named("name"));
    /// assert!(signed_jar.get("name").is_none());
    /// ```
    pub fn remove(&mut self, cookie: Cookie<'static>) {
        self.parent.remove(cookie);
    }
}

#[cfg(test)]
mod test {
    use {CookieJar, Cookie};

    #[test]
    fn simple() {
        let key: Vec<u8> = (0..super::KEY_LEN as u8).collect();
        let mut jar = CookieJar::new();
        assert_simple_behaviour!(jar, jar.signed(&key));
    }

    #[test]
    fn private() {
        let key: Vec<u8> = (0..super::KEY_LEN as u8).collect();
        let mut jar = CookieJar::new();
        assert_secure_behaviour!(jar, jar.signed(&key));
    }
}