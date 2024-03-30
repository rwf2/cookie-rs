use std::collections::HashSet;

#[cfg(feature = "signed")] use crate::secure::SignedJar;
#[cfg(feature = "private")] use crate::secure::PrivateJar;
#[cfg(any(feature = "signed", feature = "private"))] use crate::secure::Key;

use crate::delta::DeltaCookie;
use crate::prefix::{Prefix, PrefixedJar};
use crate::Cookie;

/// A collection of cookies that tracks its modifications.
///
/// A `CookieJar` provides storage for any number of cookies. Any changes made
/// to the jar are tracked; the changes can be retrieved via the
/// [`delta`](#method.delta) method which returns an iterator over the changes.
///
/// # Usage
///
/// A jar's life begins via [`CookieJar::new()`] and calls to
/// [`add_original()`](#method.add_original):
///
/// ```rust
/// use cookie::{Cookie, CookieJar};
///
/// let mut jar = CookieJar::new();
/// jar.add_original(("name", "value"));
/// jar.add_original(("second", "another"));
/// jar.add_original(Cookie::build(("third", "again")).path("/"));
/// ```
///
/// Cookies can be added via [`CookieJar::add()`] and removed via
/// [`CookieJar::remove()`]. Note that any `T: Into<Cookie>` can be passed into
/// these methods; see [`Cookie::build()`] for a table of implementing types.
///
/// Finally, cookies can be retrieved with [`CookieJar::get()`].
///
/// ```rust
/// # use cookie::{Cookie, CookieJar};
/// let mut jar = CookieJar::new();
/// jar.add(("a", "one"));
/// jar.add(("b", "two"));
///
/// assert_eq!(jar.get("a").map(|c| c.value()), Some("one"));
/// assert_eq!(jar.get("b").map(|c| c.value()), Some("two"));
///
/// jar.remove("b");
/// assert!(jar.get("b").is_none());
/// ```
///
/// # Deltas
///
/// A jar keeps track of any modifications made to it over time. The
/// modifications are recorded as cookies. The modifications can be retrieved
/// via [delta](#method.delta). Any new `Cookie` added to a jar via `add`
/// results in the same `Cookie` appearing in the `delta`; cookies added via
/// `add_original` do not count towards the delta. Any _original_ cookie that is
/// removed from a jar results in a "removal" cookie appearing in the delta. A
/// "removal" cookie is a cookie that a server sends so that the cookie is
/// removed from the client's machine.
///
/// Deltas are typically used to create `Set-Cookie` headers corresponding to
/// the changes made to a cookie jar over a period of time.
///
/// ```rust
/// # use cookie::{Cookie, CookieJar};
/// let mut jar = CookieJar::new();
///
/// // original cookies don't affect the delta
/// jar.add_original(("original", "value"));
/// assert_eq!(jar.delta().count(), 0);
///
/// // new cookies result in an equivalent `Cookie` in the delta
/// jar.add(("a", "one"));
/// jar.add(("b", "two"));
/// assert_eq!(jar.delta().count(), 2);
///
/// // removing an original cookie adds a "removal" cookie to the delta
/// jar.remove("original");
/// assert_eq!(jar.delta().count(), 3);
///
/// // removing a new cookie that was added removes that `Cookie` from the delta
/// jar.remove("a");
/// assert_eq!(jar.delta().count(), 2);
/// ```
#[derive(Default, Debug, Clone)]
pub struct CookieJar {
    original_cookies: HashSet<DeltaCookie>,
    delta_cookies: HashSet<DeltaCookie>,
}

impl CookieJar {
    /// Creates an empty cookie jar.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::CookieJar;
    ///
    /// let jar = CookieJar::new();
    /// assert_eq!(jar.iter().count(), 0);
    /// ```
    pub fn new() -> CookieJar {
        CookieJar::default()
    }

    /// Returns a reference to the `Cookie` inside this jar with the name
    /// `name`. If no such cookie exists, returns `None`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::{CookieJar, Cookie};
    ///
    /// let mut jar = CookieJar::new();
    /// assert!(jar.get("name").is_none());
    ///
    /// jar.add(("name", "value"));
    /// assert_eq!(jar.get("name").map(|c| c.value()), Some("value"));
    /// ```
    pub fn get(&self, name: &str) -> Option<&Cookie<'static>> {
        self.delta_cookies
            .get(name)
            .or_else(|| self.original_cookies.get(name))
            .and_then(|c| if c.removed { None } else { Some(&c.cookie) })
    }

    /// Adds an "original" `cookie` to this jar. If an original cookie with the
    /// same name already exists, it is replaced with `cookie`. Cookies added
    /// with `add` take precedence and are not replaced by this method.
    ///
    /// Adding an original cookie does not affect the [delta](#method.delta)
    /// computation. This method is intended to be used to seed the cookie jar
    /// with cookies received from a client's HTTP message.
    ///
    /// For accurate `delta` computations, this method should not be called
    /// after calling `remove`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::{CookieJar, Cookie};
    ///
    /// let mut jar = CookieJar::new();
    /// jar.add_original(("name", "value"));
    /// jar.add_original(("second", "two"));
    ///
    /// assert_eq!(jar.get("name").map(|c| c.value()), Some("value"));
    /// assert_eq!(jar.get("second").map(|c| c.value()), Some("two"));
    /// assert_eq!(jar.iter().count(), 2);
    /// assert_eq!(jar.delta().count(), 0);
    /// ```
    pub fn add_original<C: Into<Cookie<'static>>>(&mut self, cookie: C) {
        self.original_cookies.replace(DeltaCookie::added(cookie.into()));
    }

    /// Adds `cookie` to this jar. If a cookie with the same name already
    /// exists, it is replaced with `cookie`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::{CookieJar, Cookie};
    ///
    /// let mut jar = CookieJar::new();
    /// jar.add(("name", "value"));
    /// jar.add(("second", "two"));
    ///
    /// assert_eq!(jar.get("name").map(|c| c.value()), Some("value"));
    /// assert_eq!(jar.get("second").map(|c| c.value()), Some("two"));
    /// assert_eq!(jar.iter().count(), 2);
    /// assert_eq!(jar.delta().count(), 2);
    /// ```
    pub fn add<C: Into<Cookie<'static>>>(&mut self, cookie: C) {
        self.delta_cookies.replace(DeltaCookie::added(cookie.into()));
    }

    /// Removes `cookie` from this jar. If an _original_ cookie with the same
    /// name as `cookie` is present in the jar, a _removal_ cookie will be
    /// present in the `delta` computation. **To properly generate the removal
    /// cookie, `cookie` must contain the same `path` and `domain` as the cookie
    /// that was initially set.**
    ///
    /// A "removal" cookie is a cookie that has the same name as the original
    /// cookie but has an empty value, a max-age of 0, and an expiration date
    /// far in the past. See also [`Cookie::make_removal()`].
    ///
    /// # Example
    ///
    /// Removing an _original_ cookie results in a _removal_ cookie:
    ///
    /// ```rust
    /// use cookie::{CookieJar, Cookie};
    /// use cookie::time::Duration;
    ///
    /// let mut jar = CookieJar::new();
    ///
    /// // Assume this cookie originally had a path of "/" and domain of "a.b".
    /// jar.add_original(("name", "value"));
    ///
    /// // If the path and domain were set, they must be provided to `remove`.
    /// jar.remove(Cookie::build("name").path("/").domain("a.b"));
    ///
    /// // The delta will contain the removal cookie.
    /// let delta: Vec<_> = jar.delta().collect();
    /// assert_eq!(delta.len(), 1);
    /// assert_eq!(delta[0].name(), "name");
    /// assert_eq!(delta[0].max_age(), Some(Duration::seconds(0)));
    /// ```
    ///
    /// Removing a new cookie does not result in a _removal_ cookie unless
    /// there's an original cookie with the same name:
    ///
    /// ```rust
    /// use cookie::{CookieJar, Cookie};
    ///
    /// let mut jar = CookieJar::new();
    /// jar.add(("name", "value"));
    /// assert_eq!(jar.delta().count(), 1);
    ///
    /// jar.remove("name");
    /// assert_eq!(jar.delta().count(), 0);
    ///
    /// jar.add_original(("name", "value"));
    /// jar.add(("name", "value"));
    /// assert_eq!(jar.delta().count(), 1);
    ///
    /// jar.remove("name");
    /// assert_eq!(jar.delta().count(), 1);
    /// ```
    pub fn remove<C: Into<Cookie<'static>>>(&mut self, cookie: C) {
        let mut cookie = cookie.into();
        if self.original_cookies.contains(cookie.name()) {
            cookie.make_removal();
            self.delta_cookies.replace(DeltaCookie::removed(cookie));
        } else {
            self.delta_cookies.remove(cookie.name());
        }
    }

    /// Removes `cookie` from this jar completely.
    ///
    /// This method differs from `remove` in that no delta cookie is created
    /// under any condition. Thus, no path or domain are needed: only the
    /// cookie's name. Neither the `delta` nor `iter` methods will return a
    /// cookie that is removed using this method.
    ///
    /// # Example
    ///
    /// Removing an _original_ cookie; no _removal_ cookie is generated:
    ///
    /// ```rust
    /// # extern crate cookie;
    /// use cookie::{CookieJar, Cookie};
    /// use cookie::time::Duration;
    ///
    /// # fn main() {
    /// let mut jar = CookieJar::new();
    ///
    /// // Add an original cookie and a new cookie.
    /// jar.add_original(("name", "value"));
    /// jar.add(("key", "value"));
    /// assert_eq!(jar.delta().count(), 1);
    /// assert_eq!(jar.iter().count(), 2);
    ///
    /// // Now force remove the original cookie.
    /// jar.force_remove("name");
    /// assert_eq!(jar.delta().count(), 1);
    /// assert_eq!(jar.iter().count(), 1);
    ///
    /// // Now force remove the new cookie. `to_string()` for illustration only.
    /// jar.force_remove("key".to_string());
    /// assert_eq!(jar.delta().count(), 0);
    /// assert_eq!(jar.iter().count(), 0);
    /// # }
    /// ```
    pub fn force_remove<N: AsRef<str>>(&mut self, name: N) {
        self.original_cookies.remove(name.as_ref());
        self.delta_cookies.remove(name.as_ref());
    }

    /// Removes all delta cookies, i.e. all cookies not added via
    /// [`CookieJar::add_original()`], from this `CookieJar`. This undoes any
    /// changes from [`CookieJar::add()`] and [`CookieJar::remove()`]
    /// operations.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::{CookieJar, Cookie};
    ///
    /// let mut jar = CookieJar::new();
    ///
    /// // Only original cookies will remain after calling `reset_delta`.
    /// jar.add_original(("name", "value"));
    /// jar.add_original(("language", "Rust"));
    ///
    /// // These operations, represented by delta cookies, will be reset.
    /// jar.add(("language", "C++"));
    /// jar.remove("name");
    ///
    /// // All is normal.
    /// assert_eq!(jar.get("name"), None);
    /// assert_eq!(jar.get("language").map(Cookie::value), Some("C++"));
    /// assert_eq!(jar.iter().count(), 1);
    /// assert_eq!(jar.delta().count(), 2);
    ///
    /// // Resetting undoes delta operations.
    /// jar.reset_delta();
    /// assert_eq!(jar.get("name").map(Cookie::value), Some("value"));
    /// assert_eq!(jar.get("language").map(Cookie::value), Some("Rust"));
    /// assert_eq!(jar.iter().count(), 2);
    /// assert_eq!(jar.delta().count(), 0);
    /// ```
    pub fn reset_delta(&mut self) {
        self.delta_cookies = HashSet::new();
    }

    /// Returns an iterator over cookies that represent the changes to this jar
    /// over time. These cookies can be rendered directly as `Set-Cookie` header
    /// values to affect the changes made to this jar on the client.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::{CookieJar, Cookie};
    ///
    /// let mut jar = CookieJar::new();
    /// jar.add_original(("name", "value"));
    /// jar.add_original(("second", "two"));
    ///
    /// // Add new cookies.
    /// jar.add(("new", "third"));
    /// jar.add(("another", "fourth"));
    /// jar.add(("yac", "fifth"));
    ///
    /// // Remove some cookies.
    /// jar.remove(("name"));
    /// jar.remove(("another"));
    ///
    /// // Delta contains two new cookies ("new", "yac") and a removal ("name").
    /// assert_eq!(jar.delta().count(), 3);
    /// ```
    pub fn delta(&self) -> Delta {
        Delta { iter: self.delta_cookies.iter() }
    }

    /// Returns an iterator over all of the cookies present in this jar.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::{CookieJar, Cookie};
    ///
    /// let mut jar = CookieJar::new();
    ///
    /// jar.add_original(("name", "value"));
    /// jar.add_original(("second", "two"));
    ///
    /// jar.add(("new", "third"));
    /// jar.add(("another", "fourth"));
    /// jar.add(("yac", "fifth"));
    ///
    /// jar.remove("name");
    /// jar.remove("another");
    ///
    /// // There are three cookies in the jar: "second", "new", and "yac".
    /// # assert_eq!(jar.iter().count(), 3);
    /// for cookie in jar.iter() {
    ///     match cookie.name() {
    ///         "second" => assert_eq!(cookie.value(), "two"),
    ///         "new" => assert_eq!(cookie.value(), "third"),
    ///         "yac" => assert_eq!(cookie.value(), "fifth"),
    ///         _ => unreachable!("there are only three cookies in the jar")
    ///     }
    /// }
    /// ```
    pub fn iter(&self) -> Iter {
        Iter {
            delta_cookies: self.delta_cookies.iter()
                .chain(self.original_cookies.difference(&self.delta_cookies)),
        }
    }

    /// Returns a read-only `PrivateJar` with `self` as its parent jar using the
    /// key `key` to verify/decrypt cookies retrieved from the child jar. Any
    /// retrievals from the child jar will be made from the parent jar.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::{Cookie, CookieJar, Key};
    ///
    /// // Generate a secure key.
    /// let key = Key::generate();
    ///
    /// // Add a private (signed + encrypted) cookie.
    /// let mut jar = CookieJar::new();
    /// jar.private_mut(&key).add(("private", "text"));
    ///
    /// // The cookie's contents are encrypted.
    /// assert_ne!(jar.get("private").unwrap().value(), "text");
    ///
    /// // They can be decrypted and verified through the child jar.
    /// assert_eq!(jar.private(&key).get("private").unwrap().value(), "text");
    ///
    /// // A tampered with cookie does not validate but still exists.
    /// let mut cookie = jar.get("private").unwrap().clone();
    /// jar.add(("private", cookie.value().to_string() + "!"));
    /// assert!(jar.private(&key).get("private").is_none());
    /// assert!(jar.get("private").is_some());
    /// ```
    #[cfg(feature = "private")]
    #[cfg_attr(all(nightly, doc), doc(cfg(feature = "private")))]
    pub fn private<'a>(&'a self, key: &Key) -> PrivateJar<&'a Self> {
        PrivateJar::new(self, key)
    }

    /// Returns a read/write `PrivateJar` with `self` as its parent jar using
    /// the key `key` to sign/encrypt and verify/decrypt cookies added/retrieved
    /// from the child jar.
    ///
    /// Any modifications to the child jar will be reflected on the parent jar,
    /// and any retrievals from the child jar will be made from the parent jar.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::{Cookie, CookieJar, Key};
    ///
    /// // Generate a secure key.
    /// let key = Key::generate();
    ///
    /// // Add a private (signed + encrypted) cookie.
    /// let mut jar = CookieJar::new();
    /// jar.private_mut(&key).add(("private", "text"));
    ///
    /// // Remove a cookie using the child jar.
    /// jar.private_mut(&key).remove("private");
    /// ```
    #[cfg(feature = "private")]
    #[cfg_attr(all(nightly, doc), doc(cfg(feature = "private")))]
    pub fn private_mut<'a>(&'a mut self, key: &Key) -> PrivateJar<&'a mut Self> {
        PrivateJar::new(self, key)
    }

    /// Returns a read-only `SignedJar` with `self` as its parent jar using the
    /// key `key` to verify cookies retrieved from the child jar. Any retrievals
    /// from the child jar will be made from the parent jar.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::{Cookie, CookieJar, Key};
    ///
    /// // Generate a secure key.
    /// let key = Key::generate();
    ///
    /// // Add a signed cookie.
    /// let mut jar = CookieJar::new();
    /// jar.signed_mut(&key).add(("signed", "text"));
    ///
    /// // The cookie's contents are signed but still in plaintext.
    /// assert_ne!(jar.get("signed").unwrap().value(), "text");
    /// assert!(jar.get("signed").unwrap().value().contains("text"));
    ///
    /// // They can be verified through the child jar.
    /// assert_eq!(jar.signed(&key).get("signed").unwrap().value(), "text");
    ///
    /// // A tampered with cookie does not validate but still exists.
    /// let mut cookie = jar.get("signed").unwrap().clone();
    /// jar.add(("signed", cookie.value().to_string() + "!"));
    /// assert!(jar.signed(&key).get("signed").is_none());
    /// assert!(jar.get("signed").is_some());
    /// ```
    #[cfg(feature = "signed")]
    #[cfg_attr(all(nightly, doc), doc(cfg(feature = "signed")))]
    pub fn signed<'a>(&'a self, key: &Key) -> SignedJar<&'a Self> {
        SignedJar::new(self, key)
    }

    /// Returns a read/write `SignedJar` with `self` as its parent jar using the
    /// key `key` to sign/verify cookies added/retrieved from the child jar.
    ///
    /// Any modifications to the child jar will be reflected on the parent jar,
    /// and any retrievals from the child jar will be made from the parent jar.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::{CookieJar, Key};
    ///
    /// // Generate a secure key.
    /// let key = Key::generate();
    ///
    /// // Add a signed cookie.
    /// let mut jar = CookieJar::new();
    /// jar.signed_mut(&key).add(("signed", "text"));
    ///
    /// // Remove a cookie.
    /// jar.signed_mut(&key).remove("signed");
    /// ```
    #[cfg(feature = "signed")]
    #[cfg_attr(all(nightly, doc), doc(cfg(feature = "signed")))]
    pub fn signed_mut<'a>(&'a mut self, key: &Key) -> SignedJar<&'a mut Self> {
        SignedJar::new(self, key)
    }

    /// Returns a read-only `PrefixedJar` with `self` as its parent jar that
    /// prefixes the name of cookies with `prefix`. Any retrievals from the
    /// child jar will be made from the parent jar.
    ///
    /// **Note:** Cookie prefixes are specified in an HTTP draft! Their meaning
    /// and definition are subject to change.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::CookieJar;
    /// use cookie::prefix::{Host, Secure};
    ///
    /// // Add a `Host` prefixed cookie.
    /// let mut jar = CookieJar::new();
    /// jar.prefixed_mut(Host).add(("h0st", "value"));
    /// jar.prefixed_mut(Secure).add(("secur3", "value"));
    ///
    /// // The cookie's name is prefixed in the parent jar.
    /// assert!(matches!(jar.get("h0st"), None));
    /// assert!(matches!(jar.get("__Host-h0st"), Some(_)));
    /// assert!(matches!(jar.get("secur3"), None));
    /// assert!(matches!(jar.get("__Secure-secur3"), Some(_)));
    ///
    /// // The prefixed jar automatically removes the prefix.
    /// assert_eq!(jar.prefixed(Host).get("h0st").unwrap().name(), "h0st");
    /// assert_eq!(jar.prefixed(Host).get("h0st").unwrap().value(), "value");
    /// assert_eq!(jar.prefixed(Secure).get("secur3").unwrap().name(), "secur3");
    /// assert_eq!(jar.prefixed(Secure).get("secur3").unwrap().value(), "value");
    ///
    /// // Only the correct prefixed jar retrieves the cookie.
    /// assert!(matches!(jar.prefixed(Host).get("secur3"), None));
    /// assert!(matches!(jar.prefixed(Secure).get("h0st"), None));
    /// ```
    #[inline(always)]
    pub fn prefixed<'a, P: Prefix>(&'a self, prefix: P) -> PrefixedJar<P, &'a Self> {
        let _ = prefix;
        PrefixedJar::new(self)
    }

    /// Returns a read/write `PrefixedJar` with `self` as its parent jar that
    /// prefixes the name of cookies with `prefix` and makes the cookie conform
    /// to the prefix's requirements. This means that added cookies:
    ///
    ///   1. Have the [`Prefix::PREFIX`] prepended to their name.
    ///   2. Modify the cookie via [`Prefix::conform()`] so that it conforms to
    ///      the prefix's requirements.
    ///
    /// Any modifications to the child jar will be reflected on the parent jar,
    /// and any retrievals from the child jar will be made from the parent jar.
    ///
    /// **Note:** Cookie prefixes are specified in an HTTP draft! Their meaning
    /// and definition are subject to change.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::CookieJar;
    /// use cookie::prefix::{Host, Secure};
    ///
    /// // Add some prefixed cookies.
    /// let mut jar = CookieJar::new();
    /// jar.prefixed_mut(Host).add(("one", "1"));
    /// jar.prefixed_mut(Secure).add((2.to_string(), "2"));
    /// jar.prefixed_mut(Host).add((format!("{:0b}", 3), "0b11"));
    ///
    /// // Fetch cookies with either `prefixed()` or `prefixed_mut()`.
    /// assert_eq!(jar.prefixed(Host).get("one").unwrap().value(), "1");
    /// assert_eq!(jar.prefixed(Secure).get("2").unwrap().value(), "2");
    /// assert_eq!(jar.prefixed_mut(Host).get("11").unwrap().value(), "0b11");
    ///
    /// // Remove cookies.
    /// jar.prefixed_mut(Host).remove("one");
    /// assert!(jar.prefixed(Host).get("one").is_none());
    /// ```
    pub fn prefixed_mut<'a, P: Prefix>(&'a mut self, prefix: P) -> PrefixedJar<P, &'a mut Self> {
        let _ = prefix;
        PrefixedJar::new(self)
    }
}

use std::iter::FromIterator;

impl FromIterator<Cookie<'static>> for CookieJar {
    fn from_iter<T: IntoIterator<Item = Cookie<'static>>>(iter: T) -> Self {
        let mut jar = Self::new();
        for cookie in iter.into_iter() {
            jar.add_original(cookie);
        }
        jar
    }
}

use std::collections::hash_set::Iter as HashSetIter;

/// Iterator over the changes to a cookie jar.
pub struct Delta<'a> {
    iter: HashSetIter<'a, DeltaCookie>,
}

impl<'a> Iterator for Delta<'a> {
    type Item = &'a Cookie<'static>;

    fn next(&mut self) -> Option<&'a Cookie<'static>> {
        self.iter.next().map(|c| &c.cookie)
    }
}

use std::collections::hash_set::Difference;
use std::collections::hash_map::RandomState;
use std::iter::Chain;

/// Iterator over all of the cookies in a jar.
pub struct Iter<'a> {
    delta_cookies: Chain<HashSetIter<'a, DeltaCookie>, Difference<'a, DeltaCookie, RandomState>>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a Cookie<'static>;

    fn next(&mut self) -> Option<&'a Cookie<'static>> {
        for cookie in self.delta_cookies.by_ref() {
            if !cookie.removed {
                return Some(&*cookie);
            }
        }

        None
    }
}

#[cfg(test)]
mod test {
    use super::CookieJar;
    use crate::Cookie;

    #[test]
    #[allow(deprecated)]
    fn simple() {
        let mut c = CookieJar::new();

        c.add(("test", ""));
        c.add(("test2", ""));
        c.remove("test");

        assert!(c.get("test").is_none());
        assert!(c.get("test2").is_some());

        c.add(("test3", ""));
        c.remove("test2");
        c.remove("test3");

        assert!(c.get("test").is_none());
        assert!(c.get("test2").is_none());
        assert!(c.get("test3").is_none());
    }

    #[test]
    fn jar_is_send() {
        fn is_send<T: Send>(_: T) -> bool {
            true
        }

        assert!(is_send(CookieJar::new()))
    }

    #[test]
    #[cfg(all(feature = "signed", feature = "private"))]
    fn iter() {
        let key = crate::Key::generate();
        let mut c = CookieJar::new();

        c.add_original(Cookie::new("original", "original"));

        c.add(Cookie::new("test", "test"));
        c.add(Cookie::new("test2", "test2"));
        c.add(Cookie::new("test3", "test3"));
        assert_eq!(c.iter().count(), 4);

        c.signed_mut(&key).add(Cookie::new("signed", "signed"));
        c.private_mut(&key).add(Cookie::new("encrypted", "encrypted"));
        assert_eq!(c.iter().count(), 6);

        c.remove("test");
        assert_eq!(c.iter().count(), 5);

        c.remove("signed");
        c.remove("test2");
        assert_eq!(c.iter().count(), 3);

        c.add(("test2", "test2"));
        assert_eq!(c.iter().count(), 4);

        c.remove("test2");
        assert_eq!(c.iter().count(), 3);
    }

    #[test]
    fn delta() {
        use std::collections::HashMap;
        use time::Duration;

        let mut c = CookieJar::new();

        c.add_original(Cookie::new("original", "original"));
        c.add_original(Cookie::new("original1", "original1"));

        c.add(Cookie::new("test", "test"));
        c.add(Cookie::new("test2", "test2"));
        c.add(Cookie::new("test3", "test3"));
        c.add(Cookie::new("test4", "test4"));

        c.remove("test");
        c.remove("original");

        assert_eq!(c.delta().count(), 4);

        let names: HashMap<_, _> = c.delta()
            .map(|c| (c.name(), c.max_age()))
            .collect();

        assert!(names.get("test2").unwrap().is_none());
        assert!(names.get("test3").unwrap().is_none());
        assert!(names.get("test4").unwrap().is_none());
        assert_eq!(names.get("original").unwrap(), &Some(Duration::seconds(0)));
    }

    #[test]
    fn replace_original() {
        let mut jar = CookieJar::new();
        jar.add_original(Cookie::new("original_a", "a"));
        jar.add_original(Cookie::new("original_b", "b"));
        assert_eq!(jar.get("original_a").unwrap().value(), "a");

        jar.add(Cookie::new("original_a", "av2"));
        assert_eq!(jar.get("original_a").unwrap().value(), "av2");
    }

    #[test]
    fn empty_delta() {
        let mut jar = CookieJar::new();
        jar.add(Cookie::new("name", "val"));
        assert_eq!(jar.delta().count(), 1);

        jar.remove("name");
        assert_eq!(jar.delta().count(), 0);

        jar.add_original(Cookie::new("name", "val"));
        assert_eq!(jar.delta().count(), 0);

        jar.remove("name");
        assert_eq!(jar.delta().count(), 1);

        jar.add(Cookie::new("name", "val"));
        assert_eq!(jar.delta().count(), 1);

        jar.remove("name");
        assert_eq!(jar.delta().count(), 1);
    }

    #[test]
    fn add_remove_add() {
        let mut jar = CookieJar::new();
        jar.add_original(Cookie::new("name", "val"));
        assert_eq!(jar.delta().count(), 0);

        jar.remove("name");
        assert_eq!(jar.delta().filter(|c| c.value().is_empty()).count(), 1);
        assert_eq!(jar.delta().count(), 1);

        // The cookie's been deleted. Another original doesn't change that.
        jar.add_original(Cookie::new("name", "val"));
        assert_eq!(jar.delta().filter(|c| c.value().is_empty()).count(), 1);
        assert_eq!(jar.delta().count(), 1);

        jar.remove("name");
        assert_eq!(jar.delta().filter(|c| c.value().is_empty()).count(), 1);
        assert_eq!(jar.delta().count(), 1);

        jar.add(Cookie::new("name", "val"));
        assert_eq!(jar.delta().filter(|c| !c.value().is_empty()).count(), 1);
        assert_eq!(jar.delta().count(), 1);

        jar.remove("name");
        assert_eq!(jar.delta().filter(|c| c.value().is_empty()).count(), 1);
        assert_eq!(jar.delta().count(), 1);
    }

    #[test]
    fn replace_remove() {
        let mut jar = CookieJar::new();
        jar.add_original(Cookie::new("name", "val"));
        assert_eq!(jar.delta().count(), 0);

        jar.add(Cookie::new("name", "val"));
        assert_eq!(jar.delta().count(), 1);
        assert_eq!(jar.delta().filter(|c| !c.value().is_empty()).count(), 1);

        jar.remove("name");
        assert_eq!(jar.delta().filter(|c| c.value().is_empty()).count(), 1);
    }

    #[test]
    fn remove_with_path() {
        let mut jar = CookieJar::new();
        jar.add_original(("name", "val"));
        assert_eq!(jar.iter().count(), 1);
        assert_eq!(jar.delta().count(), 0);
        assert_eq!(jar.iter().filter(|c| c.path().is_none()).count(), 1);

        jar.remove(Cookie::build("name").path("/"));
        assert_eq!(jar.iter().count(), 0);
        assert_eq!(jar.delta().count(), 1);
        assert_eq!(jar.delta().filter(|c| c.value().is_empty()).count(), 1);
        assert_eq!(jar.delta().filter(|c| c.path() == Some("/")).count(), 1);
    }
}
