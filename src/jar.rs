use time::{Duration, OffsetDateTime};

#[cfg(feature = "signed")] use crate::secure::SignedJar;
#[cfg(feature = "private")] use crate::secure::PrivateJar;
#[cfg(any(feature = "signed", feature = "private"))] use crate::secure::Key;

use crate::{Cookie, CookieCrumb, delta::DeltaCookie};

/// A collection of cookies that tracks its modifications.
///
/// A `CookieJar` provides storage for any number of cookies. Any changes made
/// to the jar are tracked; the changes can be retrieved via the
/// [delta](#method.delta) method which returns an iterator over the changes.
///
/// A `CookieJar` is `Send`, `Sync`, and allows thread-safe mutation via shared
/// references.
///
/// # Usage
///
/// A jar's life begins via [`new()`](#method.new) and calls to
/// [`add_original()`](#method.add_original):
///
/// ```rust
/// use cookie::{Cookie, CookieJar};
///
/// let jar = CookieJar::new();
/// jar.add_original(Cookie::new("name", "value"));
/// jar.add_original(Cookie::new("second", "another"));
/// ```
///
/// Cookies can be added via [`add()`](#method.add) and removed via
/// [`remove()`](#method.remove). Finally, cookies can be looked up via
/// [`get()`](#method.get):
///
/// ```rust
/// # use cookie::{Cookie, CookieJar};
/// let jar = CookieJar::new();
/// jar.add(Cookie::new("a", "one"));
/// jar.add(Cookie::new("b", "two"));
///
/// assert_eq!(jar.get("a").unwrap().value(), "one");
/// assert_eq!(jar.get("b").unwrap().value(), "two");
///
/// jar.remove(Cookie::named("b"));
/// assert!(jar.get("b").is_none());
/// ```
///
/// # Deltas
///
/// A jar keeps track of any modifications made to it over time. Modifications
/// are recorded as cookies and  can be retrieved via
/// [`delta()`](#method.delta). Any new `Cookie` added to a jar via `add()`
/// results in the same `Cookie` appearing in the `delta`; cookies added via
/// `add_original()` do not count towards the delta. Any _original_ cookie that
/// is removed from a jar results in a "removal" cookie appearing in the delta.
/// A "removal" cookie is a cookie that a server sends so that the cookie is
/// removed from the client's machine.
///
/// Deltas are typically used to create `Set-Cookie` headers corresponding to
/// the changes made to a cookie jar over a period of time.
///
/// ```rust
/// # use cookie::{Cookie, CookieJar};
/// let jar = CookieJar::new();
///
/// // original cookies don't affect the delta
/// jar.add_original(Cookie::new("original", "value"));
/// assert_eq!(jar.delta().count(), 0);
///
/// // new cookies result in an equivalent `Cookie` in the delta
/// jar.add(Cookie::new("a", "one"));
/// jar.add(Cookie::new("b", "two"));
/// assert_eq!(jar.delta().count(), 2);
///
/// // removing an original cookie adds a "removal" cookie to the delta
/// jar.remove(Cookie::named("original"));
/// assert_eq!(jar.delta().count(), 3);
///
/// // removing a new cookie that was added removes that `Cookie` from the delta
/// jar.remove(Cookie::named("a"));
/// assert_eq!(jar.delta().count(), 2);
/// ```
#[derive(Default, Debug)]
pub struct CookieJar {
    originals: dashmap::DashMap<DeltaCookie, ()>,
    deltas: dashmap::DashMap<DeltaCookie, ()>,
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
    /// let jar = CookieJar::new();
    /// assert!(jar.get("name").is_none());
    ///
    /// jar.add(Cookie::new("name", "value"));
    /// assert_eq!(jar.get("name").unwrap().value(), "value");
    /// ```
    pub fn get(&self, name: &str) -> Option<CookieCrumb> {
        self.deltas
            .get(name)
            .or_else(|| self.originals.get(name))
            .and_then(|c| if !c.key().removed { Some(CookieCrumb(c)) } else { None })
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
    /// let jar = CookieJar::new();
    /// jar.add_original(Cookie::new("name", "value"));
    /// jar.add_original(Cookie::new("second", "two"));
    ///
    /// assert_eq!(jar.get("name").unwrap().value(), "value");
    /// assert_eq!(jar.get("second").unwrap().value(), "two");
    /// assert_eq!(jar.iter().count(), 2);
    /// assert_eq!(jar.delta().count(), 0);
    /// ```
    pub fn add_original(&self, cookie: Cookie<'static>) {
        self.originals.replace(DeltaCookie::added(cookie), ());
    }

    /// Adds `cookie` to this jar. If a cookie with the same name already
    /// exists, it is replaced with `cookie`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::{CookieJar, Cookie};
    ///
    /// let jar = CookieJar::new();
    /// jar.add(Cookie::new("name", "value"));
    /// jar.add(Cookie::new("second", "two"));
    ///
    /// assert_eq!(jar.get("name").unwrap().value(), "value");
    /// assert_eq!(jar.get("second").unwrap().value(), "two");
    /// assert_eq!(jar.iter().count(), 2);
    /// assert_eq!(jar.delta().count(), 2);
    /// ```
    pub fn add(&self, cookie: Cookie<'static>) {
        self.deltas.replace(DeltaCookie::added(cookie), ());
    }

    /// Removes `cookie` from this jar. If an _original_ cookie with the same
    /// name as `cookie` is present in the jar, a _removal_ cookie will be
    /// present in the `delta` computation. To properly generate the removal
    /// cookie, `cookie` must contain the same `path` and `domain` as the cookie
    /// that was initially set.
    ///
    /// A "removal" cookie is a cookie that has the same name as the original
    /// cookie but has an empty value, a max-age of 0, and an expiration date
    /// far in the past.
    ///
    /// # Example
    ///
    /// Removing an _original_ cookie results in a _removal_ cookie:
    ///
    /// ```rust
    /// # extern crate cookie;
    /// extern crate time;
    ///
    /// use cookie::{CookieJar, Cookie};
    /// use time::Duration;
    ///
    /// # fn main() {
    /// let jar = CookieJar::new();
    ///
    /// // Assume this cookie originally had a path of "/" and domain of "a.b".
    /// jar.add_original(Cookie::new("name", "value"));
    ///
    /// // If the path and domain were set, they must be provided to `remove`.
    /// jar.remove(Cookie::build("name", "").path("/").domain("a.b").finish());
    ///
    /// // The delta will contain the removal cookie.
    /// let delta: Vec<_> = jar.delta().collect();
    /// assert_eq!(delta.len(), 1);
    /// assert_eq!(delta[0].name(), "name");
    /// assert_eq!(delta[0].max_age(), Some(Duration::seconds(0)));
    /// # }
    /// ```
    ///
    /// Removing a new cookie does not result in a _removal_ cookie:
    ///
    /// ```rust
    /// use cookie::{CookieJar, Cookie};
    ///
    /// let jar = CookieJar::new();
    /// jar.add(Cookie::new("name", "value"));
    /// assert_eq!(jar.delta().count(), 1);
    ///
    /// jar.remove(Cookie::named("name"));
    /// assert_eq!(jar.delta().count(), 0);
    /// ```
    pub fn remove(&self, mut cookie: Cookie<'static>) {
        if self.originals.contains_key(cookie.name()) {
            cookie.set_value("");
            cookie.set_max_age(Duration::seconds(0));
            cookie.set_expires(OffsetDateTime::now_utc() - Duration::days(365));
            self.deltas.replace(DeltaCookie::removed(cookie), ());
        } else {
            self.deltas.remove(cookie.name());
        }
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
    /// let jar = CookieJar::new();
    ///
    /// // Only original cookies will remain after calling `reset_delta`.
    /// jar.add_original(Cookie::new("name", "value"));
    /// jar.add_original(Cookie::new("language", "Rust"));
    ///
    /// // These operations, represented by delta cookies, will be reset.
    /// jar.add(Cookie::new("language", "C++"));
    /// jar.remove(Cookie::named("name"));
    ///
    /// // All is normal.
    /// assert_eq!(jar.get("name"), None);
    /// assert_eq!(jar.get("language").unwrap().value(), "C++");
    /// assert_eq!(jar.iter().count(), 1);
    /// assert_eq!(jar.delta().count(), 2);
    ///
    /// // Resetting undoes delta operations.
    /// jar.reset_delta();
    /// assert_eq!(jar.get("name").unwrap().value(), "value");
    /// assert_eq!(jar.get("language").unwrap().value(), "Rust");
    /// assert_eq!(jar.iter().count(), 2);
    /// assert_eq!(jar.delta().count(), 0);
    /// ```
    pub fn reset_delta(&self) {
        self.deltas.clear();
    }

    /// Removes `cookie` from this jar completely. This method differs from
    /// `remove` in that no delta cookie is created under any condition. Neither
    /// the `delta` nor `iter` methods will return a cookie that is removed
    /// using this method.
    ///
    /// # Example
    ///
    /// Removing an _original_ cookie; no _removal_ cookie is generated:
    ///
    /// ```rust
    /// # extern crate cookie;
    /// extern crate time;
    ///
    /// use cookie::{CookieJar, Cookie};
    /// use time::Duration;
    ///
    /// # fn main() {
    /// let jar = CookieJar::new();
    ///
    /// // Add an original cookie and a new cookie.
    /// jar.add_original(Cookie::new("name", "value"));
    /// jar.add(Cookie::new("key", "value"));
    /// assert_eq!(jar.delta().count(), 1);
    /// assert_eq!(jar.iter().count(), 2);
    ///
    /// // Now force remove the original cookie.
    /// jar.force_remove(&Cookie::named("name"));
    /// assert_eq!(jar.delta().count(), 1);
    /// assert_eq!(jar.iter().count(), 1);
    ///
    /// // Now force remove the new cookie.
    /// jar.force_remove(&Cookie::named("key"));
    /// assert_eq!(jar.delta().count(), 0);
    /// assert_eq!(jar.iter().count(), 0);
    /// # }
    /// ```
    pub fn force_remove(&self, cookie: &Cookie) {
        self.originals.remove(cookie.name());
        self.deltas.remove(cookie.name());
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
    /// let jar = CookieJar::new();
    /// jar.add_original(Cookie::new("name", "value"));
    /// jar.add_original(Cookie::new("second", "two"));
    ///
    /// // Add new cookies.
    /// jar.add(Cookie::new("new", "third"));
    /// jar.add(Cookie::new("another", "fourth"));
    /// jar.add(Cookie::new("yac", "fifth"));
    ///
    /// // Remove some cookies.
    /// jar.remove(Cookie::named("name"));
    /// jar.remove(Cookie::named("another"));
    ///
    /// // Delta contains two new cookies ("new", "yac") and a removal ("name").
    /// assert_eq!(jar.delta().count(), 3);
    /// ```
    pub fn delta(&self) -> Delta {
        Delta { iter: self.deltas.iter() }
    }

    /// Returns an iterator over all of the cookies present in this jar.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::{CookieJar, Cookie};
    ///
    /// let jar = CookieJar::new();
    ///
    /// jar.add_original(Cookie::new("name", "value"));
    /// jar.add_original(Cookie::new("second", "two"));
    ///
    /// jar.add(Cookie::new("new", "third"));
    /// jar.add(Cookie::new("another", "fourth"));
    /// jar.add(Cookie::new("yac", "fifth"));
    ///
    /// jar.remove(Cookie::named("name"));
    /// jar.remove(Cookie::named("another"));
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
            delta_cookie: &self.deltas,
            delta_cookies_iter: self.deltas.iter(),
            original_cookies_iter: self.originals.iter(),
        }
    }

    /// Returns a `PrivateJar` with `self` as its parent jar using the key `key`
    /// to sign/encrypt and verify/decrypt cookies added/retrieved from the
    /// child jar.
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
    /// let jar = CookieJar::new();
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
    #[cfg(feature = "private")]
    #[cfg_attr(nightly, doc(cfg(feature = "private")))]
    pub fn private(&self, key: &Key) -> PrivateJar {
        PrivateJar::new(self, key)
    }

    /// Returns a `SignedJar` with `self` as its parent jar using the key `key`
    /// to sign/verify cookies added/retrieved from the child jar.
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
    /// // Add a signed cookie.
    /// let jar = CookieJar::new();
    /// jar.signed(&key).add(Cookie::new("signed", "text"));
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
    /// jar.add(Cookie::new("signed", cookie.value().to_string() + "!"));
    /// assert!(jar.signed(&key).get("signed").is_none());
    /// assert!(jar.get("signed").is_some());
    /// ```
    #[cfg(feature = "signed")]
    #[cfg_attr(nightly, doc(cfg(feature = "signed")))]
    pub fn signed(&self, key: &Key) -> SignedJar {
        SignedJar::new(self, key)
    }
}

impl Clone for CookieJar {
    fn clone(&self) -> Self {
        CookieJar {
            originals: self.originals.iter().map(|c| (c.key().clone(), ())).collect(),
            deltas: self.deltas.iter().map(|c| (c.key().clone(), ())).collect(),
        }
    }
}

/// Iterator over the changes to a cookie jar.
pub struct Delta {
    iter: dashmap::Iter<DeltaCookie, ()>,
}

impl Iterator for Delta {
    type Item = CookieCrumb;

    fn next(&mut self) -> Option<CookieCrumb> {
        self.iter.next().map(CookieCrumb)
    }
}

/// Iterator over all of the cookies in a jar.
pub struct Iter<'a> {
    delta_cookie: &'a dashmap::DashMap<DeltaCookie, ()>,
    delta_cookies_iter: dashmap::Iter<DeltaCookie, ()>,
    original_cookies_iter: dashmap::Iter<DeltaCookie, ()>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = CookieCrumb;

    fn next(&mut self) -> Option<CookieCrumb> {
        for cookie in self.delta_cookies_iter.by_ref() {
            if !cookie.key().removed {
                return Some(CookieCrumb(cookie));
            }
        }

        for cookie in self.original_cookies_iter.by_ref() {
            if !self.delta_cookie.contains_key(cookie.key().name()) {
                if !cookie.key().removed {
                    return Some(CookieCrumb(cookie));
                }
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
    fn cookie_jar_is_send_syncv() {
        fn is_send_sync<T: Send + Sync>() {}
        is_send_sync::<CookieJar>();
    }

    #[test]
    #[allow(deprecated)]
    fn simple() {
        let c = CookieJar::new();

        c.add(Cookie::new("test", ""));
        c.add(Cookie::new("test2", ""));
        c.remove(Cookie::named("test"));

        assert!(c.get("test").is_none());
        assert!(c.get("test2").is_some());

        c.add(Cookie::new("test3", ""));
        c.remove(Cookie::named("test2"));
        c.remove(Cookie::named("test3"));

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
        let jar = CookieJar::new();

        jar.add_original(Cookie::new("original", "original"));

        jar.add(Cookie::new("test", "test"));
        jar.add(Cookie::new("test2", "test2"));
        jar.add(Cookie::new("test3", "test3"));
        assert_eq!(jar.iter().count(), 4);

        jar.signed(&key).add(Cookie::new("signed", "signed"));
        jar.private(&key).add(Cookie::new("encrypted", "encrypted"));
        assert_eq!(jar.iter().count(), 6);

        jar.remove(Cookie::named("test"));
        assert_eq!(jar.iter().count(), 5);

        jar.remove(Cookie::named("signed"));
        jar.remove(Cookie::named("test2"));
        assert_eq!(jar.iter().count(), 3);

        jar.add(Cookie::new("test2", "test2"));
        assert_eq!(jar.iter().count(), 4);

        jar.remove(Cookie::named("test2"));
        assert_eq!(jar.iter().count(), 3);
    }

    #[test]
    fn delta() {
        use std::collections::HashMap;
        use time::Duration;

        let c = CookieJar::new();

        c.add_original(Cookie::new("original", "original"));
        c.add_original(Cookie::new("original1", "original1"));

        c.add(Cookie::new("test", "test"));
        c.add(Cookie::new("test2", "test2"));
        c.add(Cookie::new("test3", "test3"));
        c.add(Cookie::new("test4", "test4"));

        c.remove(Cookie::named("test"));
        c.remove(Cookie::named("original"));

        assert_eq!(c.delta().count(), 4);

        let names: HashMap<_, _> = c.delta()
            .map(|c| (c.clone(), c.max_age()))
            .collect();

        assert!(names.get("test2").unwrap().is_none());
        assert!(names.get("test3").unwrap().is_none());
        assert!(names.get("test4").unwrap().is_none());
        assert_eq!(names.get("original").unwrap(), &Some(Duration::seconds(0)));
    }

    #[test]
    fn replace_original() {
        let jar = CookieJar::new();
        jar.add_original(Cookie::new("original_a", "a"));
        jar.add_original(Cookie::new("original_b", "b"));
        assert_eq!(jar.get("original_a").unwrap().value(), "a");

        jar.add(Cookie::new("original_a", "av2"));
        assert_eq!(jar.get("original_a").unwrap().value(), "av2");
    }

    #[test]
    fn empty_delta() {
        let jar = CookieJar::new();
        jar.add(Cookie::new("name", "val"));
        assert_eq!(jar.delta().count(), 1);

        jar.remove(Cookie::named("name"));
        assert_eq!(jar.delta().count(), 0);

        jar.add_original(Cookie::new("name", "val"));
        assert_eq!(jar.delta().count(), 0);

        jar.remove(Cookie::named("name"));
        assert_eq!(jar.delta().count(), 1);

        jar.add(Cookie::new("name", "val"));
        assert_eq!(jar.delta().count(), 1);

        jar.remove(Cookie::named("name"));
        assert_eq!(jar.delta().count(), 1);
    }

    #[test]
    fn add_remove_add() {
        let jar = CookieJar::new();
        jar.add_original(Cookie::new("name", "val"));
        assert_eq!(jar.delta().count(), 0);

        jar.remove(Cookie::named("name"));
        assert_eq!(jar.delta().filter(|c| c.value().is_empty()).count(), 1);
        assert_eq!(jar.delta().count(), 1);

        // The cookie's been deleted. Another original doesn't change that.
        jar.add_original(Cookie::new("name", "val"));
        assert_eq!(jar.delta().filter(|c| c.value().is_empty()).count(), 1);
        assert_eq!(jar.delta().count(), 1);

        jar.remove(Cookie::named("name"));
        assert_eq!(jar.delta().filter(|c| c.value().is_empty()).count(), 1);
        assert_eq!(jar.delta().count(), 1);

        jar.add(Cookie::new("name", "val"));
        assert_eq!(jar.delta().filter(|c| !c.value().is_empty()).count(), 1);
        assert_eq!(jar.delta().count(), 1);

        jar.remove(Cookie::named("name"));
        assert_eq!(jar.delta().filter(|c| c.value().is_empty()).count(), 1);
        assert_eq!(jar.delta().count(), 1);
    }

    #[test]
    fn replace_remove() {
        let jar = CookieJar::new();
        jar.add_original(Cookie::new("name", "val"));
        assert_eq!(jar.delta().count(), 0);

        jar.add(Cookie::new("name", "val"));
        assert_eq!(jar.delta().count(), 1);
        assert_eq!(jar.delta().filter(|c| !c.value().is_empty()).count(), 1);

        jar.remove(Cookie::named("name"));
        assert_eq!(jar.delta().filter(|c| c.value().is_empty()).count(), 1);
    }

    #[test]
    fn remove_with_path() {
        let jar = CookieJar::new();
        jar.add_original(Cookie::build("name", "val").finish());
        assert_eq!(jar.iter().count(), 1);
        assert_eq!(jar.delta().count(), 0);
        assert_eq!(jar.iter().filter(|c| c.path().is_none()).count(), 1);

        jar.remove(Cookie::build("name", "").path("/").finish());
        assert_eq!(jar.iter().count(), 0);
        assert_eq!(jar.delta().count(), 1);
        assert_eq!(jar.delta().filter(|c| c.value().is_empty()).count(), 1);
        assert_eq!(jar.delta().filter(|c| c.path() == Some("/")).count(), 1);
    }
}
