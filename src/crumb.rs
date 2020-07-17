use crate::{Cookie, delta::DeltaCookie};

/// _Almost_ a cookie: a shared reference to a [`Cookie`] in a
/// [`CookieJar`](crate::CookieJar).
///
/// A `CookieCrumb` is a reference-counted pointer to a [`Cookie`], allowing for
/// shared, read-only access to the cookie's contents via its `Deref`
/// implementation. In other words, a [`CookieCrumb`] behaves _exactly_ like an
/// `&Cookie` when dereferenced:
///
/// ```rust
/// use cookie::{CookieJar, CookieCrumb, Cookie};
///
/// let jar = CookieJar::new();
/// jar.add(Cookie::new("name", "value"));
///
/// // Because of it's `Deref` `impl`, a `CookieCrumb` derefs to an `&Cookie`.
/// let crumb = jar.get("name").unwrap();
/// assert_eq!(crumb.name(), "name");
/// assert_eq!(crumb.value(), "value");
/// ```
///
/// The `CookieCrumb`'s `Clone` implementation increases the crumb's
/// reference-count by `1`, returning a new reference-counted pointer to the same
/// [`Cookie`]. To get an owned `Cookie` from a `CookieCrumb`, call
/// [`CookieCrumb::into_cookie()`].
///
/// ## `PartialEq`, `Eq`, and `Hash`
///
/// `CookieCrumb` implements [`PartialEq`] and [`Eq`] by deferring to the
/// implementations on `Cookie`. Additionally, `CookieCrumb` implements [`Hash`]
/// by hashing the cookie's [`name`](Cookie::name()). This means that that the
/// following property is satisfied, but the converse is not:
///
/// ```text
/// self == other => hash(self) == hash(other)
/// ```
#[derive(Clone)]
pub struct CookieCrumb(pub(crate) dashmap::ElementGuard<DeltaCookie, ()>);

impl CookieCrumb {
    /// Returns the entire `Cookie` referenced by this crumb.
    ///
    /// ```rust
    /// use cookie::{CookieJar, CookieCrumb, Cookie};
    ///
    /// let jar = CookieJar::new();
    /// jar.add(Cookie::new("name", "value"));
    ///
    /// let crumb: CookieCrumb = jar.get("name").unwrap();
    /// let cookie: Cookie = crumb.into_cookie();
    /// ```
    #[inline]
    pub fn into_cookie(self) -> Cookie<'static> {
        self.0.key().cookie.clone()
    }
}

impl std::ops::Deref for CookieCrumb {
    type Target = Cookie<'static>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0.key().cookie
    }
}

use std::hash::{Hash, Hasher};
use std::borrow::Borrow;

impl std::fmt::Debug for CookieCrumb {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        (self as &Cookie).fmt(f)
    }
}

impl PartialEq for CookieCrumb {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        (self as &Cookie) == (other as &Cookie)
    }
}

impl Eq for CookieCrumb {  }

impl Hash for CookieCrumb {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name().hash(state);
    }
}

impl Borrow<str> for CookieCrumb {
    #[inline]
    fn borrow(&self) -> &str {
        self.name()
    }
}

impl From<CookieCrumb> for Cookie<'static> {
    #[inline]
    fn from(crumb: CookieCrumb) -> Self {
        crumb.into_cookie()
    }
}
