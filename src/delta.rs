use std::ops::{Deref, DerefMut};
use std::hash::{Hash, Hasher};
use std::borrow::Borrow;

use Cookie;

/// A `DeltaCookie` is a helper structure used in a cookie jar. It wraps a
/// `Cookie` so that it can be hashed and compared purely by name. It further
/// records whether the wrapped cookie is a "removal" cookie, that is, a cookie
/// that when sent to the client removes the named cookie on the client's
/// machine.
#[derive(Clone, Debug)]
pub struct DeltaCookie<'c> {
    pub cookie: Cookie<'c>,
    pub removed: bool,
}

impl<'c> DeltaCookie<'c> {
    /// Create a new `DeltaCookie` that is being added to a jar.
    #[inline]
    pub fn added(cookie: Cookie<'c>) -> DeltaCookie<'c> {
        DeltaCookie {
            cookie: cookie,
            removed: false,
        }
    }

    /// Create a new `DeltaCookie` that is being removed from a jar. The
    /// `cookie` should be a "removal" cookie.
    #[inline]
    pub fn removed(cookie: Cookie<'c>) -> DeltaCookie<'c> {
        DeltaCookie {
            cookie: cookie,
            removed: true,
        }
    }
}

impl<'c> Deref for DeltaCookie<'c> {
    type Target = Cookie<'c>;

    fn deref(&self) -> &Cookie<'c> {
        &self.cookie
    }
}

impl<'c> DerefMut for DeltaCookie<'c> {
    fn deref_mut(&mut self) -> &mut Cookie<'c> {
        &mut self.cookie
    }
}

impl PartialEq for DeltaCookie<'_> {
    fn eq(&self, other: &DeltaCookie) -> bool {
        self.name() == other.name()
    }
}

impl Eq for DeltaCookie<'_> {}

impl Hash for DeltaCookie<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name().hash(state);
    }
}

impl Borrow<str> for DeltaCookie<'_> {
    fn borrow(&self) -> &str {
        self.name()
    }
}
