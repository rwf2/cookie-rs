use std::time::SystemTime;

/// A cookie's expiration: either a date-time or session.
///
/// An `Expiration` is constructible with `Expiration::from()` via any of:
///
///   * `None` -> `Expiration::Session`
///   * `Some(SystemTime)` -> `Expiration::DateTime`
///   * `SystemTime` -> `Expiration::DateTime`
///
/// ```rust
/// use std::time::SystemTime;
///
/// use cookie::Expiration;
///
/// let expires = Expiration::from(None);
/// assert_eq!(expires, Expiration::Session);
///
/// let now = SystemTime::now();
/// let expires = Expiration::from(now);
/// assert_eq!(expires, Expiration::DateTime(now));
///
/// let expires = Expiration::from(Some(now));
/// assert_eq!(expires, Expiration::DateTime(now));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Expiration {
    /// Expiration for a "permanent" cookie at a specific date-time.
    DateTime(SystemTime),
    /// Expiration for a "session" cookie. Browsers define the notion of a
    /// "session" and will automatically expire session cookies when they deem
    /// the "session" to be over. This is typically, but need not be, when the
    /// browser is closed.
    Session,
}

impl Expiration {
    /// Returns `true` if `self` is an `Expiration::DateTime`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::time::SystemTime;
    ///
    /// use cookie::Expiration;
    ///
    /// let expires = Expiration::from(None);
    /// assert!(!expires.is_datetime());
    ///
    /// let expires = Expiration::from(SystemTime::now());
    /// assert!(expires.is_datetime());
    /// ```
    pub fn is_datetime(&self) -> bool {
        match self {
            Expiration::DateTime(_) => true,
            Expiration::Session => false
        }
    }

    /// Returns `true` if `self` is an `Expiration::Session`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::time::SystemTime;
    ///
    /// use cookie::Expiration;
    ///
    /// let expires = Expiration::from(None);
    /// assert!(expires.is_session());
    ///
    /// let expires = Expiration::from(SystemTime::now());
    /// assert!(!expires.is_session());
    /// ```
    pub fn is_session(&self) -> bool {
        match self {
            Expiration::DateTime(_) => false,
            Expiration::Session => true
        }
    }

    /// Returns the inner `SystemTime` if `self` is a `DateTime`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::time::SystemTime;
    ///
    /// use cookie::Expiration;
    ///
    /// let expires = Expiration::from(None);
    /// assert!(expires.datetime().is_none());
    ///
    /// let now = SystemTime::now();
    /// let expires = Expiration::from(now);
    /// assert_eq!(expires.datetime(), Some(now));
    /// ```
    pub fn datetime(self) -> Option<SystemTime> {
        match self {
            Expiration::Session => None,
            Expiration::DateTime(v) => Some(v)
        }
    }

    /// Applied `f` to the inner `SystemTime` if `self` is a `DateTime` and
    /// returns the mapped `Expiration`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::time::{Duration, SystemTime};
    ///
    /// use cookie::Expiration;
    ///
    /// let now = SystemTime::now();
    /// let one_week = Duration::from_secs(7 * 24 * 60 * 60);
    ///
    /// let expires = Expiration::from(now);
    /// assert_eq!(expires.map(|t| t + one_week).datetime(), Some(now + one_week));
    ///
    /// let expires = Expiration::from(None);
    /// assert_eq!(expires.map(|t| t + one_week).datetime(), None);
    /// ```
    pub fn map<F>(self, f: F) -> Self
        where F: FnOnce(SystemTime) -> SystemTime
    {
        match self {
            Expiration::Session => Expiration::Session,
            Expiration::DateTime(v) => Expiration::DateTime(f(v)),
        }
    }
}

impl From<SystemTime> for Expiration {
    fn from(datetime: SystemTime) -> Self {
        Expiration::DateTime(datetime)
    }
}

impl From<Option<SystemTime>> for Expiration {
    fn from(option: Option<SystemTime>) -> Self {
        match option {
            Some(value) => Expiration::DateTime(value),
            None => Expiration::Session
        }
    }
}
