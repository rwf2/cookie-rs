//! This module contains the [`Duration`] type which is used for the [`Cookie::max_age`][cma]
//! parameter.
//!
//! [cma]: method@crate::Cookie::max_age

use std::convert::TryInto;

use time;

/// A `Duration` type to represent a span of time for the [`Cookie::max_age`][cma] parameter. It
/// is similar to [`std::time::Duration`], but only contains whole seconds, and provides some extra
/// convenience methods such as [`from_mins`](Duration::from_mins()) and
/// [`as_mins`](Duration::as_mins()) (and similar for hours & “naive” days).
///
/// [`u32`] should be sufficient for cookies’ `Max-Age` parameter, since an [HTTP workgroup
/// draft][httpwg] is proposing an upper limit of 400 days, which is currently implemented in
/// [Chrome][chrome], and which received positive reactions from Firefox & Safari.
///
/// [cma]: method@crate::Cookie::max_age
/// [httpwg]: https://httpwg.org/http-extensions/draft-ietf-httpbis-rfc6265bis.html#name-the-max-age-attribute
/// [chrome]: https://developer.chrome.com/blog/cookie-max-age-expires/
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Duration(u32);

impl Duration {

    /// A duration of zero time.
    pub const ZERO: Self = Self(0);

    /// The maximum duration, `u32::MAX` seconds.
    pub const MAX: Self = Self(u32::MAX);

    /// Creates a new `Duration` from the specified number of whole seconds.
    pub const fn from_secs(seconds: u32) -> Self {
        Self(seconds)
    }

    /// Creates a new `Duration` from the specified number of whole minutes.
    pub const fn from_mins(minutes: u32) -> Self {
        Self::from_secs(match minutes.checked_mul(60) { Some(s) => s, _ => u32::MAX })
    }

    /// Creates a new `Duration` from the specified number of whole hours.
    pub const fn from_hours(hours: u32) -> Self {
        Self::from_mins(match hours.checked_mul(60) { Some(s) => s, _ => u32::MAX })
    }

    /// Creates a new `Duration` from the specified number of whole “naive” days, that is the number
    /// of whole 24-hour periods (not considering timezone changes, etc.).
    pub const fn from_naive_days(days: u32) -> Self {
        Self::from_hours(match days.checked_mul(24) { Some(s) => s, _ => u32::MAX })
    }

    /// Returns the number of _whole_ seconds contained by this `Duration`.
    pub const fn as_secs(&self) -> u32 {
        self.0
    }

    /// Returns the number of _whole_ minutes contained by this `Duration`.
    pub const fn as_mins(&self) -> u32 {
        self.as_secs() / 60
    }

    /// Returns the number of _whole_ hours contained by this `Duration`.
    pub const fn as_hours(&self) -> u32 {
        self.as_mins() / 60
    }

    /// Returns the number of _whole_ “naive” days contained by this `Duration`, that is the number
    /// of whole 24-hour periods.
    pub const fn as_naive_days(&self) -> u32 {
        self.as_hours() / 24
    }
}

impl From<u32> for Duration {
    /// Creates a new `Duration` from the specified number of whole seconds.
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<time::Duration> for Duration {
    fn from(value: time::Duration) -> Self {
        let seconds = value.whole_seconds();
        Self(seconds.try_into().unwrap_or_else(|_| if seconds < 0 { 0 } else { u32::MAX }))
    }
}

impl std::ops::Sub<Duration> for time::OffsetDateTime {
    type Output = time::OffsetDateTime;
    fn sub(self, rhs: Duration) -> Self::Output {
        self - time::Duration::seconds(rhs.0 as i64)
    }
}

impl std::ops::Add<Duration> for time::OffsetDateTime {
    type Output = time::OffsetDateTime;
    fn add(self, rhs: Duration) -> Self::Output {
        self + time::Duration::seconds(rhs.0 as i64)
    }
}
