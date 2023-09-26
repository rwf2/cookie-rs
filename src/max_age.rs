//! This module contains the [`Duration`] type which is used for the [`Cookie::max_age`][cma]
//! parameter.
//!
//! [cma]: method@crate::Cookie::max_age

/// A `Duration` type to represent a span of time for the [`Cookie::max_age`][cma] parameter. It
/// wraps either [`std::time::Duration`] or `[time::Duration]` (the latter if the `time` feature is
/// enabled), but is kept within the range of `0..=u32::MAX` seconds.
///
/// [`u32`] should be sufficient for cookies’ `Max-Age` parameter, since an [HTTP workgroup
/// draft][httpwg] is proposing an upper limit of 400 days, which is currently implemented in
/// [Chrome][chrome], and which received positive reactions from Firefox & Safari.
///
/// [cma]: method@crate::Cookie::max_age
/// [httpwg]: https://httpwg.org/http-extensions/draft-ietf-httpbis-rfc6265bis.html#name-the-max-age-attribute
/// [chrome]: https://developer.chrome.com/blog/cookie-max-age-expires/
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Duration(
    time::Duration,
);

macro_rules! clamp {
    ( $seconds:expr ) => { {
        #[allow(unused_comparisons)]
        if $seconds >= 0 && $seconds <= u32::MAX as _ { $seconds as u32 }
        else if $seconds < 0 as _ { 0 }
        else { u32::MAX }
    } };
}

impl Duration {

    /// A duration of zero time.
    pub const ZERO: Self = Self(time::Duration::ZERO);

    /// The maximum duration, `u32::MAX` seconds.
    pub const MAX: Self = Self(time::Duration::seconds(u32::MAX as _));

    /// Creates a new `Duration` from the specified number of whole seconds, clamped to
    /// `0..=u32::MAX`.
    pub const fn from_secs(seconds: u32) -> Self {
        Self(time::Duration::seconds(seconds as _))
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
        clamp!(self.0.whole_seconds())
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

    /// Returns the equivalent [`std::time::Duration`].
    pub const fn as_std(self) -> std::time::Duration {
        if self.0.is_negative() { std::time::Duration::ZERO } else { self.0.unsigned_abs() }
    }

    /// Returns the equivalent [`time::Duration`].
    pub const fn as_time(self) -> time::Duration {
        self.0
    }
}

impl From<u32> for Duration {
    /// Creates a new `Duration` from the specified number of whole seconds.
    fn from(value: u32) -> Self {
        Self::from_secs(value)
    }
}

impl From<std::time::Duration> for Duration {
    fn from(value: std::time::Duration) -> Self {
        Self::from_secs(clamp!(value.as_secs()))
    }
}

impl From<time::Duration> for Duration {
    fn from(value: time::Duration) -> Self {
        Self::from_secs(clamp!(value.whole_seconds()))
    }
}

impl std::ops::Add<Duration> for Duration {
    type Output = Duration;
    fn add(self, rhs: Duration) -> Self::Output {
        Self::from_secs(clamp!((self.0 + rhs.0).whole_seconds()))
    }
}

impl std::ops::Sub<Duration> for Duration {
    type Output = Duration;
    fn sub(self, rhs: Duration) -> Self::Output {
        Self::from_secs(clamp!((self.0 - rhs.0).whole_seconds()))
    }
}

impl std::ops::Add<Duration> for time::OffsetDateTime {
    type Output = time::OffsetDateTime;
    fn add(self, rhs: Duration) -> Self::Output {
        self + rhs.0
    }
}

impl std::ops::Sub<Duration> for time::OffsetDateTime {
    type Output = time::OffsetDateTime;
    fn sub(self, rhs: Duration) -> Self::Output {
        self - rhs.0
    }
}
