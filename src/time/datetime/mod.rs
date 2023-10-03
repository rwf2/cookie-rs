mod internal;

#[derive(Debug, Clone, Copy, Eq)]
pub enum DateTime {
    #[cfg(feature = "time")]
    Time(time::OffsetDateTime),
    #[cfg(feature = "chrono")]
    Chrono(chrono::DateTime<chrono::Utc>)
}

/// API implemented for internal use. This is private. Everything else: public.
pub(crate) trait InternalDateTime: From<DateTime> + Into<DateTime> {
    /// The max cookie date-time.
    const MAX: Self;

    /// The datetime right now.
    fn now() -> Self;

    /// UTC based (year, month, day, hour, minute, second, nanosecond).
    ///   * date is ISO 8601 calendar date
    ///   * month is 1-indexed
    fn destruct(&self) -> (i32, u32, u32, i32, u32, u32, u32);

    /// The datetime as a string suitable for use as a cookie expiration.
    fn expiration_format(&self) -> Option<String>;
}

impl PartialEq for DateTime {
    fn eq(&self, other: &Self) -> bool {
        self.destruct() == other.destruct()
    }
}

impl std::hash::Hash for DateTime {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.destruct().hash(state)
    }
}

impl PartialOrd for DateTime {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.destruct().partial_cmp(&other.destruct())
    }
}

impl Ord for DateTime {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.destruct().cmp(&other.destruct())
    }
}

#[cfg(feature = "time")]
mod time_impl {
    use super::*;

    impl From<DateTime> for time::OffsetDateTime {
        fn from(value: DateTime) -> Self {
            let (yr, mon, day, hr, min, sec, nano) = value.destruct();
            todo!()
        }
    }

    impl From<time::OffsetDateTime> for DateTime {
        fn from(value: time::OffsetDateTime) -> Self {
            DateTime::Time(value)
        }
    }

    impl PartialEq<time::OffsetDateTime> for DateTime {
        fn eq(&self, other: &time::OffsetDateTime) -> bool {
            self.destruct().eq(&other.destruct())
        }
    }
}

#[cfg(feature = "chrono")]
mod chrono_impl {
    use super::*;

    impl From<DateTime> for chrono::DateTime<chrono::Utc> {
        fn from(value: DateTime) -> Self {
            let (yr, mon, day, hr, min, sec, nano) = value.destruct();
            todo!()
        }
    }

    impl From<chrono::DateTime<chrono::Utc>> for DateTime {
        fn from(value: chrono::DateTime<chrono::Utc>) -> Self {
            DateTime::Chrono(value)
        }
    }

    impl PartialEq<chrono::DateTime<chrono::Utc>> for DateTime {
        fn eq(&self, other: &chrono::DateTime<chrono::Utc>) -> bool {
            self.destruct().eq(&other.destruct())
        }
    }
}
