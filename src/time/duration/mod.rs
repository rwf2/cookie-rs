mod internal;

#[derive(Debug, Clone, Copy)]
pub enum Duration {
    #[cfg(feature = "time")]
    Time(time::Duration),
    #[cfg(feature = "chrono")]
    Chrono(chrono::Duration)
}

pub(crate) trait InternalDuration {
    const ZERO: Self;

    fn seconds(&self) -> i64;
    fn milliseconds(&self) -> i128;
}

impl PartialEq for Duration {
    fn eq(&self, other: &Self) -> bool {
        self.milliseconds() == other.milliseconds()
    }
}

#[cfg(feature = "time")]
mod time_impl {
    use super::*;

    impl From<Duration> for time::Duration {
        fn from(value: Duration) -> Self {
            time::Duration::milliseconds(value.milliseconds() as i64)
        }
    }

    impl From<time::Duration> for Duration {
        fn from(value: time::Duration) -> Self {
            Duration::Time(value)
        }
    }

    impl PartialEq<time::Duration> for Duration {
        fn eq(&self, other: &time::Duration) -> bool {
            self.milliseconds().eq(&other.milliseconds())
        }
    }

    impl PartialEq<Duration> for time::Duration {
        fn eq(&self, other: &Duration) -> bool {
            self.milliseconds().eq(&other.milliseconds())
        }
    }
}

#[cfg(feature = "chrono")]
mod chrono_impl {
    use super::*;

    impl From<Duration> for chrono::Duration {
        fn from(value: Duration) -> Self {
            chrono::Duration::milliseconds(value.milliseconds() as i64)
        }
    }

    impl From<chrono::Duration> for Duration {
        fn from(value: chrono::Duration) -> Self {
            Duration::Chrono(value)
        }
    }

    impl PartialEq<chrono::Duration> for Duration {
        fn eq(&self, other: &chrono::Duration) -> bool {
            self.milliseconds().eq(&other.milliseconds())
        }
    }

    impl PartialEq<Duration> for chrono::Duration {
        fn eq(&self, other: &Duration) -> bool {
            self.milliseconds().eq(&other.milliseconds())
        }
    }
}
