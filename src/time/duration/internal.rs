use super::{Duration, InternalDuration};

impl InternalDuration for Duration {
    #[cfg(feature = "time")]
    const ZERO: Self = Duration::Time(time::Duration::ZERO);

    #[cfg(not(feature = "time"))]
    const ZERO: Self = Duration::Chrono(chrono::Duration::zero());

    fn seconds(&self) -> i64 {
        match self {
            #[cfg(feature = "time")]
            Duration::Time(v) => v.seconds(),
            #[cfg(feature = "chrono")]
            Duration::Chrono(v) => v.seconds(),
        }
    }

    fn milliseconds(&self) -> i128 {
        match self {
            #[cfg(feature = "time")]
            Duration::Time(v) => v.milliseconds(),
            #[cfg(feature = "chrono")]
            Duration::Chrono(v) => v.milliseconds(),
        }
    }
}

impl InternalDuration for time::Duration {
    const ZERO: Self = time::Duration::ZERO;

    fn seconds(&self) -> i64 {
        self.whole_seconds()
    }

    fn milliseconds(&self) -> i128 {
        self.whole_milliseconds()
    }
}

impl InternalDuration for chrono::Duration {
    const ZERO: Self = chrono::Duration::zero();

    fn seconds(&self) -> i64 {
        self.num_seconds()
    }

    fn milliseconds(&self) -> i128 {
        self.num_milliseconds().into()
    }
}
