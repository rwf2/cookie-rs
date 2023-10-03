use super::{DateTime, InternalDateTime};

impl InternalDateTime for DateTime {
    const MAX: Self = {
        #[cfg(feature = "time")] {
            DateTime::Time(time::OffsetDateTime::MAX)
        }

        #[cfg(not(feature = "time"))] {
            DateTime::Chrono(chrono::DateTime::MAX)
        }
    };

    fn now() -> Self {
        #[cfg(feature = "time")] {
            DateTime::Time(time::OffsetDateTime::now())
        }

        #[cfg(not(feature = "time"))] {
            DateTime::Chrono(chrono::DateTime::now())
        }
    }

    fn destruct(&self) -> (i32, u32, u32, i32, u32, u32, u32) {
        match self {
            #[cfg(feature = "time")]
            DateTime::Time(inner) => inner.destruct(),
            #[cfg(feature = "chrono")]
            DateTime::Chrono(inner) => inner.destruct(),
        }
    }

    fn expiration_format(&self) -> Option<String> {
        match self {
            #[cfg(feature = "time")]
            DateTime::Time(inner) => inner.expiration_format(),
            #[cfg(feature = "chrono")]
            DateTime::Chrono(inner) => inner.expiration_format(),
        }
    }
}

#[cfg(feature = "time")]
impl InternalDateTime for time::OffsetDateTime {
    const MAX: Self = time::macros::datetime!(9999-12-31 23:59:59.999_999 UTC);

    fn now() -> Self {
        time::OffsetDateTime::now_utc()
    }

    fn destruct(&self) -> (i32, u32, u32, i32, u32, u32, u32) {
        let (year, month, day) = self.to_calendar_date();
        let (hour, minute, second, nanos) = self.to_hms_nano();
        (year, month as u32, day.into(), hour.into(), minute.into(), second.into(), nanos)
    }

    fn expiration_format(&self) -> Option<String> {
        self.format(&crate::parse::FMT1).ok()
    }
}

#[cfg(feature = "chrono")]
impl InternalDateTime for chrono::DateTime<chrono::Utc> {
    const MAX: Self = chrono::DateTime::from_naive_utc_and_offset(
        chrono::NaiveDateTime::new(
            chrono::NaiveDate::from_ymd_opt(9999, 12, 31).unwrap(),
            chrono::NaiveTime::from_hms_micro_opt(23, 59, 59, 999_999).unwrap()
        ), chrono::Utc);

    fn now() -> Self {
        chrono::Utc::now()
    }

    fn destruct(&self) -> (i32, u32, u32, i32, u32, u32, u32) {
        todo!()
    }

    fn expiration_format(&self) -> Option<String> {
        todo!()
    }
}
