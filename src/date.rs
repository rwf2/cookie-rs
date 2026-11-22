//! Parsing and formatting of cookie dates.

use std::fmt;
use std::time::{Duration, SystemTime};

/// The latest representable date: Dec 31, 9999, 23:59:59 UTC, in seconds since
/// the Unix epoch. RFC 6265 requires dates not to exceed 9999 years.
const MAX_TIMESTAMP: i64 = 253_402_300_799;

/// The earliest date that can be written: Jan 1, 0000, 00:00:00 UTC, in seconds
/// since the Unix epoch. An HTTP date has a four digit, unsigned year.
const MIN_TIMESTAMP: i64 = -62_167_219_200;

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

/// The latest date-time a cookie can expire: Dec 31, 9999, 23:59:59 UTC.
pub(crate) fn max_datetime() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(MAX_TIMESTAMP as u64)
}

/// Returns the number of whole seconds between the Unix epoch and `datetime`,
/// rounding down and saturating. This is negative if `datetime` is before the
/// epoch.
fn timestamp(datetime: SystemTime) -> i64 {
    match datetime.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_secs()).unwrap_or(i64::MAX),
        Err(e) => {
            let before = e.duration();
            i64::try_from(before.as_secs()).ok()
                .and_then(|secs| secs.checked_add((before.subsec_nanos() > 0) as i64))
                .map_or(i64::MIN, |secs| -secs)
        }
    }
}

/// Returns the date-time that is `timestamp` seconds from the Unix epoch, if
/// it is representable on this platform.
fn datetime(timestamp: i64) -> Option<SystemTime> {
    let magnitude = Duration::from_secs(timestamp.unsigned_abs());
    match timestamp < 0 {
        true => SystemTime::UNIX_EPOCH.checked_sub(magnitude),
        false => SystemTime::UNIX_EPOCH.checked_add(magnitude),
    }
}

/// Days from the Unix epoch to the proleptic Gregorian date `y`-`m`-`d`.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let (era, yoe) = (y.div_euclid(400), y.rem_euclid(400));
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
}

/// The proleptic Gregorian date `(y, m, d)` that is `days` from the Unix epoch.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let (era, doe) = (z.div_euclid(146_097), z.rem_euclid(146_097));
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + (m <= 2) as i64, m, doy - (153 * mp + 2) / 5 + 1)
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        4 | 6 | 9 | 11 => 30,
        2 if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) => 29,
        2 => 28,
        _ => 31,
    }
}

/// Wrapper around a date-time whose `Display` implementation formats it as an
/// HTTP date: `Wed, 21 Oct 2015 07:28:00 GMT`. Dates outside of years 0000 to
/// 9999 are written as the closest date in that range.
pub(crate) struct HttpDate(pub SystemTime);

impl fmt::Display for HttpDate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let timestamp = timestamp(self.0).clamp(MIN_TIMESTAMP, MAX_TIMESTAMP);
        let (days, secs) = (timestamp.div_euclid(86_400), timestamp.rem_euclid(86_400));
        let (y, m, d) = civil_from_days(days);
        let weekday = WEEKDAYS[(days + 4).rem_euclid(7) as usize];
        let month = MONTHS[(m - 1) as usize];
        write!(f, "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
            weekday, d, month, y, secs / 3600, secs / 60 % 60, secs % 60)
    }
}

/// Splits `min` to `max` leading ASCII digits off of `s`, returning their
/// value and the rest of `s`. Returns `None` if `s` does not start with `min`
/// to `max` digits.
fn digits(s: &str, min: usize, max: usize) -> Option<(i64, &str)> {
    let n = s.bytes().take_while(|b| b.is_ascii_digit()).count();
    if n < min || n > max {
        return None;
    }

    Some((s[..n].parse().ok()?, &s[n..]))
}

fn hms(token: &str) -> Option<(i64, i64, i64)> {
    let (h, rest) = digits(token, 1, 2)?;
    let (m, rest) = digits(rest.strip_prefix(':')?, 1, 2)?;
    let (s, _) = digits(rest.strip_prefix(':')?, 1, 2)?;
    Some((h, m, s))
}

fn month(token: &str) -> Option<i64> {
    let name = token.get(..3)?;
    let i = MONTHS.iter().position(|m| m.eq_ignore_ascii_case(name))?;
    Some(i as i64 + 1)
}

/// Parses a cookie date as specified in RFC 6265 §5.1.1.
///
/// The algorithm is purposefully lenient. In particular, it ignores the
/// weekday and the time zone, if any, and reads the date as UTC.
pub(crate) fn parse(string: &str) -> Option<SystemTime> {
    let is_delimiter = |c: char| matches!(c,
        '\t' | ' '..='/' | ';'..='@' | '['..='`' | '{'..='~');

    let (mut time, mut day, mut mon, mut year) = (None, None, None, None);
    for token in string.split(is_delimiter).filter(|t| !t.is_empty()) {
        if time.is_none() {
            time = hms(token);
            if time.is_some() {
                continue;
            }
        }

        if day.is_none() {
            day = digits(token, 1, 2).map(|(d, _)| d);
            if day.is_some() {
                continue;
            }
        }

        if mon.is_none() {
            mon = month(token);
            if mon.is_some() {
                continue;
            }
        }

        if year.is_none() {
            year = digits(token, 2, 4).map(|(y, _)| y);
        }
    }

    let ((h, min, s), d, m, y) = (time?, day?, mon?, year?);
    let y = match y {
        70..=99 => y + 1900,
        0..=69 => y + 2000,
        _ => y,
    };

    if y < 1601 || d < 1 || d > days_in_month(y, m) || h > 23 || min > 59 || s > 59 {
        return None;
    }

    datetime(days_from_civil(y, m, d) * 86_400 + h * 3600 + min * 60 + s)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};
    use super::{HttpDate, datetime, parse, timestamp};

    // Computed independently of this module.
    const DATES: &[(i64, &str)] = &[
        (-11644473600, "Mon, 01 Jan 1601 00:00:00 GMT"),
        (-2203891201, "Wed, 28 Feb 1900 23:59:59 GMT"),
        (-2203891200, "Thu, 01 Mar 1900 00:00:00 GMT"),
        (-1, "Wed, 31 Dec 1969 23:59:59 GMT"),
        (0, "Thu, 01 Jan 1970 00:00:00 GMT"),
        (784111777, "Sun, 06 Nov 1994 08:49:37 GMT"),
        (951825600, "Tue, 29 Feb 2000 12:00:00 GMT"),
        (1445412480, "Wed, 21 Oct 2015 07:28:00 GMT"),
        (1508570880, "Sat, 21 Oct 2017 07:28:00 GMT"),
        (2147483648, "Tue, 19 Jan 2038 03:14:08 GMT"),
        (4107456000, "Sun, 28 Feb 2100 00:00:00 GMT"),
        (4107542400, "Mon, 01 Mar 2100 00:00:00 GMT"),
        (13574563200, "Tue, 29 Feb 2400 00:00:00 GMT"),
        (253402300799, "Fri, 31 Dec 9999 23:59:59 GMT"),
    ];

    fn parse_timestamp(string: &str) -> Option<i64> {
        parse(string).map(timestamp)
    }

    #[test]
    fn format_and_parse() {
        for &(ts, string) in DATES {
            // Not every platform can represent every date.
            let Some(datetime) = datetime(ts) else { continue };
            assert_eq!(HttpDate(datetime).to_string(), string);
            assert_eq!(parse_timestamp(string), Some(ts), "{}", string);
        }
    }

    #[test]
    fn format_truncates_subseconds() {
        let after = SystemTime::UNIX_EPOCH + Duration::from_millis(1500);
        assert_eq!(HttpDate(after).to_string(), "Thu, 01 Jan 1970 00:00:01 GMT");

        if let Some(before) = SystemTime::UNIX_EPOCH.checked_sub(Duration::from_millis(1500)) {
            assert_eq!(HttpDate(before).to_string(), "Wed, 31 Dec 1969 23:59:58 GMT");
        }
    }

    #[test]
    fn format_is_bounded() {
        // Not every platform can represent every date.
        let max = "Fri, 31 Dec 9999 23:59:59 GMT";
        for ts in [253402300800, 1 << 40, i64::MAX] {
            if let Some(datetime) = datetime(ts) {
                assert_eq!(HttpDate(datetime).to_string(), max);
            }
        }

        let min = "Sat, 01 Jan 0000 00:00:00 GMT";
        for ts in [-62167219200, -62167219201, -(1 << 40), i64::MIN + 1] {
            if let Some(datetime) = datetime(ts) {
                assert_eq!(HttpDate(datetime).to_string(), min);
            }
        }

        if let Some(datetime) = datetime(-62167219199) {
            assert_eq!(HttpDate(datetime).to_string(), "Sat, 01 Jan 0000 00:00:01 GMT");
        }
    }

    #[test]
    fn parse_lenient() {
        let expected = Some(1445412480);
        let strings = [
            "Wed, 21 Oct 2015 07:28:00 GMT",
            "Wed, 21-Oct-2015 07:28:00 GMT",
            "Wednesday, 21-Oct-15 07:28:00 GMT",
            "Wed Oct 21 07:28:00 2015",
            "21 Oct 2015 07:28:00 GMT",
            "21 Oct 2015 07:28:00",
            "Wed, 21 Oct 2015 07:28:00 UTC",
            "Wed, 21 Oct 2015 7:28:00 GMT",
            "Wed,21 Oct 2015 07:28:00 GMT",
            "  Wed, 21 Oct 2015 07:28:00 GMT  ",
            "wed, 21 OCT 2015 07:28:00 gmt",
            "Wed, 21 October 2015 07:28:00 GMT",
            "07:28:00 2015 Oct 21",
            "Wed Oct 21 2015 07:28:00 GMT+0000 (Coordinated Universal Time)",
        ];

        for string in strings {
            assert_eq!(parse_timestamp(string), expected, "{}", string);
        }

        // Time zones are ignored: the date is always read as UTC.
        assert_eq!(parse_timestamp("Wed, 21 Oct 2015 07:28:00 +0500"), expected);
        assert_eq!(parse_timestamp("Wed, 21 Oct 2015 07:28:00 PST"), expected);
    }

    #[test]
    fn parse_invalid() {
        let strings = [
            "",
            "Wed, 21 Oct 2015",
            "Wed, 21 Oct 07:28:00 GMT",
            "Wed, Oct 2015 07:28:00 GMT",
            "Wed, 21 2015 07:28:00 GMT",
            "Wed, 21 Okt 2015 07:28:00 GMT",
            "2015-10-21T07:28:00Z",
            "Wed, 00 Oct 2015 07:28:00 GMT",
            "Wed, 32 Oct 2015 07:28:00 GMT",
            "Tue, 31 Sep 2015 07:28:00 GMT",
            "Sun, 29 Feb 2015 07:28:00 GMT",
            "Wed, 29 Feb 2100 07:28:00 GMT",
            "Wed, 21 Oct 2015 24:28:00 GMT",
            "Wed, 21 Oct 2015 07:60:00 GMT",
            "Wed, 21 Oct 2015 07:28:60 GMT",
            "Wed, 21 Oct 2015 07:28 GMT",
            "Wed, 21 Oct 2015 007:28:00 GMT",
            "Wed, 21 Oct 1600 07:28:00 GMT",
            "Wed, 21 Oct 5 07:28:00 GMT",
            "Wed, 21 Oct 20155 07:28:00 GMT",
            "Sat, 01 Jan 10000 00:00:00 GMT",
        ];

        for string in strings {
            assert_eq!(parse(string), None, "{}", string);
        }
    }
}
