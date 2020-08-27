use crate::Cookie;
use crate::parse::parse_cookie;
use crate::parse::ParseError;
use std::borrow::Cow;

/// An iterator over a list of `cookie`s. Follows the HTTP request cookie spec. Accepts a semicolon separated list of key-value pairs.
/// 
/// This struct is created by the `parse_string` method. See its documentation for more
pub struct CookieIter<'c> {
    /// The remaining input that has not yet been iterated over
    pub remaining: Option<Cow<'c, str>>,
    /// Is this iterator parsing a percent-encoded string?
    pub encoded: bool,
}

impl <'c> Iterator for CookieIter<'c>
{
    type Item = Result<Cookie<'c>, ParseError>;


    fn next(&mut self) -> Option<Self::Item> {
        let remaining = self.remaining.as_mut()?;
        if let Some(split_index) = remaining.find(';') {
            let split_index = split_index + 1;
            match remaining {
                Cow::Borrowed(ref mut remaining) => {
                    let next = &remaining[..split_index];
                    *remaining = &remaining[split_index..];
                    Some(parse_cookie(next, self.encoded))
                }
                Cow::Owned(ref mut remaining) => {
                    let next = remaining.drain(..split_index).collect::<String>();
                    Some(parse_cookie(next, self.encoded))
                }
            }
        } else {
            let next = self.remaining.take()?;
            Some(parse_cookie(next, self.encoded))
        }
    }
}

#[cfg(test)]
mod test {
    use super::CookieIter;
    use std::borrow::Cow;

    #[test]
    fn test_iter() {
        let input = Cow::from("hello=world; foo=bar");
        let mut ci = CookieIter { remaining: Some(input), encoded: false };
        
        match ci.next() {
            Some(Ok(cookie)) => assert_eq!(("hello", "world"), cookie.name_value()),
            _=> assert!(false),
        }

        match ci.next() {
            Some(Ok(cookie)) => assert_eq!(("foo", "bar"), cookie.name_value()),
            _=> assert!(false),
        }
    }

    #[test]
    #[cfg(feature = "percent-encode")]
    fn test_iter_encode() {
        let input = Cow::from("hello=world; foo=bar%20baz");
        let mut ci = CookieIter { remaining: Some(input), encoded: false };
        match ci.next() {
            Some(Ok(cookie)) => assert_eq!(("hello", "world"), cookie.name_value()),
            _=> assert!(false),
        } match ci.next() {
            Some(Ok(cookie)) => assert_eq!(("foo", "bar%20baz"), cookie.name_value()),
            _=> assert!(false),
        }

        let input = Cow::from("hello=world; foo=bar%20baz");
        let mut ci = CookieIter { remaining: Some(input), encoded: true };
        match ci.next() {
            Some(Ok(cookie)) => assert_eq!(("hello", "world"), cookie.name_value()),
            _=> assert!(false),
        } match ci.next() {
            Some(Ok(cookie)) => assert_eq!(("foo", "bar baz"), cookie.name_value()),
            _=> assert!(false),
        }
    }

}
