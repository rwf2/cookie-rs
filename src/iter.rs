use crate::Cookie;
use crate::parse::parse_cookie;
use crate::parse::ParseError;

pub struct CookieIter<'c> {
    pub input: Option<&'c str>,
    pub decode: bool,
}

impl <'c> Iterator for CookieIter<'c>
{
    type Item = Result<Cookie<'c>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut split2 = self.input?.splitn(2, ';');
        let unparsed = split2.next().unwrap().trim();
        self.input = split2.next();
        Some(parse_cookie(unparsed, self.decode))
    }
}

impl <'c> CookieIter<'c> {
    pub fn new(iter: &'c str, decode: bool) -> CookieIter<'c>
    {
        CookieIter {
            input: Some(iter),
            decode,
        }
    }

}

#[cfg(test)]
mod test {
    use super::CookieIter;

    #[test]
    fn test_iter() {
        let mut ci = CookieIter::new("hello=world; foo=bar", false);
        
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
        let mut ci = CookieIter::new("hello=world; foo=bar%20baz", false);
        match ci.next() {
            Some(Ok(cookie)) => assert_eq!(("hello", "world"), cookie.name_value()),
            _=> assert!(false),
        } match ci.next() {
            Some(Ok(cookie)) => assert_eq!(("foo", "bar%20baz"), cookie.name_value()),
            _=> assert!(false),
        }

        let mut ci = CookieIter::new("hello=world; foo=bar%20baz", true);
        match ci.next() {
            Some(Ok(cookie)) => assert_eq!(("hello", "world"), cookie.name_value()),
            _=> assert!(false),
        } match ci.next() {
            Some(Ok(cookie)) => assert_eq!(("foo", "bar baz"), cookie.name_value()),
            _=> assert!(false),
        }
    }

}
