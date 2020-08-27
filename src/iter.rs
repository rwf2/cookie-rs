use crate::Cookie;
use crate::parse::parse_cookie;
use crate::parse::ParseError;
use std::borrow::Cow;

pub struct CookieIter<'c> {
    pub input: Option<Cow<'c, str>>,
    pub decode: bool,
}

impl <'c> Iterator for CookieIter<'c>
{
    type Item = Result<Cookie<'c>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        let input = self.input.as_mut()?;
        if let Some(split_index) = input.find(';') {
            let split_index = split_index + 1;
            match input {
                Cow::Borrowed(ref mut input) => {
                    let next = &input[..split_index];
                    *input = &input[split_index..];
                    Some(parse_cookie(next, self.decode))
                }
                Cow::Owned(ref mut input) => {
                    let next = input.drain(..split_index).collect::<String>();
                    Some(parse_cookie(next, self.decode))
                }
            }
        } else {
            let next = self.input.take()?;
            Some(parse_cookie(next, self.decode))
        }
    }
}

impl <'c> CookieIter<'c> {
    pub fn new(iter: Cow<'c, str>, decode: bool) -> CookieIter<'c>
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
    use std::borrow::Cow;

    #[test]
    fn test_iter() {
        let input = Cow::from("hello=world; foo=bar");
        let mut ci = CookieIter::new(input, false);
        
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
        let mut ci = CookieIter::new(input, false);
        match ci.next() {
            Some(Ok(cookie)) => assert_eq!(("hello", "world"), cookie.name_value()),
            _=> assert!(false),
        } match ci.next() {
            Some(Ok(cookie)) => assert_eq!(("foo", "bar%20baz"), cookie.name_value()),
            _=> assert!(false),
        }

        let input = Cow::from("hello=world; foo=bar%20baz");
        let mut ci = CookieIter::new(input, true);
        match ci.next() {
            Some(Ok(cookie)) => assert_eq!(("hello", "world"), cookie.name_value()),
            _=> assert!(false),
        } match ci.next() {
            Some(Ok(cookie)) => assert_eq!(("foo", "bar baz"), cookie.name_value()),
            _=> assert!(false),
        }
    }

}
