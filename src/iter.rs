use crate::Cookie;
use crate::parse::{

pub struct CookieIter<'c> {
    pub input: Option<&'c str>,
}

impl <'c> Iterator for CookieIter<'c> {
    type Item = Result<Cookie<'c>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut split2 = self.input?.splitn(2, ';');
        let unparsed = split2.next().unwrap().trim();
        self.input = split2.next();
        
        Some(Cookie::parse(unparsed))
    }
}

#[cfg(test)]
mod test {
    use super::CookieIter;

    #[test]
    fn test_iter() {
        let ci = CookieIter { input: Some("hello=world; foo=bar") };
        
        for cookie in ci {
            println!("Cookie: {:?}", cookie);
        }
    }
}
