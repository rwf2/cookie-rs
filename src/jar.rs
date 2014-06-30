use std::collections::{HashMap, HashSet};
use time;

use Cookie;

pub struct CookieJar {
    orig_map: HashMap<String, Cookie>,
    new_map: HashMap<String, Cookie>,
    removed_cookies: HashSet<String>,
}

impl CookieJar {
    pub fn new() -> CookieJar {
        CookieJar {
            orig_map: HashMap::new(),
            new_map: HashMap::new(),
            removed_cookies: HashSet::new(),
        }
    }

    pub fn add_original(&mut self, cookie: Cookie) {
        self.orig_map.insert(cookie.name.clone(), cookie);
    }

    pub fn add(&mut self, cookie: Cookie) {
        let name = cookie.name.clone();
        self.removed_cookies.remove(&name);
        self.new_map.insert(name, cookie);
    }

    pub fn remove(&mut self, cookie: &str) {
        let cookie = cookie.to_string();
        self.new_map.remove(&cookie);
        self.removed_cookies.insert(cookie);
    }

    pub fn find<'a>(&'a self, name: &str) -> Option<&'a Cookie> {
        let name = name.to_string();
        if self.removed_cookies.contains(&name) {
            None
        } else {
            self.new_map.find(&name).or_else(|| self.orig_map.find(&name))
        }
    }

    pub fn delta(&self) -> Vec<String> {
        let mut ret = Vec::new();
        for cookie in self.removed_cookies.iter() {
            let mut c = Cookie::new(cookie.clone(), String::new());
            c.max_age = Some(0);
            let mut now = time::now();
            now.tm_year -= 1;
            c.expires = Some(now);
            ret.push(c.to_str());
        }
        for (_, cookie) in self.new_map.iter() {
            ret.push(cookie.to_str());
        }
        return ret;
    }
}

#[cfg(test)]
mod test {
    use {Cookie, CookieJar};

    #[test]
    fn simple() {
        let mut c = CookieJar::new();

        c.add(Cookie::new("test".to_string(), "".to_string()));
        c.add(Cookie::new("test2".to_string(), "".to_string()));
        c.remove("test");

        assert!(c.find("test").is_none());
        assert!(c.find("test2").is_some());
    }
}
