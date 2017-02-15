#[cfg(test)]
macro_rules! assert_simple_behaviour {
    ($clear:expr, $secure:expr) => ({
        assert_eq!($clear.iter().count(), 0);

        $secure.add(Cookie::new("name", "val"));
        assert_eq!($clear.iter().count(), 1);
        assert_eq!($secure.find("name").unwrap().value(), "val");
        assert_ne!($clear.find("name").unwrap().value(), "val");

        $secure.add(Cookie::new("another", "two"));
        assert_eq!($clear.iter().count(), 2);

        $clear.remove(Cookie::named("another"));
        assert_eq!($clear.iter().count(), 1);

        $secure.remove(Cookie::named("name"));
        assert_eq!($clear.iter().count(), 0);
    })
}

#[cfg(test)]
macro_rules! assert_secure_behaviour {
    ($clear:expr, $secure:expr) => ({
        $secure.add(Cookie::new("secure", "secure"));
        assert!($clear.find("secure").unwrap().value() != "secure");
        assert!($secure.find("secure").unwrap().value() == "secure");

        let mut cookie = $clear.find("secure").unwrap().clone();
        let new_val = format!("{}l", cookie.value());
        cookie.set_value(new_val);
        $clear.add(cookie);
        assert!($secure.find("secure").is_none());

        let mut cookie = $clear.find("secure").unwrap().clone();
        cookie.set_value("foobar");
        $clear.add(cookie);
        assert!($secure.find("secure").is_none());
    })
}

