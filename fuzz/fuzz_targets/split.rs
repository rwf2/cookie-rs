#![no_main]

extern crate cookie;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    // Use `count()` to exhaust the iterator.
    let _ = cookie::Cookie::split_parse(data).count();
});
