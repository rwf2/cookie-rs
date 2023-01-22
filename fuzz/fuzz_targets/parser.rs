#![no_main]

extern crate cookie;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let _ = cookie::Cookie::parse(data);
});
