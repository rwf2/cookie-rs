# Cookie

[![CI Status](https://github.com/rwf2/cookie-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/rwf2/cookie-rs/actions)
[![Current crates.io Version](https://img.shields.io/crates/v/cookie.svg)](https://crates.io/crates/cookie)
[![Documentation](https://docs.rs/cookie/badge.svg)](https://docs.rs/cookie)

A Rust library for parsing HTTP cookies and managing cookie jars.

# Usage

Add the following to your `Cargo.toml`:

```toml
[dependencies]
cookie = "0.19"
```

See the [documentation](https://docs.rs/cookie) for detailed usage information.

# Minimum Supported Rust Version (MSRV)

| Version Range                    | MSRV         |
|----------------------------------|--------------|
| `cookie` `==` `0.19`             | `rustc 1.87` |
| `cookie` `==` `0.18`             | `rustc 1.56` |
| `0.16` `<=` `cookie` `<=` `0.17` | `rustc 1.53` |
| `cookie` `<=` `0.15`             | `rustc 1.41` |

The latest versions of the dependencies of the `private`, `signed`, and
`key-expansion` features may require a newer `rustc`. To build with the MSRV,
use Cargo's MSRV-aware resolver, which selects compatible versions:

```toml
[package]
rust-version = "1.87"
resolver = "3"
```

# License

This project is licensed under your option of either of the following:

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   https://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   https://opensource.org/license/mit)

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in `cookie` by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
