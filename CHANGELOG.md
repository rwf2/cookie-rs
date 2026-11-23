# Version 0.19

## Version 0.19.0-rc.0 (Nov 23, 2026)

### Breaking Changes

  * The MSRV is now `1.87`.

    The latest versions of the dependencies of the `private`, `signed`, and
    `key-expansion` features may require a newer `rustc`. To build with the
    MSRV, use Cargo's MSRV-aware resolver: set `rust-version = "1.87"` and
    `resolver = "3"` in your manifest.

  * The crate now uses the Rust 2024 edition.

  * Optional dependency names are no longer exposed as Cargo features.

    The manifest now uses `dep:` syntax for optional dependencies. Enable
    `percent-encode`, `private`, `signed`, `key-expansion`, or `secure`
    instead of dependency names.

  * `Cookie::domain_raw()` now preserves a leading `.` from parsed `Domain`
    attributes. For the previous behavior, use:

    ```rust
    cookie.domain_raw().map(|d| d.strip_prefix('.').unwrap_or(d))
    ```

  * `Cookie` and `CookieBuilder` no longer implement `Display`.

    The previous implementation wrote the cookie's name and value without any
    encoding or escaping, allowing a name or value containing a `;` to inject
    cookie attributes. Writing a cookie now requires choosing how the name and
    value are written:

      * `cookie.encoded()` percent-encodes the name and value. This is the safe
        choice. Read the cookie back with `Cookie::parse_encoded()` or
        `Cookie::split_parse_encoded()`.
      * `cookie.unescaped()` writes the name and value as-is. This is the
        previous behavior of `cookie.to_string()`. Read the cookie back with
        `Cookie::parse()` or `Cookie::split_parse()`.

    To write a `CookieBuilder`, use `builder.inner().encoded()` or
    `builder.inner().unescaped()`.

    The two cannot be mixed. In particular, a signed or private cookie written
    with `encoded()` and read without decoding can fail to verify or decrypt.
    This includes cookies read by previous versions of this library: when
    upgrading servers one at a time, write cookies with `unescaped()` until
    every server reads cookies with `parse_encoded()`.

    Similarly, a cookie written with `unescaped()` and read with
    `parse_encoded()` has any `%` followed by two hexadecimal digits in its
    name or value, such as `%25`, decoded. A signed cookie read in this manner
    can fail to verify.

  * `Cookie::stripped()` and `Display::encoded()` were removed.

    Use `cookie.encoded().stripped()` or `cookie.unescaped().stripped()`.
    `cookie.stripped().encoded()` becomes `cookie.encoded().stripped()`.

  * `Path` and `Domain` values are truncated at the first `;` or control
    character when set.

    This applies to `Cookie::set_path()`, `Cookie::set_domain()`,
    `CookieBuilder::path()`, and `CookieBuilder::domain()`. Neither attribute
    can contain these characters, and a value containing a `;` previously
    injected cookie attributes when written.

  * The `percent-encode` feature is now enabled by default.

  * A signed cookie's value is now bound to the cookie's name.

    Previously, only a cookie's value was signed. As such, a value signed for
    one name verified under any other name. The cookie's name is now signed as
    well: a value signed for one name fails to verify under any other name,
    as is the case for private cookies.

    Signed cookies created by previous versions fail to verify, and signed
    cookies created by this version fail to verify in previous versions.
    Private cookies are unaffected.

    The name includes any cookie prefix. As such, a cookie signed as
    `__Host-name` and retrieved via `jar.prefixed(Host).get("name")`, which
    removes the prefix, no longer verifies via `SignedJar::verify()`. Use
    `jar.signed(&key).get("__Host-name")` instead.

  * The `time` dependency was removed in favor of `std::time`.

    `cookie::time` is no longer exported. Methods that previously accepted or
    returned a `time::Duration` now use `std::time::Duration`, and methods that
    previously accepted or returned a `time::OffsetDateTime` now use
    `std::time::SystemTime`:

      * `Cookie::max_age()`, `Cookie::set_max_age()`, `CookieBuilder::max_age()`
      * `Cookie::expires_datetime()`, `Cookie::set_expires()`,
        `CookieBuilder::expires()`
      * `Expiration::DateTime`, `Expiration::datetime()`, `Expiration::map()`

    Values from `time` convert to and from the `std` types:

    ```rust
    use std::time::{Duration, SystemTime};

    cookie.set_expires(SystemTime::from(offset_date_time));
    cookie.set_max_age(Duration::try_from(time_duration).unwrap_or_default());
    ```

    Here, `Duration` is `std::time::Duration`, not `time::Duration`. A
    `Max-Age` can no longer be negative. The conversion above sets a negative
    `Max-Age` to `0`, which has the same effect: the cookie expires immediately.
    The conversion to a `SystemTime` panics if the platform cannot represent
    the date, e.g, a date before the Unix epoch on `wasm32-unknown-unknown`.

    The crate no longer enables the `formatting`, `parsing`, and `macros`
    features of `time`. If you depend on `time` and use these features, enable
    them in your manifest. Similarly, libraries that re-export this crate no
    longer export `time` via `cookie::time`.

    `Cookie::make_permanent()` and `CookieBuilder::permanent()` now read the
    time via `std::time::SystemTime::now()`, which panics on platforms without
    a system clock, such as `wasm32-unknown-unknown`. Enabling the
    `wasm-bindgen` feature of `time` no longer has any effect.

  * `Expiration` no longer implements `From<T>` for every
    `T: Into<Option<OffsetDateTime>>`.

    The blanket implementation was replaced by `From<SystemTime>` and
    `From<Option<SystemTime>>`. The blanket implementation caused a build
    failure when an upstream crate added an unrelated `From` implementation.

  * `Expires` is now parsed using the algorithm in RFC 6265 §5.1.1.

    The algorithm is more lenient than the previous fixed set of formats. In
    particular, the weekday and the time zone, if any, are ignored. Dates are
    always read as UTC.

    As required by the RFC, an `Expires` with a year before `1601` or a year of
    a single digit is now ignored. On platforms that cannot represent dates
    before the Unix epoch, such as `wasm32-unknown-unknown`, an `Expires`
    before the Unix epoch is read as the Unix epoch.

  * An `Expires` before the Unix epoch is written as the Unix epoch.

    Not every client can read an earlier date: some treat a cookie with such a
    date as a session cookie instead of as an expired cookie.

  * Cookies containing invalid control characters are no longer parsed.

    Parsing a cookie containing a control character other than a horizontal
    tab now fails with the new `ParseError::InvalidControl`, as required by RFC
    6265bis. This includes a trailing `\r` or `\n`: remove any line ending
    before parsing.

  * Only spaces and horizontal tabs are trimmed when parsing.

    As specified by RFC 6265, other Unicode whitespace surrounding a name,
    value, or attribute is no longer removed. In particular,
    `Cookie::split_parse()` no longer skips a segment that only contains such
    whitespace: it yields a `ParseError::MissingPair`.

  * An empty `Max-Age` is now ignored when parsing.

    Previously, `Max-Age=` was parsed as the maximum `Max-Age` and `Max-Age=-`
    as a `Max-Age` of `0`.

  * `Cookie` equality now compares the `SameSite` attribute and compares
    `Path` case-sensitively.

    Previously, two cookies that only differed in `SameSite`, or in the case
    of their `Path`, i.e, `/foo` and `/Foo`, were equal. `Domain` continues to
    be compared case-insensitively.

  * `Cookie::parse_encoded()` and `Cookie::split_parse_encoded()` no longer
    parse a name that only has a cookie prefix after decoding.

    Browsers do not decode a cookie's name and thus only enforce a cookie
    prefix, i.e, `__Host-`, if the name has the prefix before it is decoded.
    Parsing a name such as `%5F%5FHost-name` now fails with the new
    `ParseError::EncodedPrefix`. Previously, such a cookie was returned by
    `PrefixedJar::get()`. This applies to the `__Host-`, `__Secure-`,
    `__Http-`, and `__Host-Http-` prefixes.

  * Removal cookies now expire at the Unix epoch.

    `Cookie::make_removal()`, `CookieBuilder::removal()`, and
    `CookieJar::remove()` set `Expires` to January 1, 1970 instead of one year
    before the current time. Removing a cookie no longer reads the system clock.

### New Features

  * Added `Cookie::unescaped()`.

    The returned `Display` writes the cookie's name and value without any
    encoding or escaping. This is dangerous if the name or value is derived
    from untrusted input! Prefer `Cookie::encoded()`.

  * Added `Cookie::domain_verbatim()`.

    This accessor returns the current `Domain` attribute value without removing
    a leading `.`.

### General Changes and Fixes

  * The manifest now declares `rust-version = "1.87"`.

  * Private cookies are now encrypted with nonces generated by the operating
    system.

    Previously, a process that forked after encrypting a private cookie could
    reuse nonces in the parent and child processes, which allows forging
    private cookies. Version `0.18.3` contains the same fix.

  * A `Max-Age` larger than `i64::MAX` is written as `i64::MAX`.

    Not every client can read a larger `Max-Age`. As in previous versions, a
    larger `Max-Age` is parsed as `i64::MAX`.

  * The documentation for `SignedJar::add_original()` and
    `PrivateJar::add_original()` no longer suggests using them to add cookies
    received from a client.

    These methods sign and encrypt the cookie they are given, respectively.
    Use `CookieJar::add_original()` to add cookies received from a client.

  * The documentation now notes that a signed or private cookie's value is
    bound to the cookie's name including any prefix, that a signed or private
    cookie's attributes are not authenticated, and that a `Key` should not be
    used to encrypt more than 2^32 private cookies.

  * The `FromStr` implementation for `Cookie` is now documented.

    Like `Cookie::parse()`, it does not percent-decode.

  * On `wasm32-unknown-unknown`, the `private` and `signed` features now
    require enabling the `wasm_js` feature of `getrandom` `0.4` in place of
    the `js` feature of `getrandom` `0.2`.

  * Dependencies were updated:
    - `aes-gcm` to `0.11`
    - `base64` to `0.23`
    - `hkdf` to `0.13`
    - `hmac` to `0.13`
    - `rand` to `0.10.1`
    - `sha2` to `0.11`

    The minimum versions of `ctutils` and `cmov`, indirect dependencies, are
    set to exclude versions with known security issues.

  * Published crates now include only the files needed to build the crate.

    Development scripts and the fuzzing harness are excluded from packaging.

  * The docs.rs and nightly-doc configuration now uses manifest metadata
    instead of a build script.

  * Various documentation URLs and doctests were clarified and updated.

# Version 0.18

## Version 0.18.3 (Nov 23, 2026)

### Changes and Fixes

  * Private cookies are now encrypted with nonces generated by the operating
    system.

## Version 0.18.2 (Aug 8, 2026)

### Changes and Fixes

  * Stopped using internal `time` APIs.

  * `Expires` parsing is more RFC 6265-compliant.
    - Weekday prefixes are now optional.
    - Two-digit years follow the RFC boundary: `69` is `2069` (not `1969`).

  * The manifest now declares `rust-version = "1.56"`.

## Version 0.18.1 (Mar 25, 2024)

### New Features

  * Added support for the draft `Partitioned` attribute.

    The new `CookieBuilder::partition()`, `Cookie::partitioned()`, and
    `Cookie::set_partitioned()` methods allow enabling and/or disabling the
    attribute. Additionally, the attribute is recognized during parsing.

  * Added `CookieBuilder::removal()`, counterpart to `Cookie::make_removal()`.

## Version 0.18.0 (Oct 9, 2023)

### Breaking Changes

  * The MSRV is now 1.56.

  * `Cookie::value()` no longer trims surrounding double quotes. (89eddd)

    Use `Cookie::value_trimmed()` for the previous behavior.

  * Many methods now expect a `T: Into<Cookie>` in place of `Cookie`. (49ff7b)

    Functions and methods that previously accepted a `Cookie` now accept any `T:
    Into<Cookie>`. This particularly affects the `CookieJar` API, which now allows
    simpler addition and removal of cookies:

      * `jar.add(("foo", "bar"));`
      * `jar.add(Cookie::build(("foo", "bar")).path("/"));`
      * `jar.remove("foo");`
      * `jar.remove(Cookie::build("foo").path("/"));`

  * `CookieJar::force_remove()` now expects a `T: AsRef<str>` in place of
    `&Cookie`.

    Force-removal never requires more information than a cookie's name. The API
    has been simplified to reflect this.

  * `CookieBuilder::finish()` was deprecated in favor of
    `CookieBuilder::build()`.

    This largely serves as a compile-time notice that calling `finish()` or
    `build()` is largely unnecessary given that `CookieBuilder` implements
    `Into<Cookie>`.

  * `Cookie::named()` was deprecated in favor of using `Cookie::build()` or
    `Cookie::from()`.

      * `Cookie::named("foo")` is equivalent to `Cookie::from("foo")`.
      * `Cookie::build("foo")` begins building a cookie equivalent to
        `Cookie::named("foo")`.

### New Features

  * Added `Cookie::value_trimmed()` and `Cookie::name_value_trimmed()`.

    These versions of `Cookie::value()` and `Cookie::name_value()`,
    respectively, trim a matching pair of surrounding double quotes from the
    cookie's value, if any are present.

  * String-like types, tuples of string-like types, and `CookieBuilder`
    implement `Into<Cookie>`.

    Implementations of `Into<Cookie>` for string-like types (`&str`, `String`,
    `Cow<str>`), tuples of string-like types `(name: string, value: string)`,
    and `CookieBuilder` were added. The former implementations create a cookie
    with a name corresponding to the string and an empty value. The tuple
    implementation creates a cookie with the given name and value strings. The
    `CookieBuilder` implementation returns the built cookie.

  * `Key` implements `Debug`.

    To not leak sensitive information, the representation is simply `"Key"`.

  * `CookieBuilder` implements `Borrow{Mut}<Cookie>`, `As{Ref,Mut}<Cookie>`,
    `Display`.

  * Added `CookieBuilder::inner{_mut}()` to (mutably) borrow cookies being
    built.

  * Added `PrefixedJar` and `CookieJar::prefixed{_mut}()`, which implement the
    cookie prefixes HTTP draft.

## Version 0.18.0.rc.0 (Sep 27, 2023)

See the entry above for 0.18.0.

# Version 0.17

## Version 0.17.0 (Jan 22, 2022)

### Breaking Changes

  * Cookie parsing no longer removes a `.` `Domain` prefix. `Cookie::domain()`
    now removes a `.` prefix before returning.

    As these changes are inverses, they are not likely observable. The change
    only affects manually set `domain` values via the `.domain()` builder
    method, the `set_domain()` setter method, or similar, which will now have a
    prefix of `.` removed when returned by `Cookie::domain()`. This results in
    more consistent treatment of `Domain` values.

### New Features

  * Added `Cookie::split_parse()` and `Cookie::split_parse_encoded()` methods.

    The methods split a `;`-joined cookie string and parse/decode the split
    values. They return a newly introduced iterator value of type `SplitCookies`
    over the parse results.

### General Changes and Fixes

  * Parsing fuzzers were introduced and run for 48 CPU hours without failure.
  * `base64` was updated to `0.21`.

# Version 0.16

## Version 0.16.2 (Dec 16, 2022)

### General Changes

  * `base64` was updated to `0.20`.

## Version 0.16.1 (Sep 25, 2022)

### Changes and Fixes

  * The `,`, `(`, and `)` are percent-encoded/decoded when encoding is used.
  * The `aes-gcm` dependency was updated to 0.10.

## Version 0.16.0 (Dec 28, 2021)

### Breaking Changes

  * The MSRV is now `1.53`, up from `1.41` in `0.15`.
  * `time` has been updated to `0.3` and is reexported from the crate root.

### General Changes

  * `rust-crypto` dependencies were updated to their latest versions.

# Version 0.15

## Version 0.15.1 (Jul 14, 2021)

### Changes and Fixes

  * A panic that could result from non-char boundary indexing was fixed.
  * Stale doc references to version `0.14` were updated.

## Version 0.15.0 (Feb 25, 2021)

### Breaking Changes

  * `Cookie::force_remove()` takes `&Cookie` instead of `Cookie`.
  * Child jar methods split into immutable and mutable versions
    (`Cookie::{private{_mut}, signed{_mut}}`).
  * `Cookie::encoded()` returns a new `Display` struct.
  * Dates with year `<= 99` are handled like Chrome: range `0..=68` maps to
    `2000..=2068`, `69..=99` to `1969..=1999`.
  * `Cookie::{set_}expires()` operates on a new `Expiration` enum.

### New Features

  * Added `Cookie::make_removal()` to manually create expired cookies.
  * Added `Cookie::stripped()` display variant to print only the `name` and
    `value` of a cookie.
  * `Key` implements a constant-time `PartialEq`.
  * Added `Key::master()` to retrieve the full 512-bit master key.
  * Added `PrivateJar::decrypt()` to manually decrypt an encrypted `Cookie`.
  * Added `SignedJar::verify()` to manually verify a signed `Cookie`.
  * `Cookie::expires()` returns an `Option<Expiration>` to allow distinguishing
    between unset and `None` expirations.
  * Added `Cookie::expires_datetime()` to retrieve the expiration as an
    `OffsetDateTime`.
  * Added `Cookie::unset_expires()` to unset expirations.

### General Changes and Fixes

  * MSRV is 1.41.

# Version 0.14

## Version 0.14.3 (Nov 5, 2020)

### Changes and Fixes

  * `rust-crypto` dependencies were updated to their latest versions.

## Version 0.14.2 (Jul 22, 2020)

### Changes and Fixes

  * Documentation now builds on the stable channel.
  * `rust-crypto` dependencies were updated to their latest versions.
  * Fixed 'interator' -> 'iterator' documentation typo.

## Version 0.14.1 (Jun 5, 2020)

### Changes and Fixes

  * Updated `base64` dependency to 0.12.
  * Updated minimum `time` dependency to correct version: 0.2.11.
  * Added `readme` key to `Cargo.toml`, updated `license` field.

## Version 0.14.0 (May 29, 2020)

### Breaking Changes

  * The `Key::from_master()` method was deprecated in favor of the more aptly
    named `Key::derive_from()`.
  * The deprecated `CookieJar::clear()` method was removed.

### New Features

  * Added `Key::from()` to create a `Key` structure from a full-length key.
  * Signed and private cookie jars can be individually enabled via the new
    `signed` and `private` features, respectively.
  * Key derivation via key expansion can be individually enabled via the new
    `key-expansion` feature.

### General Changes and Fixes

  * `ring` is no longer a dependency: `RustCrypto`-based cryptography is used in
    lieu of `ring`. Prior to their inclusion here, the `hmac` and `hkdf` crates
    were audited.
  * Quotes, if present, are stripped from cookie values when parsing.

# Version 0.13

## Version 0.13.3 (Feb 3, 2020)

### Changes

  * The `time` dependency was unpinned from `0.2.4`, allowing any `0.2.x`
    version of `time` where `x >= 6`.

## Version 0.13.2 (Jan 28, 2020)

### Changes

  * The `time` dependency was pinned to `0.2.4` due to upstream breaking changes
    in `0.2.5`.

## Version 0.13.1 (Jan 23, 2020)

### New Features

  * Added the `CookieJar::reset_delta()` method, which reverts all _delta_
    changes to a `CookieJar`.

## Version 0.13.0 (Jan 21, 2020)

### Breaking Changes

  * `time` was updated from 0.1 to 0.2.
  * `ring` was updated from 0.14 to 0.16.
  * `SameSite::None` now writes `SameSite=None` to correspond with updated
    `SameSite` draft. `SameSite` can be unset by passing `None` to
    `Cookie::set_same_site()`.
  * `CookieBuilder` gained a lifetime: `CookieBuilder<'c>`.

### General Changes and Fixes

  * Added a CHANGELOG.
  * `expires`, `max_age`, `path`, and `domain` can be unset by passing `None` to
    the respective `Cookie::set_{field}()` method.
  * The "Expires" field is limited to a date-time of Dec 31, 9999, 23:59:59.
  * The `%` character is now properly encoded and decoded.
  * Constructor methods on `CookieBuilder` allow non-static lifetimes.
