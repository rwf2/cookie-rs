# Version 0.13

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
