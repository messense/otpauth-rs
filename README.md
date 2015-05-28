# otpauth-rs

[![Build Status](https://travis-ci.org/messense/otpauth-rs.svg)](https://travis-ci.org/messense/otpauth-rs)
[![Coverage Status](https://coveralls.io/repos/messense/otpauth-rs/badge.svg)](https://coveralls.io/r/messense/otpauth-rs)
[![Crates.io](https://img.shields.io/crates/v/opencc.svg)](https://crates.io/crates/opencc)

Two-step verification of HOTP/TOTP for Rust.

## Installation

Add it to your ``Cargo.toml``:

```toml
[dependencies]
otpauth = "*"
```

Add ``extern crate otpauth`` to your crate root and your're good to go!

## Examples

### HOTP example

```rust
extern crate otpauth;

use otpauth::OtpAuth;

fn main() {
    let auth = OtpAuth::new("python");
    let code = auth.hotp(4);
    assert_eq!(true, auth.valid_hotp(code, 0, 100));
}
```

### TOTP example

```rust
extern crate otpauth;
extern crate time;

use otpauth::OtpAuth;

fn main() {
    let auth = OtpAuth::new("python");
    let timestamp1 = time::now().to_timespec().sec as usize;
    let code = auth.totp(30usize, timestamp1);
    let timestamp2 = time::now().to_timespec().sec as usize;
    assert_eq!(true, auth.valid_totp(code, 30usize, timestamp2));
}
```


## License

This work is released under the MIT license. A copy of the license is provided in the [LICENSE](./LICENSE) file.
