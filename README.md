# otpauth-rs

[![Build Status](https://travis-ci.org/messense/otpauth-rs.svg)](https://travis-ci.org/messense/otpauth-rs)
[![Build status](https://ci.appveyor.com/api/projects/status/2kg380h0l0c4li9o/branch/master?svg=true)](https://ci.appveyor.com/project/messense/otpauth-rs/branch/master)
[![Coverage Status](https://coveralls.io/repos/messense/otpauth-rs/badge.svg)](https://coveralls.io/r/messense/otpauth-rs)
[![Crates.io](https://img.shields.io/crates/v/otpauth.svg)](https://crates.io/crates/otpauth)

Two-step verification of HOTP/TOTP for Rust.

## Installation

Add it to your ``Cargo.toml``:

```toml
[dependencies]
otpauth = "0.3"
```

## Examples

### HOTP example

```rust
extern crate otpauth;

use otpauth::HOTP;

fn main() {
    let auth = HOTP::new("python");
    let code = auth.generate(4);
    assert_eq!(true, auth.verify(code, 0, 100));
}
```

### TOTP example

```rust
use std::time::{SystemTime, UNIX_EPOCH};

use otpauth::TOTP;


fn main() {
    let auth = TOTP::new("python");
    let timestamp1 = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let code = auth.generate(30, timestamp1);
    let timestamp2 = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    assert_eq!(true, auth.verify(code, 30, timestamp2));
}
```


## License

This work is released under the MIT license. A copy of the license is provided in the [LICENSE](./LICENSE) file.
