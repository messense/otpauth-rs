# otpauth-rs

[![CI](https://github.com/messense/otpauth-rs/actions/workflows/CI.yml/badge.svg)](https://github.com/messense/otpauth-rs/actions/workflows/CI.yml)
[![Crates.io](https://img.shields.io/crates/v/otpauth.svg)](https://crates.io/crates/otpauth)

Two-step verification of HOTP/TOTP for Rust.

## Installation

Add it to your ``Cargo.toml``:

```toml
[dependencies]
otpauth = "0.5"
```

## Examples

### HOTP example

```rust
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
