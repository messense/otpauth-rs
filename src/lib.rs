//! Two-step verification of HOTP/TOTP.
//!
//! # Installation
//!
//! Add it to your ``Cargo.toml``:
//!
//! ```toml
//! [dependencies]
//! otpauth = "0.2"
//! ```
//!
//! Add ``extern crate otpauth`` to your crate root and your're good to go!
//!
//! # Examples
//!
//! ## HOTP example
//!
//! ```rust
//! extern crate otpauth;
//!
//! use otpauth::HOTP;
//!
//! fn main() {
//!     let auth = HOTP::new("python");
//!     let code = auth.generate(4);
//!     assert_eq!(true, auth.verify(code, 0, 100));
//! }
//! ```
//!
//! ## TOTP example
//!
//! ```rust
//! extern crate otpauth;
//! extern crate time;
//!
//! use otpauth::TOTP;
//!
//! fn main() {
//!     let auth = TOTP::new("python");
//!     let timestamp1 = time::now().to_timespec().sec as usize;
//!     let code = auth.generate(30, timestamp1);
//!     let timestamp2 = time::now().to_timespec().sec as usize;
//!     assert_eq!(true, auth.verify(code, 30, timestamp2));
//! }
//! ```

#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", deny(clippy))]
#![cfg_attr(feature="clippy", warn(cyclomatic_complexity))]

extern crate crypto;
extern crate byteorder;
extern crate base32;

pub mod hotp;
pub mod totp;

pub use hotp::HOTP;
pub use totp::TOTP;
