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
//! use std::time::{SystemTime, UNIX_EPOCH};
//!
//! use otpauth::TOTP;
//!
//!
//! fn main() {
//!     let auth = TOTP::new("python");
//!     let timestamp1 = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as usize;
//!     let code = auth.generate(30, timestamp1);
//!     let timestamp2 = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as usize;
//!     assert_eq!(true, auth.verify(code, 30, timestamp2));
//! }
//! ```

pub mod hotp;
pub mod totp;

pub use hotp::HOTP;
pub use totp::TOTP;
