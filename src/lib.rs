//! Two-step verification of HOTP/TOTP.
//!
//! # Examples
//!
//!
//! ## HOTP example
//! ```
//! extern crate otpauth;
//!
//! fn main() {
//!     let auth = otpauth::OtpAuth::new("python");
//!     let code = auth.hotp(4);
//!     assert_eq!(true, auth.valid_hotp(code, 0, 100));
//! }
//! ```
//!
//! ## TOTP example
//!
//! ```
//! extern crate otpauth;
//! extern crate time;
//!
//! fn main() {
//!     let auth = otpauth::OtpAuth::new("python");
//!     let timestamp1 = time::now().to_timespec().sec as usize;
//!     let code = auth.totp(30usize, timestamp1);
//!     let timestamp2 = time::now().to_timespec().sec as usize;
//!     assert_eq!(true, auth.valid_totp(code, 30usize, timestamp2));
//! }
//! ```
//!
extern crate crypto;
extern crate byteorder;

use std::io::Cursor;

use crypto::digest::Digest;
use crypto::mac::Mac;
use crypto::hmac::Hmac;
use crypto::sha1::Sha1;
use byteorder::{BigEndian, WriteBytesExt, ReadBytesExt};

pub struct OtpAuth {
    /// A secret token for the authentication
    pub secret: String,
}

impl OtpAuth {
    /// Constructs a new `OtpAuth`
    pub fn new(secret: &str) -> OtpAuth {
        OtpAuth {
            secret: secret.to_string(),
        }
    }

    /// Generate a TOTP code.
    ///
    /// A TOTP code is an extension of HOTP algorithm.
    ///
    /// ``period``: A period that a TOTP code is valid in seconds
    ///
    /// ``timestamp``: Create TOTP at this given timestamp
    pub fn totp(&self, period: usize, timestamp: usize) -> u32 {
        let counter = timestamp / period;
        self.hotp(counter)
    }

    /// Generate a HOTP code.
    ///
    /// ``counter``: HOTP is a counter based algorithm.
    pub fn hotp(&self, counter: usize) -> u32 {
        // Init Hmac
        let key = self.secret.clone().into_bytes();
        let mut hmac = Hmac::new(Sha1::new(), &key[..]);
        // Calc msg
        let mut wtr = vec![];
        // supress warning about unused_must_use
        let _ = wtr.write_u64::<BigEndian>(counter as u64);
        hmac.input(&wtr[..]);
        // Get digest
        let result = hmac.result();
        let digest = result.code();
        let ob = digest[19];
        let pos: usize = (ob & 15) as usize;
        let mut rdr = Cursor::new(digest[pos..pos+4].to_vec());
        let base = rdr.read_u32::<BigEndian>().unwrap() & 0x7fffffff;
        base % 1000000
    }

    /// Valid a TOTP code.
    ///
    /// ``code``: A number that is less than 6 characters.
    ///
    /// ``period``: A period that a TOTP code is valid in seconds
    ///
    /// ``timestamp``: Validate TOTP at this given timestamp
    pub fn valid_totp(&self, code: u32, period: usize, timestamp: usize) -> bool {
        let code_str = code.to_string();
        let code_bytes = code_str.as_bytes();
        if code_bytes.len() > 6 {
            return false;
        }
        let valid_code = self.totp(period, timestamp).to_string();
        let valid_bytes = valid_code.as_bytes();
        if code_bytes.len() != valid_code.len() {
            return false;
        }
        let mut rv = 0;
        for (a, b) in code_bytes.iter().zip(valid_bytes.iter()) {
            rv |= a ^ b;
        }
        rv == 0
    }

    /// Valid a HOTP code.
    ///
    /// ``code``: A number that is less than 6 characters.
    ///
    /// ``last``: Guess HOTP code from last + 1 range.
    ///
    /// ``trials``: Guest HOTP code end at last + trials + 1.
    pub fn valid_hotp(&self, code: u32, last: usize, trials: usize) -> bool {
        let code_str = code.to_string();
        let code_bytes = code_str.as_bytes();
        if code_bytes.len() > 6 {
            return false;
        }
        for i in last+1..last+trials+1 {
            let valid_code = self.hotp(i).to_string();
            let valid_bytes = valid_code.as_bytes();
            if code_bytes.len() != valid_code.len() {
                continue;
            }
            let mut rv = 0;
            for (a, b) in code_bytes.iter().zip(valid_bytes.iter()) {
                rv |= a ^ b;
            }
            if rv == 0 {
                return true;        
            }
        }
        false
    }
}
