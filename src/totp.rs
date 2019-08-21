//! Two-step verification of TOTP algorithm
//!
//! # Example
//!
//! ```
//! use std::time::{SystemTime, UNIX_EPOCH};
//!
//!
//! fn main() {
//!     let auth = otpauth::TOTP::new("python");
//!     let timestamp1 = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
//!     let code = auth.generate(30, timestamp1);
//!     let timestamp2 = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
//!     assert!(auth.verify(code, 30, timestamp2));
//! }
//! ```

use super::hotp::HOTP;


/// Two-step verification of TOTP algorithm
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct TOTP {
    hotp: HOTP,
}

impl TOTP {
    /// Constructs a new `TOTP`
    pub fn new<S: Into<String>>(secret: S) -> TOTP {
        TOTP { hotp: HOTP::new(secret) }
    }

    /// Constructs a new `TOTP` with base-32 encoded secret bytes
    pub fn from_base32<S: Into<String>>(secret: S) -> Option<TOTP> {
        HOTP::from_base32(secret)
            .map(|hotp| TOTP { hotp })
    }

    /// Constructs a new `TOTP` with secret bytes
    pub fn from_bytes(bytes: &[u8]) -> TOTP {
        TOTP { hotp: HOTP::from_bytes(bytes) }
    }

    /// Generate a TOTP code.
    ///
    /// A TOTP code is an extension of HOTP algorithm.
    ///
    /// ``period``: A period that a TOTP code is valid in seconds
    ///
    /// ``timestamp``: Create TOTP at this given timestamp
    pub fn generate(&self, period: u64, timestamp: u64) -> u32 {
        let counter = timestamp / period;
        self.hotp.generate(counter)
    }

    /// Valid a TOTP code.
    ///
    /// ``code``: A number that is less than 6 characters.
    ///
    /// ``period``: A period that a TOTP code is valid in seconds
    ///
    /// ``timestamp``: Validate TOTP at this given timestamp
    pub fn verify(&self, code: u32, period: u64, timestamp: u64) -> bool {
        let code_str = code.to_string();
        let code_bytes = code_str.as_bytes();
        if code_bytes.len() > 6 {
            return false;
        }
        let valid_code = self.generate(period, timestamp).to_string();
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

    /// Return the secret bytes in base32 encoding.
    pub fn base32_secret(&self) -> String {
        self.hotp.base32_secret()
    }

    /// Generate the otpauth protocal string.
    ///
    /// ``label``: Label of the identifier.
    ///
    /// ``issuer``: The company, the organization or something else.
    pub fn to_uri<S: AsRef<str>>(&self, label: S, issuer: S) -> String {
        format!("otpauth://totp/{}?secret={}&issuer={}",
                label.as_ref(),
                self.hotp.base32_secret(),
                issuer.as_ref())
    }
}
