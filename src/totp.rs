//! Two-step verification of TOTP algorithm
//!
//! # Example
//!
//! ```
//! extern crate otpauth;
//! extern crate time;
//!
//! fn main() {
//!     let auth = otpauth::TOTP::new("python");
//!     let timestamp1 = time::now().to_timespec().sec as usize;
//!     let code = auth.generate(30, timestamp1);
//!     let timestamp2 = time::now().to_timespec().sec as usize;
//!     assert!(auth.verify(code, 30, timestamp2));
//! }
//! ```
//!
use super::hotp;


pub struct TOTP {
    /// A secret token for the authentication
    pub secret: String,
}

impl TOTP {
    /// Constructs a new `TOTP`
    pub fn new(secret: &str) -> TOTP {
        TOTP {
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
    pub fn generate(&self, period: usize, timestamp: usize) -> u32 {
        let counter = timestamp / period;
        let hotp_auth = hotp::HOTP::new(&self.secret[..]);
        hotp_auth.generate(counter)
    }

    /// Valid a TOTP code.
    ///
    /// ``code``: A number that is less than 6 characters.
    ///
    /// ``period``: A period that a TOTP code is valid in seconds
    ///
    /// ``timestamp``: Validate TOTP at this given timestamp
    pub fn verify(&self, code: u32, period: usize, timestamp: usize) -> bool {
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

    /// Generate the otpauth protocal string.
    ///
    /// ``label``: Label of the identifier.
    ///
    /// ``issuer``: The company, the organization or something else.
    pub fn to_uri(&self, label: &str, issuer: &str) -> String {
        use base32::encode;
        use base32::Alphabet::RFC4648;

        let encoded_secret = encode(RFC4648 { padding: false }, self.secret.as_bytes());
        format!("otpauth://totp/{}?secret={}&issuer={}", label, encoded_secret, issuer)
    }
}
