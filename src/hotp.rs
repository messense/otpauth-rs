//! Two-step verfication of HOTP algorithm.
//!
//! # Example
//!
//! ```
//! extern crate otpauth;
//!
//! fn main() {
//!     let auth = otpauth::HOTP::new("python");
//!     let code = auth.generate(4);
//!     assert!(auth.verify(code, 0, 100));
//! }
//! ```

use std::io::Cursor;

use byteorder::{BigEndian, ReadBytesExt};
use base32::Alphabet::RFC4648;
use ring::hmac;


/// Two-step verfication of HOTP algorithm.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct HOTP {
    /// A secret token for the authentication
    secret: Vec<u8>,
}

impl HOTP {
    /// Constructs a new `HOTP`
    pub fn new<S: Into<String>>(secret: S) -> HOTP {
        HOTP { secret: secret.into().into_bytes() }
    }

    pub fn from_base32<S: Into<String>>(secret: S) -> Option<HOTP> {
        base32::decode(RFC4648 { padding: false }, &secret.into())
            .map(|secret| HOTP { secret })
    }

    pub fn from_bytes(bytes: &[u8]) -> HOTP {
        HOTP { secret: bytes.into() }
    }

    /// Generate a HOTP code.
    ///
    /// ``counter``: HOTP is a counter based algorithm.
    pub fn generate(&self, counter: u64) -> u32 {
        let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &self.secret);
        let wtr = counter.to_be_bytes().to_vec();
        let result = hmac::sign(&key, &wtr);
        let digest = result.as_ref();
        let ob = digest[19];
        let pos = (ob & 15) as usize;
        let mut rdr = Cursor::new(digest[pos..pos + 4].to_vec());
        let base = rdr.read_u32::<BigEndian>().unwrap() & 0x7fff_ffff;
        base % 1_000_000
    }

    /// Valid a HOTP code.
    ///
    /// ``code``: A number that is less than 6 characters.
    ///
    /// ``last``: Guess HOTP code from ``last + 1`` range.
    ///
    /// ``trials``: Guess HOTP code end at ``last + trials + 1``.
    pub fn verify(&self, code: u32, last: u64, trials: u64) -> bool {
        let code_str = code.to_string();
        let code_bytes = code_str.as_bytes();
        if code_bytes.len() > 6 {
            return false;
        }
        for i in last + 1..last + trials + 1 {
            let valid_code = self.generate(i).to_string();
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

    pub fn base32_secret(&self) -> String {
        base32::encode(RFC4648 { padding: false }, &self.secret)
    }

    /// Generate the otpauth protocal string.
    ///
    /// ``label``: Label of the identifier.
    ///
    /// ``issuer``: The company, the organization or something else.
    ///
    /// ``counter``: Counter of the HOTP algorithm.
    pub fn to_uri<S: AsRef<str>>(&self, label: S, issuer: S, counter: u64) -> String {
        format!("otpauth://hotp/{}?secret={}&issuer={}&counter={}",
                label.as_ref(),
                self.base32_secret(),
                issuer.as_ref(),
                counter)
    }
}
