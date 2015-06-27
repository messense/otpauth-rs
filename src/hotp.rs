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
//!
use std::io::Cursor;

use crypto::digest::Digest;
use crypto::mac::Mac;
use crypto::hmac::Hmac;
use crypto::sha1::Sha1;
use byteorder::{BigEndian, WriteBytesExt, ReadBytesExt};


#[derive(Debug, Eq, PartialEq, Clone)]
pub struct HOTP {
    /// A secret token for the authentication
    pub secret: String,
}

impl HOTP {
    /// Constructs a new `HOTP`
    pub fn new(secret: &str) -> HOTP {
        HOTP {
            secret: secret.to_owned(),
        }
    }

    /// Generate a HOTP code.
    ///
    /// ``counter``: HOTP is a counter based algorithm.
    pub fn generate(&self, counter: usize) -> u32 {
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

    /// Valid a HOTP code.
    ///
    /// ``code``: A number that is less than 6 characters.
    ///
    /// ``last``: Guess HOTP code from ``last + 1`` range.
    ///
    /// ``trials``: Guess HOTP code end at ``last + trials + 1``.
    pub fn verify(&self, code: u32, last: usize, trials: usize) -> bool {
        let code_str = code.to_string();
        let code_bytes = code_str.as_bytes();
        if code_bytes.len() > 6 {
            return false;
        }
        for i in last+1..last+trials+1 {
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

    /// Generate the otpauth protocal string.
    ///
    /// ``label``: Label of the identifier.
    ///
    /// ``issuer``: The company, the organization or something else.
    ///
    /// ``counter``: Counter of the HOTP algorithm.
    pub fn to_uri(&self, label: &str, issuer: &str, counter: usize) -> String {
        use base32::encode;
        use base32::Alphabet::RFC4648;

        let encoded_secret = encode(RFC4648 { padding: false }, self.secret.as_bytes());
        format!("otpauth://hotp/{}?secret={}&issuer={}&counter={}", label, encoded_secret, issuer, counter)
    }
}
