extern crate otpauth;
extern crate time;

use otpauth::OtpAuth;

#[test]
fn test_hotp() {
    let auth = OtpAuth::new("python");
    let code = auth.hotp(4);
    assert_eq!(true, auth.valid_hotp(code, 0, 100));
    assert_eq!(false, auth.valid_hotp(123456, 0, 100));
}

#[test]
fn test_totp() {
    let auth = OtpAuth::new("python");
    let timestamp1 = time::now().to_timespec().sec as usize;
    let code = auth.totp(30usize, timestamp1);
    let timestamp2 = time::now().to_timespec().sec as usize;
    assert_eq!(true, auth.valid_totp(code, 30usize, timestamp2));
    assert_eq!(false, auth.valid_totp(123456, 30usize, timestamp2));
}
