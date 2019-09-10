extern crate ring;
extern crate base64;

#[macro_use]
mod macros;
mod private;
mod signed;
mod key;

pub use self::private::*;
pub use self::signed::*;
pub use self::key::*;

#[test]
fn roundtrip_tests() {
    use super::{Cookie, CookieJar};

    // Secret is 'Super secret!' passed through sha256
    let secret = b"\x1b\x1c\x6f\x1b\x31\x99\x82\x77\x0e\x05\xb6\x05\x54\x0b\xd9\xea\x54\x9f\x9a\x56\xf4\x0f\x97\xdc\x6e\xf2\x89\x86\x91\xe0\xa5\x79";
    let key = Key::from_master(secret);

    let mut jar = CookieJar::new();
    jar.add(Cookie::new("signed_with_ring014", "3tdHXEQ2kf6fxC7dWzBGmpSLMtJenXLKrZ9cHkSsl1w=Tamper-proof"));
    jar.add(Cookie::new("encrypted_with_ring014", "lObeZJorGVyeSWUA8khTO/8UCzFVBY9g0MGU6/J3NN1R5x11dn2JIA=="));
    jar.add(Cookie::new("signed_with_ring016", "3tdHXEQ2kf6fxC7dWzBGmpSLMtJenXLKrZ9cHkSsl1w=Tamper-proof"));
    jar.add(Cookie::new("encrypted_with_ring016", "SU1ujceILyMBg3fReqRmA9HUtAIoSPZceOM/CUpObROHEujXIjonkA=="));

    let signed = jar.signed(&key);
    assert_eq!(signed.get("signed_with_ring014").unwrap().value(), "Tamper-proof");
    assert_eq!(signed.get("signed_with_ring016").unwrap().value(), "Tamper-proof");

    let private = jar.private(&key);
    assert_eq!(private.get("encrypted_with_ring014").unwrap().value(), "Tamper-proof");
    assert_eq!(private.get("encrypted_with_ring016").unwrap().value(), "Tamper-proof");
}
