extern crate short_crypt;

use short_crypt::ShortCrypt;

#[test]
fn test_encrypt() {
    let sc = ShortCrypt::new("magickey");

    assert_eq!((8, [216, 78, 214, 199, 157, 190, 78, 250].to_vec()), sc.encrypt("articles"));
}

#[test]
fn test_decrypt() {
    let sc = ShortCrypt::new("magickey");

    assert_eq!(
        b"articles".to_vec(),
        sc.decrypt(&(8, vec![216, 78, 214, 199, 157, 190, 78, 250])).unwrap()
    );
}

#[test]
fn test_encrypt_decrypt() {
    let sc = ShortCrypt::new("magickey");

    let data = b"articles";

    assert_eq!(data.to_vec(), sc.decrypt(&sc.encrypt(data)).unwrap());
}

#[test]
fn test_encrypt_to_url_component() {
    let sc = ShortCrypt::new("magickey");

    assert_eq!("2E87Wx52-Tvo", sc.encrypt_to_url_component("articles"));
}

#[test]
fn test_encrypt_to_url_component_and_push_to_string() {
    let url = "https://magiclen.org/".to_string();

    let sc = ShortCrypt::new("magickey");

    assert_eq!(
        "https://magiclen.org/2E87Wx52-Tvo",
        sc.encrypt_to_url_component_and_push_to_string("articles", url)
    );
}

#[test]
fn test_decrypt_url_component() {
    let sc = ShortCrypt::new("magickey");

    assert_eq!(b"articles".to_vec(), sc.decrypt_url_component("2E87Wx52-Tvo").unwrap());
}

#[test]
fn test_decrypt_url_component_and_push_to_vec() {
    let url = b"https://magiclen.org/".to_vec();

    let sc = ShortCrypt::new("magickey");

    assert_eq!(
        b"https://magiclen.org/articles".to_vec(),
        sc.decrypt_url_component_and_push_to_vec("2E87Wx52-Tvo", url).unwrap()
    );
}

#[test]
fn test_encrypt_to_qr_code_alphanumeric() {
    let sc = ShortCrypt::new("magickey");

    assert_eq!("3BHNNR45XZH8PU", sc.encrypt_to_qr_code_alphanumeric("articles"));
}

#[test]
fn test_encrypt_to_qr_code_alphanumeric_and_push_to_string() {
    let url = "https://magiclen.org/".to_string();

    let sc = ShortCrypt::new("magickey");

    assert_eq!(
        "https://magiclen.org/3BHNNR45XZH8PU",
        sc.encrypt_to_qr_code_alphanumeric_and_push_to_string("articles", url)
    );
}

#[test]
fn test_decrypt_qr_code_alphanumeric() {
    let sc = ShortCrypt::new("magickey");

    assert_eq!(b"articles".to_vec(), sc.decrypt_qr_code_alphanumeric("3BHNNR45XZH8PU").unwrap());
}

#[test]
fn test_decrypt_qr_code_alphanumeric_and_push_to_vec() {
    let url = b"https://magiclen.org/".to_vec();

    let sc = ShortCrypt::new("magickey");

    assert_eq!(
        b"https://magiclen.org/articles".to_vec(),
        sc.decrypt_qr_code_alphanumeric_and_push_to_vec("3BHNNR45XZH8PU", url).unwrap()
    );
}
