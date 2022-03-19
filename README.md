ShortCrypt
====================

[![CI](https://github.com/magiclen/rust-short-crypt/actions/workflows/ci.yml/badge.svg)](https://github.com/magiclen/rust-short-crypt/actions/workflows/ci.yml)

ShortCrypt is a very simple encryption library, which aims to encrypt any data into something random at first glance.
Even if these data are similar, the ciphers are still pretty different.
The most important thing is that a cipher is only **4 bits** larger than its plaintext so that it is suitable for data used in a URL or a QR Code. Besides these, it is also an ideal candidate for serial number generation.

## Examples

`encrypt` method can create a `Cipher` tuple separating into a **base** and a **body** of the cipher. The size of a **base** is 4 bits, and the size of a **body** is equal to the plaintext.

```rust
use short_crypt::ShortCrypt;

let sc = ShortCrypt::new("magickey");

assert_eq!((8, [216, 78, 214, 199, 157, 190, 78, 250].to_vec()), sc.encrypt("articles"));
assert_eq!("articles".as_bytes().to_vec(), sc.decrypt(&(8, vec![216, 78, 214, 199, 157, 190, 78, 250])).unwrap());

```

`encrypt_to_url_component` method is common for encryption in most cases. After ShortCrypt `encrypt` a plaintext, it encodes the cipher into a random-like string based on Base64-URL format so that it can be concatenated with URLs.

```rust
use short_crypt::ShortCrypt;

let sc = ShortCrypt::new("magickey");

assert_eq!("2E87Wx52-Tvo", sc.encrypt_to_url_component("articles"));
assert_eq!("articles".as_bytes().to_vec(), sc.decrypt_url_component("2E87Wx52-Tvo").unwrap());
```

`encrypt_to_qr_code_alphanumeric` method is usually used for encrypting something into a QR code. After ShortCrypt `encrypt` a plaintext, it encodes the cipher into a random-like string based on Base32 format so that it can be inserted into a QR code with the compatibility with alphanumeric mode.

```rust
use short_crypt::ShortCrypt;

let sc = ShortCrypt::new("magickey");

assert_eq!("3BHNNR45XZH8PU", sc.encrypt_to_qr_code_alphanumeric("articles"));
assert_eq!("articles".as_bytes().to_vec(), sc.decrypt_qr_code_alphanumeric("3BHNNR45XZH8PU").unwrap());
```

Besides, in order to reduce the copy times of strings, you can also use `encrypt_to_url_component_and_push_to_string`, `encrypt_to_qr_code_alphanumeric_and_push_to_string` methods to use the same memory space.

```rust
use short_crypt::ShortCrypt;

let sc = ShortCrypt::new("magickey");

let url = "https://magiclen.org/".to_string();

assert_eq!("https://magiclen.org/2E87Wx52-Tvo", sc.encrypt_to_url_component_and_push_to_string("articles", url));

let url = "https://magiclen.org/".to_string();

assert_eq!("https://magiclen.org/3BHNNR45XZH8PU", sc.encrypt_to_qr_code_alphanumeric_and_push_to_string("articles", url));
```

## Crates.io

https://crates.io/crates/short-crypt

## Documentation

https://docs.rs/short-crypt

## License

[MIT](LICENSE)