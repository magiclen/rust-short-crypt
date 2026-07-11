/*!
# ShortCrypt

ShortCrypt is a very simple deterministic encryption library, which aims to encrypt any data into something random at first glance.

Even if these data are similar, the ciphers are still pretty different.

The most important thing is that a cipher contains only **5 bits** more information than its plaintext so that it is suitable for data used in a URL or a QR Code. Besides these, it is also an ideal candidate for serial number generation.

ShortCrypt does not provide cryptographic authentication and must not be used to protect sensitive data or resist malicious tampering.

## Examples

`encrypt` method can create a `Cipher` tuple separating into a **base** and a **body** of the cipher. The **base** contains 5 bits of information and is stored as a `u8`, while the size of the **body** is equal to the plaintext.

```rust
extern crate short_crypt;

use short_crypt::ShortCrypt;

let sc = ShortCrypt::new("magickey");

assert_eq!((8, [216, 78, 214, 199, 157, 190, 78, 250].to_vec()), sc.encrypt("articles"));
assert_eq!("articles".as_bytes().to_vec(), sc.decrypt(&(8, vec![216, 78, 214, 199, 157, 190, 78, 250])).unwrap());

```

`encrypt_to_url_component` method is common for encryption in most cases. After ShortCrypt `encrypt` a plaintext, it encodes the cipher into a random-like string based on Base64-URL format so that it can be concatenated with URLs.

```rust
extern crate short_crypt;

use short_crypt::ShortCrypt;

let sc = ShortCrypt::new("magickey");

assert_eq!("2E87Wx52-Tvo", sc.encrypt_to_url_component("articles"));
assert_eq!("articles".as_bytes().to_vec(), sc.decrypt_url_component("2E87Wx52-Tvo").unwrap());
```

`encrypt_to_qr_code_alphanumeric` method is usually used for encrypting something into a QR code. After ShortCrypt `encrypt` a plaintext, it encodes the cipher into a random-like string based on Base32 format so that it can be inserted into a QR code with the compatibility with alphanumeric mode.

```rust
extern crate short_crypt;

use short_crypt::ShortCrypt;

let sc = ShortCrypt::new("magickey");

assert_eq!("3BHNNR45XZH8PU", sc.encrypt_to_qr_code_alphanumeric("articles"));
assert_eq!("articles".as_bytes().to_vec(), sc.decrypt_qr_code_alphanumeric("3BHNNR45XZH8PU").unwrap());
```

Besides, in order to reduce the copy times of strings, you can also use `encrypt_to_url_component_and_push_to_string`, `encrypt_to_qr_code_alphanumeric_and_push_to_string` methods to use the same memory space.

```rust
extern crate short_crypt;

use short_crypt::ShortCrypt;

let sc = ShortCrypt::new("magickey");

let url = "https://magiclen.org/".to_string();

assert_eq!("https://magiclen.org/2E87Wx52-Tvo", sc.encrypt_to_url_component_and_push_to_string("articles", url));

let url = "https://magiclen.org/".to_string();

assert_eq!("https://magiclen.org/3BHNNR45XZH8PU", sc.encrypt_to_qr_code_alphanumeric_and_push_to_string("articles", url));
```
*/

#![no_std]

extern crate alloc;

pub extern crate base32;
pub extern crate base64_url;

use alloc::{string::String, vec::Vec};
use core::fmt::{self, Debug, Formatter};

pub use base64_url::base64;
use crc_any::{CRCu8, CRCu64};

/// A tuple containing a 5-bit **base** stored as a `u8` and a **body** whose length equals the plaintext length. You can use your own algorithm to combine them, or use [`ShortCrypt::encrypt_to_url_component`] or [`ShortCrypt::encrypt_to_qr_code_alphanumeric`] to produce a random-like string.
pub type Cipher = (u8, Vec<u8>);

/// A deterministic encryption context derived from a string key.
pub struct ShortCrypt {
    hashed_key:  [u8; 8],
    key_sum_rev: u64,
}

impl Debug for ShortCrypt {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("ShortCrypt").finish_non_exhaustive()
    }
}

#[inline]
fn encode_base(base: u8) -> u8 {
    debug_assert!(base < 32);

    if base < 10 { base + b'0' } else { base - 10 + b'A' }
}

#[inline]
fn decode_base(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'V' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[inline]
fn checksum_base(data: &[u8]) -> u8 {
    let mut crc8 = CRCu8::crc8cdma2000();

    crc8.update(data);
    crc8.get_crc() % 32
}

impl ShortCrypt {
    /// Creates a new `ShortCrypt` instance from a string key.
    pub fn new<S: AsRef<str>>(key: S) -> ShortCrypt {
        let key_bytes = key.as_ref().as_bytes();

        let hashed_key = {
            let mut hasher = CRCu64::crc64we();

            hasher.update(key_bytes);

            hasher.get_crc().to_be_bytes()
        };

        let mut key_sum = 0u64;

        for n in key_bytes.iter().copied() {
            key_sum = key_sum.wrapping_add(u64::from(n));
        }

        let key_sum_rev = key_sum.reverse_bits();

        ShortCrypt {
            hashed_key,
            key_sum_rev,
        }
    }

    /// Encrypts byte-like plaintext into a [`Cipher`].
    pub fn encrypt<T: ?Sized + AsRef<[u8]>>(&self, plaintext: &T) -> Cipher {
        let data = plaintext.as_ref();

        let len = data.len();

        let base = checksum_base(data);

        let mut encrypted = Vec::with_capacity(len);

        let mut m = base;
        let mut sum = u64::from(base);

        for (i, d) in data.iter().enumerate() {
            let offset = self.hashed_key[i % 8] ^ base;

            let v = d ^ offset;

            encrypted.push(v);

            m ^= v;
            sum = sum.wrapping_add(u64::from(v));
        }

        let sum: [u8; 8] = sum.to_be_bytes();

        let hashed_array: [u8; 8] = {
            let mut hasher = CRCu64::crc64we();

            hasher.update(&[m]);
            hasher.update(&sum);

            hasher.get_crc().to_be_bytes()
        };

        for i in 0..len {
            let index = i % 8;
            let p = (hashed_array[index] ^ self.hashed_key[index]) as usize % len;

            if i == p {
                continue;
            }

            encrypted.swap(i, p);
        }

        (base, encrypted)
    }

    /// Decrypts a [`Cipher`] and rejects data whose 5-bit checksum does not match.
    pub fn decrypt(&self, data: &Cipher) -> Result<Vec<u8>, &'static str> {
        let base = data.0;
        let data = &data.1;

        if base > 31 {
            return Err("The base is not correct.");
        }

        let mut decrypted = data.to_vec();

        self.decrypt_appended_inner(base, 0, &mut decrypted)
            .map_err(|_| "The cipher is incorrect.")?;

        Ok(decrypted)
    }

    fn decrypt_appended_inner(
        &self,
        base: u8,
        original_len: usize,
        output: &mut Vec<u8>,
    ) -> Result<(), ()> {
        let len = output.len() - original_len;

        let mut m = base;
        let mut sum = u64::from(base);

        for v in output[original_len..].iter().copied() {
            m ^= v;
            sum = sum.wrapping_add(u64::from(v));
        }

        let sum: [u8; 8] = sum.to_be_bytes();

        let hashed_array: [u8; 8] = {
            let mut hasher = CRCu64::crc64we();

            hasher.update(&[m]);
            hasher.update(&sum);

            hasher.get_crc().to_be_bytes()
        };

        for i in (0..len).rev() {
            let index = i % 8;
            let p = (hashed_array[index] ^ self.hashed_key[index]) as usize % len;

            if i == p {
                continue;
            }

            output.swap(original_len + i, original_len + p);
        }

        for (i, d) in output[original_len..].iter_mut().enumerate() {
            let offset = self.hashed_key[i % 8] ^ base;

            *d ^= offset;
        }

        if checksum_base(&output[original_len..]) != base {
            output.truncate(original_len);

            return Err(());
        }

        Ok(())
    }

    fn extract_base(&self, bytes: &[u8]) -> Option<(u8, usize)> {
        if bytes.is_empty() {
            return None;
        }

        let mut sum = 0u64;

        for n in bytes.iter().copied() {
            sum = sum.wrapping_add(u64::from(n));
        }

        let base_index = ((self.key_sum_rev ^ sum) % (bytes.len() as u64)) as usize;
        let base = decode_base(bytes[base_index])?;

        Some((base, base_index))
    }

    fn insert_base(&self, base: u8, original_len: usize, mut output: String) -> String {
        let base = encode_base(base);
        let mut sum = u64::from(base);

        for n in output.bytes().skip(original_len) {
            sum = sum.wrapping_add(u64::from(n));
        }

        let base_index =
            ((self.key_sum_rev ^ sum) % ((output.len() - original_len + 1) as u64)) as usize;

        output.insert(original_len + base_index, base as char);
        output
    }

    /// Encrypts data and encodes the cipher as a Base64-URL component.
    #[inline]
    pub fn encrypt_to_url_component<T: ?Sized + AsRef<[u8]>>(&self, data: &T) -> String {
        self.encrypt_to_url_component_and_push_to_string(data, String::new())
    }

    /// Encrypts data and appends the Base64-URL component to a string.
    pub fn encrypt_to_url_component_and_push_to_string<T: ?Sized + AsRef<[u8]>, S: Into<String>>(
        &self,
        data: &T,
        output: S,
    ) -> String {
        let (base, encrypted) = self.encrypt(data);

        let mut output = output.into();

        let original_len = output.len();

        base64_url::encode_to_string(&encrypted, &mut output);

        self.insert_base(base, original_len, output)
    }

    /// Decodes and decrypts a Base64-URL component.
    #[inline]
    pub fn decrypt_url_component<S: AsRef<str>>(
        &self,
        url_component: S,
    ) -> Result<Vec<u8>, &'static str> {
        self.decrypt_url_component_and_push_to_vec(url_component, Vec::new())
    }

    /// Decodes and decrypts a Base64-URL component and appends the plaintext to a vector.
    pub fn decrypt_url_component_and_push_to_vec<S: AsRef<str>>(
        &self,
        url_component: S,
        mut output: Vec<u8>,
    ) -> Result<Vec<u8>, &'static str> {
        let bytes = url_component.as_ref().as_bytes();
        let (base, base_index) =
            self.extract_base(bytes).ok_or("The URL component is incorrect.")?;

        let encrypted_base64_url = [&bytes[..base_index], &bytes[(base_index + 1)..]].concat();
        let original_len = output.len();

        base64_url::decode_to_vec(&encrypted_base64_url, &mut output)
            .map_err(|_| "The URL component is incorrect.")?;

        self.decrypt_appended_inner(base, original_len, &mut output)
            .map_err(|_| "The URL component is incorrect.")?;

        Ok(output)
    }

    /// Encrypts data and encodes the cipher as Base32 text for QR alphanumeric mode.
    #[inline]
    pub fn encrypt_to_qr_code_alphanumeric<T: ?Sized + AsRef<[u8]>>(&self, data: &T) -> String {
        self.encrypt_to_qr_code_alphanumeric_and_push_to_string(data, String::new())
    }

    /// Encrypts data and appends Base32 text for QR alphanumeric mode to a string.
    pub fn encrypt_to_qr_code_alphanumeric_and_push_to_string<
        T: ?Sized + AsRef<[u8]>,
        S: Into<String>,
    >(
        &self,
        data: &T,
        output: S,
    ) -> String {
        let (base, encrypted) = self.encrypt(data);

        let mut output = output.into();

        let original_len = output.len();

        output.push_str(&base32::encode(
            base32::Alphabet::Rfc4648 {
                padding: false
            },
            &encrypted,
        ));

        self.insert_base(base, original_len, output)
    }

    /// Decodes and decrypts Base32 text produced for QR alphanumeric mode.
    #[inline]
    pub fn decrypt_qr_code_alphanumeric<S: AsRef<str>>(
        &self,
        qr_code_alphanumeric: S,
    ) -> Result<Vec<u8>, &'static str> {
        self.decrypt_qr_code_alphanumeric_and_push_to_vec(qr_code_alphanumeric, Vec::new())
    }

    /// Decodes and decrypts QR alphanumeric text and appends the plaintext to a vector.
    pub fn decrypt_qr_code_alphanumeric_and_push_to_vec<S: AsRef<str>>(
        &self,
        qr_code_alphanumeric: S,
        mut output: Vec<u8>,
    ) -> Result<Vec<u8>, &'static str> {
        let bytes = qr_code_alphanumeric.as_ref().as_bytes();
        let (base, base_index) =
            self.extract_base(bytes).ok_or("The QR code alphanumeric text is incorrect.")?;

        let encrypted_base32 =
            String::from_utf8([&bytes[..base_index], &bytes[(base_index + 1)..]].concat())
                .map_err(|_| "The QR code alphanumeric text is incorrect.")?;

        let encrypted = base32::decode(
            base32::Alphabet::Rfc4648 {
                padding: false
            },
            &encrypted_base32,
        )
        .ok_or("The QR code alphanumeric text is incorrect.")?;

        let original_len = output.len();

        if original_len == 0 {
            output = encrypted;
        } else {
            output.extend_from_slice(&encrypted);
        }

        self.decrypt_appended_inner(base, original_len, &mut output)
            .map_err(|_| "The QR code alphanumeric text is incorrect.")?;

        Ok(output)
    }
}
