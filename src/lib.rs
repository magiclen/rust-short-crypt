/*!
# ShortCrypt

ShortCrypt is a very simple encryption library, which aims to encrypt any data into something random at first glance.
Even if these data are similar, the ciphers are still pretty different.
The most important thing is that a cipher is only **4 bits** larger than its plaintext so that it is suitable for data used in a URL or a QR Code. Besides these, it is also an ideal candidate for serial number generation.

## Examples

`encrypt` method can create a `Cipher` tuple separating into a **base** and a **body** of the cipher. The size of a **base** is 4 bits, and the size of a **body** is equal to the plaintext.

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

#[macro_use]
extern crate alloc;

pub extern crate base32;
pub extern crate base64_url;
extern crate crc_any;

#[macro_use]
extern crate debug_helper;

use core::fmt::{self, Debug, Formatter};
use core::mem::transmute;

use alloc::string::String;
use alloc::vec::Vec;

pub use base64_url::base64;

use crc_any::{CRCu64, CRCu8};

/// A tuple. The first `u8` value is the **base** which only takes 4 bits. The second `Vec<u8>` value is the **body** whose size is equal to the plaintext. You can use your own algorithms to combine them together, or just use `encrypt_to_url_component` or `encrypt_to_qr_code_alphanumeric` to output them as a random-like string.
pub type Cipher = (u8, Vec<u8>);

pub struct ShortCrypt {
    hashed_key: [u8; 8],
    key_sum_rev: u64,
}

impl Debug for ShortCrypt {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        impl_debug_for_struct!(ShortCrypt, f, self, let .hashed_key = self.hashed_key.as_ref(), (.key_sum_rev, "{:X}", self.key_sum_rev));
    }
}

macro_rules! u8_to_string_64 {
    ($i:expr) => {
        if $i < 10 {
            $i + b'0'
        } else if $i >= 10 && $i < 36 {
            $i - 10 + b'A'
        } else if $i >= 36 && $i < 62 {
            $i - 36 + b'a'
        } else if $i == 62 {
            b'-'
        } else {
            b'_'
        }
    };
}

macro_rules! string_64_to_u8 {
    ($c:expr) => {
        if $c >= b'0' && $c <= b'9' {
            $c - b'0'
        } else if $c >= b'A' && $c <= b'Z' {
            $c + 10 - b'A'
        } else if $c >= b'a' && $c <= b'z' {
            $c + 36 - b'a'
        } else if $c == b'-' {
            62
        } else {
            63
        }
    };
}

macro_rules! u8_to_string_32 {
    ($i:expr) => {
        if $i < 10 {
            $i + b'0'
        } else {
            $i - 10 + b'A'
        }
    };
}

macro_rules! string_32_to_u8 {
    ($c:expr) => {
        if $c >= b'0' && $c <= b'9' {
            $c - b'0'
        } else {
            $c + 10 - b'A'
        }
    };
}

impl ShortCrypt {
    /// Create a new ShortCrypt instance.
    pub fn new<S: AsRef<str>>(key: S) -> ShortCrypt {
        let key_bytes = key.as_ref().as_bytes();

        let hashed_key = {
            let mut hasher = CRCu64::crc64we();

            hasher.digest(key_bytes);

            unsafe { transmute(hasher.get_crc().to_be()) }
        };

        let mut key_sum = 0u64;

        for &n in key_bytes {
            key_sum = key_sum.wrapping_add(u64::from(n));
        }

        let key_sum_rev = key_sum.reverse_bits();

        ShortCrypt {
            hashed_key,
            key_sum_rev,
        }
    }

    pub fn encrypt<T: ?Sized + AsRef<[u8]>>(&self, plaintext: &T) -> Cipher {
        let data = plaintext.as_ref();

        let len = data.len();

        let hashed_value = {
            let mut crc8 = CRCu8::crc8cdma2000();

            crc8.digest(data);
            crc8.get_crc() as u8
        };

        let base = hashed_value % 32;

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

        let sum: [u8; 8] = unsafe { transmute(sum.to_be()) };

        let hashed_array: [u8; 8] = {
            let mut hasher = CRCu64::crc64we();

            hasher.digest(&[m]);
            hasher.digest(&sum);

            unsafe { transmute(hasher.get_crc().to_be()) }
        };

        let mut path = Vec::with_capacity(len);

        for i in 0..len {
            let index = i % 8;
            path.push((hashed_array[index] ^ self.hashed_key[index]) as usize % len);
        }

        for (i, &p) in path.iter().enumerate() {
            if i == p {
                continue;
            }

            encrypted.swap(i, p);
        }

        (base, encrypted)
    }

    pub fn decrypt(&self, data: &Cipher) -> Result<Vec<u8>, &'static str> {
        let base = data.0;
        let data = &data.1;

        if base > 31 {
            return Err("The base is not correct.");
        }

        let len = data.len();

        let mut decrypted = Vec::with_capacity(len);

        self.decrypt_inner(base, data, &mut decrypted);

        Ok(decrypted)
    }

    fn decrypt_inner(&self, base: u8, data: &[u8], output: &mut Vec<u8>) {
        let len = data.len();

        let mut m = base;
        let mut sum = u64::from(base);

        for &v in data.iter() {
            m ^= v;
            sum = sum.wrapping_add(u64::from(v));
        }

        let sum: [u8; 8] = unsafe { transmute(sum.to_be()) };

        let hashed_array: [u8; 8] = {
            let mut hasher = CRCu64::crc64we();

            hasher.digest(&[m]);
            hasher.digest(&sum);

            unsafe { transmute(hasher.get_crc().to_be()) }
        };

        let mut path = Vec::with_capacity(len);

        for i in 0..len {
            let index = i % 8;
            path.push((hashed_array[index] ^ self.hashed_key[index]) as usize % len);
        }

        let mut data = data.to_vec();

        for (i, &p) in path.iter().enumerate().rev() {
            if i == p {
                continue;
            }

            data.swap(i, p);
        }

        for (i, d) in data.iter().enumerate() {
            let offset = self.hashed_key[i % 8] ^ base;

            output.push(d ^ offset);
        }
    }

    pub fn encrypt_to_url_component<T: ?Sized + AsRef<[u8]>>(&self, data: &T) -> String {
        let (base, encrypted) = self.encrypt(data);

        let base = u8_to_string_64!(base);

        let base_char = base as char;

        let mut result = String::with_capacity(1 + ((encrypted.len() * 4 + 2) / 3));

        base64_url::encode_to_string(&encrypted, &mut result);

        let mut sum = u64::from(base);

        for &n in result.as_bytes() {
            sum = sum.wrapping_add(u64::from(n));
        }

        let base_index = ((self.key_sum_rev ^ sum) % ((result.len() + 1) as u64)) as usize;

        result.insert(base_index, base_char);

        result
    }

    pub fn encrypt_to_url_component_and_push_to_string<T: ?Sized + AsRef<[u8]>, S: Into<String>>(
        &self,
        data: &T,
        output: S,
    ) -> String {
        let (base, encrypted) = self.encrypt(data);

        let base = u8_to_string_64!(base);

        let base_char = base as char;

        let mut output = output.into();

        let original_len = output.len();

        base64_url::encode_to_string(&encrypted, &mut output);

        let mut sum = u64::from(base);

        for &n in output.as_bytes().iter().skip(original_len) {
            sum = sum.wrapping_add(u64::from(n));
        }

        let base_index =
            ((self.key_sum_rev ^ sum) % ((output.len() - original_len + 1) as u64)) as usize;

        output.insert(original_len + base_index, base_char);

        output
    }

    pub fn decrypt_url_component<S: AsRef<str>>(
        &self,
        url_component: S,
    ) -> Result<Vec<u8>, &'static str> {
        let bytes = url_component.as_ref().as_bytes();
        let len = bytes.len();

        if len < 1 {
            return Err("The URL component is incorrect.");
        }

        let base_index = {
            let mut sum = 0u64;

            for &n in bytes {
                sum = sum.wrapping_add(u64::from(n));
            }

            ((self.key_sum_rev ^ sum) % (len as u64)) as usize
        };

        let base = string_64_to_u8!(bytes[base_index]);

        if base > 31 {
            return Err("The URL component is incorrect.");
        }

        let encrypted_base64_url = [&bytes[..base_index], &bytes[(base_index + 1)..]].concat();

        let encrypted = base64_url::decode(&encrypted_base64_url)
            .map_err(|_| "The URL component is incorrect.")?;

        self.decrypt(&(base, encrypted))
    }

    pub fn decrypt_url_component_and_push_to_vec<S: AsRef<str>>(
        &self,
        url_component: S,
        mut output: Vec<u8>,
    ) -> Result<Vec<u8>, &'static str> {
        let bytes = url_component.as_ref().as_bytes();
        let len = bytes.len();

        if len < 1 {
            return Err("The URL component is incorrect.");
        }

        let base_index = {
            let mut sum = 0u64;

            for &n in bytes {
                sum = sum.wrapping_add(u64::from(n));
            }

            ((self.key_sum_rev ^ sum) % (len as u64)) as usize
        };

        let base = string_64_to_u8!(bytes[base_index]);

        if base > 31 {
            return Err("The URL component is incorrect.");
        }

        let encrypted_base64_url = [&bytes[..base_index], &bytes[(base_index + 1)..]].concat();

        let encrypted = base64_url::decode(&encrypted_base64_url)
            .map_err(|_| "The URL component is incorrect.")?;

        let len = encrypted.len();

        output.reserve(len);

        self.decrypt_inner(base, &encrypted, &mut output);

        Ok(output)
    }

    pub fn encrypt_to_qr_code_alphanumeric<T: ?Sized + AsRef<[u8]>>(&self, data: &T) -> String {
        let (base, encrypted) = self.encrypt(data);

        let base = u8_to_string_32!(base);

        let base_char = base as char;

        let mut result = String::with_capacity(1 + ((encrypted.len() * 8 + 4) / 5));

        result.push_str(&base32::encode(
            base32::Alphabet::RFC4648 {
                padding: false,
            },
            &encrypted,
        ));

        let mut sum = u64::from(base);

        for &n in result.as_bytes() {
            sum = sum.wrapping_add(u64::from(n));
        }

        let base_index = ((self.key_sum_rev ^ sum) % ((result.len() + 1) as u64)) as usize;

        result.insert(base_index, base_char);

        result
    }

    pub fn encrypt_to_qr_code_alphanumeric_and_push_to_string<
        T: ?Sized + AsRef<[u8]>,
        S: Into<String>,
    >(
        &self,
        data: &T,
        output: S,
    ) -> String {
        let (base, encrypted) = self.encrypt(data);

        let base = u8_to_string_32!(base);

        let base_char = base as char;

        let mut output = output.into();

        let original_len = output.len();

        output.push_str(&base32::encode(
            base32::Alphabet::RFC4648 {
                padding: false,
            },
            &encrypted,
        ));

        let mut sum = u64::from(base);

        for &n in output.as_bytes().iter().skip(original_len) {
            sum = sum.wrapping_add(u64::from(n));
        }

        let base_index =
            ((self.key_sum_rev ^ sum) % ((output.len() - original_len + 1) as u64)) as usize;

        output.insert(original_len + base_index, base_char);

        output
    }

    pub fn decrypt_qr_code_alphanumeric<S: AsRef<str>>(
        &self,
        qr_code_alphanumeric: S,
    ) -> Result<Vec<u8>, &'static str> {
        let bytes = qr_code_alphanumeric.as_ref().as_bytes();
        let len = bytes.len();

        if len < 1 {
            return Err("The QR code alphanumeric text is incorrect.");
        }

        let base_index = {
            let mut sum = 0u64;

            for &n in bytes {
                sum = sum.wrapping_add(u64::from(n));
            }

            ((self.key_sum_rev ^ sum) % (len as u64)) as usize
        };

        let base = string_32_to_u8!(bytes[base_index]);

        if base > 31 {
            return Err("The QR code alphanumeric text is incorrect.");
        }

        let encrypted_base32 =
            String::from_utf8([&bytes[..base_index], &bytes[(base_index + 1)..]].concat())
                .map_err(|_| "The QR code alphanumeric text is incorrect.")?;

        let encrypted = match base32::decode(
            base32::Alphabet::RFC4648 {
                padding: false,
            },
            &encrypted_base32,
        ) {
            Some(t) => t,
            None => return Err("The QR code alphanumeric text is incorrect."),
        };

        self.decrypt(&(base, encrypted))
    }

    pub fn decrypt_qr_code_alphanumeric_and_push_to_vec<S: AsRef<str>>(
        &self,
        qr_code_alphanumeric: S,
        mut output: Vec<u8>,
    ) -> Result<Vec<u8>, &'static str> {
        let bytes = qr_code_alphanumeric.as_ref().as_bytes();
        let len = bytes.len();

        if len < 1 {
            return Err("The QR code alphanumeric text is incorrect.");
        }

        let base_index = {
            let mut sum = 0u64;

            for &n in bytes {
                sum = sum.wrapping_add(u64::from(n));
            }

            ((self.key_sum_rev ^ sum) % (len as u64)) as usize
        };

        let base = string_32_to_u8!(bytes[base_index]);

        if base > 31 {
            return Err("The QR code alphanumeric text is incorrect.");
        }

        let encrypted_base32 =
            String::from_utf8([&bytes[..base_index], &bytes[(base_index + 1)..]].concat())
                .map_err(|_| "The QR code alphanumeric text is incorrect.")?;

        let encrypted = match base32::decode(
            base32::Alphabet::RFC4648 {
                padding: false,
            },
            &encrypted_base32,
        ) {
            Some(t) => t,
            None => return Err("The QR code alphanumeric text is incorrect."),
        };

        let len = encrypted.len();

        output.reserve(len);

        self.decrypt_inner(base, &encrypted, &mut output);

        Ok(output)
    }
}
