// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_std]
extern crate alloc;

mod constants;
mod kmip;

pub use crate::constants::*;
pub use crate::kmip::*;
pub use ttlv;

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_NAME: &str = "test_key_name";
    const KMIP_MAX_BUFFER_SIZE: usize = 1024;

    #[test]
    fn locate_key() {
        let buf = &mut [0u8; KMIP_MAX_BUFFER_SIZE];
        let request_len = request(None, locate(KEY_NAME)).encode(buf).unwrap();
        assert_eq!(176, request_len);
    }
}
