use openssl::symm::Cipher;
use crate::wasi32;

#[allow(dead_code)]
pub struct CipherSpec {
    pub(crate) key_size: u32,
    pub(crate) block_size: u32,
    pub(crate) nonce_size: u32,
    pub(crate) tag_size: u32,
}

pub(crate) struct CipherEntry {
    pub(crate) cipher: Cipher,
    pub(crate) key_ptr: wasi32::uintptr_t,
    pub(crate) key_len: wasi32::size_t,
    pub(crate) spec: &'static CipherSpec,
}

impl CipherEntry {
    pub(crate) fn new(cipher: Cipher,
                      key_ptr: wasi32::uintptr_t,
                      key_len: wasi32::size_t,
                      spec: &'static CipherSpec) -> Self {
        Self {
            cipher,
            key_ptr,
            key_len,
            spec,
        }
    }
}

impl std::fmt::Debug for CipherEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CipherEntry")
    }
}
