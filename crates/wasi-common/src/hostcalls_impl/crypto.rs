#![allow(non_camel_case_types)]
use crate::ctx::WasiCtx;
use crate::cipherentry::{CipherEntry, CipherSpec};
use crate::memory::*;
use crate::{wasi, wasi32, Error, Result};
use log::trace;
use std::str;
use openssl::symm::{Cipher, Mode, Crypter};

struct CipherImpl {
    name: &'static str,
    constructor: fn() -> Cipher,
    spec: CipherSpec,
}

const IMPLEMENTED_CIPHERS: &'static [&'static CipherImpl] = &[
    &CipherImpl {
        name: "A128GCM",
        constructor: Cipher::aes_128_gcm,
        spec: CipherSpec {
            key_size: 16,
            block_size: 16,
            nonce_size: 12,
            tag_size: 16,
        }
    },
];

pub(crate) fn crypto_aead_open(
    wasi_ctx: &mut WasiCtx,
    memory: &mut [u8],
    algorithm_ptr: wasi32::uintptr_t,
    algorithm_len: wasi32::size_t,
    key_ptr: wasi32::uintptr_t,
    key_len: wasi32::size_t,
    opened_aead_ptr: wasi32::uintptr_t, // *mut wasi::__wasi_aead_t
) -> Result<()> {
    trace!(
        "crypto_aead_open(algorithm_ptr={:#x?}, algorithm_len={:?})",
        algorithm_ptr,
        algorithm_len,
    );

    let algorithm = dec_slice_of_u8(memory, algorithm_ptr, algorithm_len)
        .and_then(|s| str::from_utf8(s).map_err(|_| Error::EILSEQ))?;

    let cipher_impl = IMPLEMENTED_CIPHERS
        .iter().find(|x| x.name == algorithm).ok_or(Error::ENOTSUP)?;

    if key_len != cipher_impl.spec.key_size {
        return Err(Error::EINVAL);
    }

    let cipher = (cipher_impl.constructor)();
    let ce = CipherEntry::new(cipher, key_ptr, key_len, &cipher_impl.spec);
    let guest_cipher = wasi_ctx.insert_cipher_entry(ce)?;
    enc_aead_byref(memory, opened_aead_ptr, guest_cipher)
}

pub(crate) fn crypto_aead_encrypt(
    wasi_ctx: &WasiCtx,
    memory: &mut [u8],
    aead: wasi::__wasi_aead_t,
    nonce_ptr: wasi32::uintptr_t,
    nonce_len: wasi32::size_t,
    auth_ptr: wasi32::uintptr_t,
    auth_len: wasi32::size_t,
    data_ptr: wasi32::uintptr_t,
    data_len: wasi32::size_t,
    tag_ptr: wasi32::uintptr_t,
    tag_len: wasi32::size_t,
) -> Result<()> {
    trace!(
        "crypto_aead_encrypt(aead={:?})",
        aead,
    );

    let ce = wasi_ctx.get_cipher_entry(aead)?;
    let key = dec_slice_of_u8(memory, ce.key_ptr, ce.key_len)?;
    let nonce = dec_slice_of_u8(memory, nonce_ptr, nonce_len)?;
    let mut encrypter = Crypter::new(
        ce.cipher,
        Mode::Encrypt,
        key,
        Some(nonce)).map_err(|_| Error::EINVAL)?;

    let auth = dec_slice_of_u8(memory, auth_ptr, auth_len)?;
    encrypter.aad_update(auth).map_err(|_| Error::EINVAL)?;

    let data_iovs = dec_iovec_slice(memory, data_ptr, data_len)?;
    let mut block = vec![0; ce.spec.block_size as usize];

    for iov in data_iovs {
        let data = unsafe {
            std::slice::from_raw_parts_mut(
                iov.buf as *mut u8,
                iov.buf_len)
        };
        for chunk in data.chunks_mut(ce.spec.block_size as usize) {
            encrypter.update(&chunk, &mut block).map_err(|_| Error::EINVAL)?;
            let len = chunk.len();
            chunk[..].copy_from_slice(&block[..len]);
        }
    }
    encrypter.finalize(&mut block).map_err(|_| Error::EINVAL)?;

    let mut tag_buf = vec![0; tag_len as usize];
    encrypter.get_tag(&mut tag_buf).map_err(|_| Error::EINVAL)?;

    enc_slice_of_u8(memory, &tag_buf, tag_ptr)
}

pub(crate) fn crypto_aead_decrypt(
    wasi_ctx: &WasiCtx,
    memory: &mut [u8],
    aead: wasi::__wasi_aead_t,
    nonce_ptr: wasi32::uintptr_t,
    nonce_len: wasi32::size_t,
    auth_ptr: wasi32::uintptr_t,
    auth_len: wasi32::size_t,
    data_ptr: wasi32::uintptr_t,
    data_len: wasi32::size_t,
    tag_ptr: wasi32::uintptr_t,
    tag_len: wasi32::size_t,
) -> Result<()> {
    trace!(
        "crypto_aead_decrypt(aead={:?})",
        aead,
    );

    let ce = wasi_ctx.get_cipher_entry(aead)?;
    let key = dec_slice_of_u8(memory, ce.key_ptr, ce.key_len)?;
    let nonce = dec_slice_of_u8(memory, nonce_ptr, nonce_len)?;
    let mut decrypter = Crypter::new(
        ce.cipher,
        Mode::Decrypt,
        key,
        Some(nonce)).map_err(|_| Error::EINVAL)?;

    let auth = dec_slice_of_u8(memory, auth_ptr, auth_len)?;
    decrypter.aad_update(auth).map_err(|_| Error::EINVAL)?;

    let tag = dec_slice_of_u8(memory, tag_ptr, tag_len)?;
    decrypter.set_tag(&tag).map_err(|_| Error::EINVAL)?;

    let data_iovs = dec_iovec_slice(memory, data_ptr, data_len)?;
    let mut block = vec![0; ce.spec.block_size as usize];

    for iov in data_iovs {
        let data = unsafe {
            std::slice::from_raw_parts_mut(
                iov.buf as *mut u8,
                iov.buf_len)
        };
        for chunk in data.chunks_mut(ce.spec.block_size as usize) {
            decrypter.update(&chunk, &mut block).map_err(|_| Error::EINVAL)?;
            let len = chunk.len();
            chunk[..].copy_from_slice(&block[..len]);
        }
    }
    decrypter.finalize(&mut block).map_err(|_| Error::EINVAL)?;

    Ok(())
}

pub(crate) fn crypto_aead_close(
    wasi_ctx: &mut WasiCtx,
    _memory: &mut [u8],
    aead: wasi::__wasi_aead_t) -> Result<()> {
    trace!(
        "crypto_aead_close(cipher={:?})",
        aead,
    );

    wasi_ctx.remove_cipher_entry(aead)?;
    Ok(())
}

pub(crate) fn crypto_mac_open(
    wasi_ctx: &mut WasiCtx,
    memory: &mut [u8],
    algorithm_ptr: wasi32::uintptr_t,
    algorithm_len: wasi32::size_t,
    key_ptr: wasi32::uintptr_t,
    key_len: wasi32::size_t,
    opened_mac_ptr: wasi32::uintptr_t, // *mut wasi::__wasi_mac_t
) -> Result<()> {
    trace!(
        "crypto_mac_open(algorithm_ptr={:#x?}, algorithm_len={:?})",
        algorithm_ptr,
        algorithm_len,
    );

    Err(Error::ENOSYS)
}

pub(crate) fn crypto_mac_update(
    wasi_ctx: &WasiCtx,
    memory: &mut [u8],
    mac: wasi::__wasi_mac_t,
    data_ptr: wasi32::uintptr_t,
    data_len: wasi32::size_t
) -> Result<()> {
    trace!(
        "crypto_mac_update(mac={:?})",
        mac,
    );

    Err(Error::ENOSYS)
}

pub(crate) fn crypto_mac_digest(
    wasi_ctx: &WasiCtx,
    memory: &mut [u8],
    mac: wasi::__wasi_mac_t,
    digest_ptr: wasi32::uintptr_t,
    digest_len: wasi32::size_t
) -> Result<()> {
    trace!(
        "crypto_mac_digest(mac={:?})",
        mac,
    );

    Err(Error::ENOSYS)
}

pub(crate) fn crypto_mac_close(
    wasi_ctx: &mut WasiCtx,
    memory: &mut [u8],
    mac: wasi::__wasi_mac_t
) -> Result<()> {
    trace!(
        "crypto_mac_close(mac={:?})",
        mac,
    );

    Err(Error::ENOSYS)
}

pub(crate) fn crypto_hkdf(
    wasi_ctx: &WasiCtx,
    memory: &mut [u8],
    algorithm_ptr: wasi32::uintptr_t,
    algorithm_len: wasi32::size_t,
    op: wasi::__wasi_hkdf_operation_t,
    input_ptr: wasi32::uintptr_t,
    input_len: wasi32::size_t,
    output_ptr: wasi32::uintptr_t,
    output_len: wasi32::size_t,
) -> Result<()> {
    trace!(
        "crypto_hkdf(algorithm_ptr={:#x?}, algorithm_len={:?})",
        algorithm_ptr,
        algorithm_len,
    );

    Err(Error::ENOSYS)
}
