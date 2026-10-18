//! The C entry points OpenSSH calls.
//!
//! Layout and signatures are from `sk-api.h` at tag `V_10_3_P1`. The field
//! order matters: `sk_enroll_response.flags` moved to the front of the struct
//! at some point, so this is transcribed from the header rather than from
//! memory (PROJECT.md §20 — cite the source).

use crate::{
    alloc::{free, to_c_buffer, zeroed_struct},
    client::DaemonClient,
    debug::DebugLog,
    CONNECT_TIMEOUT, OPERATION_TIMEOUT, SSH_SK_ECDSA, SSH_SK_ED25519, SSH_SK_ERR_DEVICE_NOT_FOUND,
    SSH_SK_ERR_GENERAL, SSH_SK_ERR_UNSUPPORTED, SSH_SK_RESIDENT_KEY, SSH_SK_USER_VERIFICATION_REQD,
    SSH_SK_VERSION_MAJOR,
};
use ctap_client::{
    split_ecdsa_signature, GetAssertion, GetAssertionResponse, MakeCredential,
    MakeCredentialResponse, COSE_EDDSA, COSE_ES256,
};
use std::{
    ffi::{c_char, CStr},
    panic::{catch_unwind, AssertUnwindSafe},
};

/// `struct sk_enroll_response`.
#[repr(C)]
#[derive(Debug)]
pub struct SkEnrollResponse {
    /// Authenticator data flags.
    pub flags: u8,
    /// The credential public key.
    pub public_key: *mut u8,
    /// Length of `public_key`.
    pub public_key_len: usize,
    /// The credential id.
    pub key_handle: *mut u8,
    /// Length of `key_handle`.
    pub key_handle_len: usize,
    /// The attestation signature.
    pub signature: *mut u8,
    /// Length of `signature`.
    pub signature_len: usize,
    /// The attestation certificate.
    pub attestation_cert: *mut u8,
    /// Length of `attestation_cert`.
    pub attestation_cert_len: usize,
    /// Raw authenticator data.
    pub authdata: *mut u8,
    /// Length of `authdata`.
    pub authdata_len: usize,
}

/// `struct sk_sign_response`.
#[repr(C)]
#[derive(Debug)]
pub struct SkSignResponse {
    /// Authenticator data flags.
    pub flags: u8,
    /// The signature counter.
    pub counter: u32,
    /// The signature's `r` component.
    pub sig_r: *mut u8,
    /// Length of `sig_r`.
    pub sig_r_len: usize,
    /// The signature's `s` component.
    pub sig_s: *mut u8,
    /// Length of `sig_s`.
    pub sig_s_len: usize,
}

/// `struct sk_resident_key`.
#[repr(C)]
#[derive(Debug)]
pub struct SkResidentKey {
    /// The key algorithm.
    pub alg: u32,
    /// The slot the credential occupies.
    pub slot: usize,
    /// The relying party id.
    pub application: *mut c_char,
    /// The credential itself.
    pub key: SkEnrollResponse,
    /// Credential flags.
    pub flags: u8,
    /// The user handle.
    pub user_id: *mut u8,
    /// Length of `user_id`.
    pub user_id_len: usize,
}

/// `struct sk_option`.
#[repr(C)]
#[derive(Debug)]
pub struct SkOption {
    /// Option name.
    pub name: *mut c_char,
    /// Option value.
    pub value: *mut c_char,
    /// Whether the provider must fail if it does not understand the option.
    pub required: u8,
}

/// Runs `f`, converting any panic into an error code.
///
/// Unwinding across an FFI boundary is undefined behaviour, so nothing may
/// escape (PROJECT.md §10).
///
/// One caveat that cannot be fixed from here: the default panic hook prints to
/// stderr *before* this catches anything, and `ssh-sk-helper` uses stderr to
/// talk to `ssh-keygen`. Installing our own hook would silence that, but a hook
/// is process-global state, which §10 forbids in this library — we would be
/// mutating the host process's behaviour behind its back. A panic here is a bug
/// either way; the barrier keeps it from becoming undefined behaviour as well.
fn guard<F: FnOnce() -> i32>(f: F) -> i32 {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(code) => code,
        Err(_) => SSH_SK_ERR_GENERAL,
    }
}

/// Reads a C string, rejecting null and invalid UTF-8.
///
/// # Safety
///
/// `ptr` must be null or point to a NUL-terminated string valid for reads.
unsafe fn c_str(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: delegated to this function's contract.
    let raw = unsafe { CStr::from_ptr(ptr) };
    raw.to_str().ok().map(str::to_owned)
}

use crate::usb::UsbClient;

/// The active transport selected for the transaction (USB prioritized, BLE fallback).
pub enum ActiveTransport {
    /// Direct USB CTAPHID connection.
    Usb(UsbClient),
    /// BLE connection via cryptick-daemon socket.
    Daemon(DaemonClient),
}

/// Connects and confirms the token is actually usable.
/// Prioritizes USB HID when plugged in, falling back to BLE via the daemon.
fn reachable_device() -> Result<ActiveTransport, i32> {
    let mut log = DebugLog::open();
    log.line(format_args!(
        "reachable_device called, checking USB first..."
    ));

    let force_ble = std::env::var("CRYPTICK_TRANSPORT").as_deref() == Ok("ble")
        || std::env::var("SSH_SK_FORCE_BLE").is_ok();

    // 1. Prioritize direct USB CTAPHID if token is plugged in (and BLE not forced)
    if !force_ble {
        if let Some(usb) = UsbClient::try_connect() {
            log.line(format_args!("reachable_device: connected via USB CTAPHID"));
            return Ok(ActiveTransport::Usb(usb));
        }
    }

    // 2. Fall back to BLE via daemon bridge
    log.line(format_args!(
        "reachable_device: using BLE daemon bridge (force_ble={force_ble})..."
    ));
    let mut client = match DaemonClient::connect(CONNECT_TIMEOUT) {
        Ok(c) => c,
        Err(e) => {
            log.line(format_args!("DaemonClient::connect error: {e}"));
            return Err(e.sk_error());
        }
    };
    let status = match client.device_status() {
        Ok(s) => s,
        Err(e) => {
            log.line(format_args!("device_status error: {e}"));
            return Err(e.sk_error());
        }
    };
    log.line(format_args!(
        "device_status: in_range={}, bonded={}",
        status.in_range, status.bonded
    ));
    if !status.in_range || !status.bonded {
        return Err(SSH_SK_ERR_DEVICE_NOT_FOUND);
    }
    Ok(ActiveTransport::Daemon(client))
}

/// Maps an SSH algorithm to its COSE identifier.
fn cose_alg(alg: u32) -> Option<i64> {
    match alg {
        SSH_SK_ECDSA => Some(COSE_ES256),
        SSH_SK_ED25519 => Some(COSE_EDDSA),
        _ => None,
    }
}

/// Runs one CTAP transaction against the active transport (USB or BLE).
fn transact(request: &ctap::Request) -> Result<ctap::Response, i32> {
    let mut log = DebugLog::open();
    // The request's *length*, never its body: the CBOR carries the
    // clientDataHash, rp id and any PIN/UV material (PROJECT.md §15.5).
    if log.is_enabled() {
        log.line(format_args!(
            "transact called with request len {}",
            request.encode().len()
        ));
    }
    let mut transport = reachable_device()?;
    let response = match &mut transport {
        ActiveTransport::Usb(usb) => {
            let r = usb.transact(request, OPERATION_TIMEOUT)?;
            log.line(format_args!("transact USB Ok: status={:?}", r.status));
            if !r.status.is_ok() {
                log.line(format_args!(
                    "transact USB returned error status: {:?}",
                    r.status
                ));
                return Err(SSH_SK_ERR_GENERAL);
            }
            r
        }
        ActiveTransport::Daemon(client) => {
            let r = match client.transact(request, OPERATION_TIMEOUT) {
                Ok(r) => {
                    log.line(format_args!("transact BLE Ok: status={:?}", r.status));
                    r
                }
                Err(e) => {
                    log.line(format_args!(
                        "transact BLE Err: {e}, sk_error={}",
                        e.sk_error()
                    ));
                    return Err(e.sk_error());
                }
            };
            if !r.status.is_ok() {
                return Err(SSH_SK_ERR_GENERAL);
            }
            r
        }
    };
    Ok(response)
}

/// Builds the enroll response OpenSSH will `freezero`.
///
/// Every buffer is `malloc`ed. If any allocation fails the partial structure is
/// released here — the caller never sees it, so nothing else can free it.
fn build_enroll_response(parsed: &MakeCredentialResponse) -> Result<*mut SkEnrollResponse, i32> {
    let public_key = parsed.public_key().map_err(|_| SSH_SK_ERR_GENERAL)?;
    let key_handle = parsed.credential_id().map_err(|_| SSH_SK_ERR_GENERAL)?;

    let out = zeroed_struct::<SkEnrollResponse>();
    if out.is_null() {
        return Err(SSH_SK_ERR_GENERAL);
    }

    // SAFETY: `out` is a non-null, zeroed SkEnrollResponse. Every pointer
    // written below is either a fresh malloc or left null, and on any failure
    // the whole structure is freed before returning.
    unsafe {
        (*out).flags = parsed.auth_data.flags;

        (*out).public_key = to_c_buffer(&public_key);
        (*out).public_key_len = public_key.len();
        (*out).key_handle = to_c_buffer(key_handle);
        (*out).key_handle_len = key_handle.len();
        (*out).signature = to_c_buffer(&parsed.signature);
        (*out).signature_len = parsed.signature.len();
        (*out).authdata = to_c_buffer(&parsed.auth_data_raw);
        (*out).authdata_len = parsed.auth_data_raw.len();

        if let Some(cert) = &parsed.attestation_cert {
            (*out).attestation_cert = to_c_buffer(cert);
            (*out).attestation_cert_len = cert.len();
        }

        if (*out).public_key.is_null()
            || (*out).key_handle.is_null()
            || (*out).signature.is_null()
            || (*out).authdata.is_null()
            || (parsed.attestation_cert.is_some() && (*out).attestation_cert.is_null())
        {
            free_enroll_response(out);
            return Err(SSH_SK_ERR_GENERAL);
        }
    }
    Ok(out)
}

/// Releases a partially built enroll response.
///
/// # Safety
///
/// `out` must be a non-null structure from [`build_enroll_response`] that has
/// not been handed to OpenSSH.
unsafe fn free_enroll_response(out: *mut SkEnrollResponse) {
    // SAFETY: delegated to this function's contract; every field is either
    // null or a single malloc, and the struct is freed last.
    unsafe {
        free((*out).public_key.cast());
        free((*out).key_handle.cast());
        free((*out).signature.cast());
        free((*out).attestation_cert.cast());
        free((*out).authdata.cast());
        free(out.cast());
    }
}

/// Splits an assertion signature the way OpenSSH's own middleware does.
///
/// ECDSA is DER and splits into minimal big-endian `r` and `s`. **Ed25519 does
/// not split**: all 64 bytes go in `sig_r` and `sig_s` is left null
/// (`sk-usbhid.c`, `pack_sig_ed25519`). Getting that backwards produces a
/// signature that verifies nowhere.
fn build_sign_response(
    alg: u32,
    parsed: &GetAssertionResponse,
) -> Result<*mut SkSignResponse, i32> {
    let (r, s) = match alg {
        SSH_SK_ECDSA => {
            let (r, s) =
                split_ecdsa_signature(&parsed.signature).map_err(|_| SSH_SK_ERR_GENERAL)?;
            (r, Some(s))
        }
        SSH_SK_ED25519 => {
            if parsed.signature.len() != 64 {
                return Err(SSH_SK_ERR_GENERAL);
            }
            (parsed.signature.clone(), None)
        }
        _ => return Err(SSH_SK_ERR_UNSUPPORTED),
    };

    let out = zeroed_struct::<SkSignResponse>();
    if out.is_null() {
        return Err(SSH_SK_ERR_GENERAL);
    }

    // SAFETY: `out` is a non-null, zeroed SkSignResponse; the same allocation
    // and unwinding discipline as build_enroll_response.
    unsafe {
        (*out).flags = parsed.auth_data.flags;
        (*out).counter = parsed.auth_data.sign_count;

        (*out).sig_r = to_c_buffer(&r);
        (*out).sig_r_len = r.len();
        if let Some(s) = &s {
            (*out).sig_s = to_c_buffer(s);
            (*out).sig_s_len = s.len();
        }

        if (*out).sig_r.is_null() || (s.is_some() && (*out).sig_s.is_null()) {
            free((*out).sig_r.cast());
            free((*out).sig_s.cast());
            free(out.cast());
            return Err(SSH_SK_ERR_GENERAL);
        }
    }
    Ok(out)
}

/// Returns the SK API version this middleware implements.
///
/// `ssh-sk-helper` calls this first and refuses to go further if the major
/// version does not match its own.
#[no_mangle]
pub extern "C" fn sk_api_version() -> u32 {
    SSH_SK_VERSION_MAJOR
}

/// Creates a credential.
///
/// # Safety
///
/// Called by `ssh-sk-helper` per `sk-api.h`: `challenge` must be valid for
/// `challenge_len` bytes, `application` and `pin` must be null or valid C
/// strings, and `enroll_response` must be a valid place to store one pointer.
#[no_mangle]
pub unsafe extern "C" fn sk_enroll(
    alg: u32,
    challenge: *const u8,
    challenge_len: usize,
    application: *const c_char,
    flags: u8,
    _pin: *const c_char,
    _options: *mut *mut SkOption,
    enroll_response: *mut *mut SkEnrollResponse,
) -> i32 {
    guard(|| {
        if !enroll_response.is_null() {
            // Never leave a stale pointer where the caller expects a result.
            // SAFETY: the caller guarantees this is a writable location.
            unsafe { *enroll_response = std::ptr::null_mut() };
        }
        let Some(alg) = cose_alg(alg) else {
            return SSH_SK_ERR_UNSUPPORTED;
        };
        if challenge.is_null() || challenge_len == 0 || enroll_response.is_null() {
            return SSH_SK_ERR_GENERAL;
        }
        // SAFETY: the caller guarantees `application` is null or a valid C
        // string, per sk-api.h.
        let Some(rp_id) = (unsafe { c_str(application) }) else {
            return SSH_SK_ERR_GENERAL;
        };
        // SAFETY: the caller guarantees `challenge` is readable for
        // `challenge_len` bytes, which was checked non-zero above.
        let challenge = unsafe { std::slice::from_raw_parts(challenge, challenge_len) };

        let request = MakeCredential {
            // Hashed inside `encode`. OpenSSH's challenge is not a
            // clientDataHash, and passing it through would produce a
            // credential that verifies against nothing.
            challenge,
            rp_id: &rp_id,
            user_id: &ctap_client::request::DEFAULT_USER_ID,
            alg,
            resident_key: flags & SSH_SK_RESIDENT_KEY != 0,
            user_verification: flags & SSH_SK_USER_VERIFICATION_REQD != 0,
        }
        .encode();

        let response = match transact(&request) {
            Ok(response) => response,
            Err(code) => return code,
        };
        let parsed = match MakeCredentialResponse::parse(&response.data) {
            Ok(p) => p,
            Err(e) => {
                // The error and the length, not the body. This previously
                // hex-dumped the whole authenticatorMakeCredential response,
                // which PROJECT.md §15.5 forbids — and `ResponseError`
                // already names the member that would not parse, which is
                // the part that actually diagnoses this.
                DebugLog::open().line(format_args!(
                    "MakeCredentialResponse::parse failed: {e}, data len={}",
                    response.data.len()
                ));
                return SSH_SK_ERR_GENERAL;
            }
        };
        match build_enroll_response(&parsed) {
            Ok(out) => {
                // SAFETY: checked non-null above; ownership passes to OpenSSH,
                // which releases it with freezero.
                unsafe { *enroll_response = out };
                0
            }
            Err(code) => code,
        }
    })
}

/// Signs a challenge with an existing credential.
///
/// # Safety
///
/// As `sk_enroll`: `data` must be valid for `data_len` bytes, `key_handle` for
/// `key_handle_len`, string pointers must be null or valid C strings, and
/// `sign_response` must be a valid place to store one pointer.
#[no_mangle]
pub unsafe extern "C" fn sk_sign(
    alg: u32,
    data: *const u8,
    data_len: usize,
    application: *const c_char,
    key_handle: *const u8,
    key_handle_len: usize,
    flags: u8,
    _pin: *const c_char,
    _options: *mut *mut SkOption,
    sign_response: *mut *mut SkSignResponse,
) -> i32 {
    guard(|| {
        if !sign_response.is_null() {
            // SAFETY: the caller guarantees this is a writable location.
            unsafe { *sign_response = std::ptr::null_mut() };
        }
        if cose_alg(alg).is_none() {
            return SSH_SK_ERR_UNSUPPORTED;
        }
        if data.is_null()
            || data_len == 0
            || key_handle.is_null()
            || key_handle_len == 0
            || sign_response.is_null()
        {
            return SSH_SK_ERR_GENERAL;
        }
        // SAFETY: the caller guarantees `application` is null or a valid C string.
        let Some(rp_id) = (unsafe { c_str(application) }) else {
            return SSH_SK_ERR_GENERAL;
        };
        // SAFETY: both lengths were checked non-zero, and the caller
        // guarantees each pointer is readable for its stated length.
        let (challenge, credential_id) = unsafe {
            (
                std::slice::from_raw_parts(data, data_len),
                std::slice::from_raw_parts(key_handle, key_handle_len),
            )
        };

        let request = GetAssertion {
            challenge,
            rp_id: &rp_id,
            credential_id,
            user_verification: flags & SSH_SK_USER_VERIFICATION_REQD != 0,
        }
        .encode();

        let response = match transact(&request) {
            Ok(response) => response,
            Err(code) => return code,
        };
        let Ok(parsed) = GetAssertionResponse::parse(&response.data) else {
            return SSH_SK_ERR_GENERAL;
        };
        match build_sign_response(alg, &parsed) {
            Ok(out) => {
                // SAFETY: checked non-null above; ownership passes to OpenSSH.
                unsafe { *sign_response = out };
                0
            }
            Err(code) => code,
        }
    })
}

/// Enumerates discoverable credentials.
///
/// # Safety
///
/// `pin` must be null or a valid C string; `rks` and `nrks` must be valid
/// places to store a pointer and a length.
#[no_mangle]
pub unsafe extern "C" fn sk_load_resident_keys(
    _pin: *const c_char,
    _options: *mut *mut SkOption,
    rks: *mut *mut *mut SkResidentKey,
    nrks: *mut usize,
) -> i32 {
    guard(|| {
        if rks.is_null() || nrks.is_null() {
            return SSH_SK_ERR_GENERAL;
        }
        // SAFETY: the caller guarantees both are writable locations.
        unsafe {
            *rks = std::ptr::null_mut();
            *nrks = 0;
        }

        let _client = match reachable_device() {
            Ok(client) => client,
            Err(code) => return code,
        };

        // Remaining: authenticatorCredentialManagement, which also needs a PIN
        // token -- and PROJECT.md §21 forbids the *daemon* implementing PIN/UV.
        // It belongs here, in the client, which is a design point worth
        // settling before this is written.
        SSH_SK_ERR_UNSUPPORTED
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_api_version_matches_the_header() {
        assert_eq!(sk_api_version(), 0x000a_0000);
        assert_eq!(
            sk_api_version() & crate::SSH_SK_VERSION_MAJOR_MASK,
            sk_api_version()
        );
    }

    #[test]
    fn the_structs_match_the_c_layout() {
        // If these drift, ssh-sk-helper reads our fields at the wrong offsets
        // and the failure is silent corruption rather than a link error.
        use std::mem::{align_of, size_of};
        assert_eq!(align_of::<SkEnrollResponse>(), align_of::<*mut u8>());
        assert_eq!(
            size_of::<SkEnrollResponse>(),
            // flags + 5 (ptr, len) pairs, with the leading byte padded out to
            // pointer alignment.
            size_of::<*mut u8>() * 11
        );
        assert_eq!(align_of::<SkSignResponse>(), align_of::<*mut u8>());
        assert_eq!(align_of::<SkOption>(), align_of::<*mut u8>());
    }

    #[test]
    fn algorithms_map_to_their_cose_identifiers() {
        assert_eq!(cose_alg(SSH_SK_ECDSA), Some(-7));
        assert_eq!(cose_alg(SSH_SK_ED25519), Some(-8));
        for alg in [2u32, 3, 0xffff_ffff] {
            assert_eq!(cose_alg(alg), None, "{alg}");
        }
    }

    #[test]
    fn a_panic_becomes_an_error_code_rather_than_unwinding_into_c() {
        let code = guard(|| panic!("this must not reach the caller"));
        assert_eq!(code, SSH_SK_ERR_GENERAL);
    }

    #[test]
    fn guard_passes_normal_returns_through() {
        assert_eq!(guard(|| 0), 0);
        assert_eq!(guard(|| SSH_SK_ERR_UNSUPPORTED), SSH_SK_ERR_UNSUPPORTED);
    }

    #[test]
    fn null_out_parameters_are_refused_not_dereferenced() {
        // SAFETY: passing null is exactly what is under test; the functions
        // must check before writing.
        unsafe {
            assert_eq!(
                sk_enroll(
                    SSH_SK_ECDSA,
                    [0u8; 32].as_ptr(),
                    32,
                    c"ssh:test".as_ptr(),
                    0,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                ),
                SSH_SK_ERR_GENERAL
            );
            assert_eq!(
                sk_load_resident_keys(
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                ),
                SSH_SK_ERR_GENERAL
            );
        }
    }

    #[test]
    fn an_unsupported_algorithm_short_circuits_before_touching_the_socket() {
        let mut out: *mut SkEnrollResponse = std::ptr::null_mut();
        // SAFETY: all pointers below are valid for their stated lengths.
        let code = unsafe {
            sk_enroll(
                0xdead,
                [0u8; 32].as_ptr(),
                32,
                c"ssh:test".as_ptr(),
                0,
                std::ptr::null(),
                std::ptr::null_mut(),
                &mut out,
            )
        };
        assert_eq!(code, SSH_SK_ERR_UNSUPPORTED);
        assert!(out.is_null(), "no response may be left behind on failure");
    }
}
