//! Handing buffers to C.
//!
//! OpenSSH releases our responses with `freezero()` — `explicit_bzero()` then
//! `free()`. So every pointer we return must come from `malloc`. Rust's global
//! allocator happens to sit on `malloc` on the platforms we target, but that is
//! an implementation detail and not a contract; mixing allocators across an FFI
//! boundary is undefined behaviour whether or not it happens to work today.

use std::ffi::c_void;

/// Copies `bytes` into a `malloc`ed buffer the caller must `free`.
///
/// Returns a null pointer if the allocation fails, which the callers here treat
/// as a general error rather than dereferencing.
///
/// An empty slice still allocates one byte: OpenSSH's `freezero(p, 0)` is happy
/// with either, but returning null for "empty" would be indistinguishable from
/// "allocation failed" at the call site.
pub fn to_c_buffer(bytes: &[u8]) -> *mut u8 {
    let size = bytes.len().max(1);
    // SAFETY: `size` is non-zero. The result is checked for null before use,
    // and the copy below writes exactly `bytes.len()` bytes into an allocation
    // of at least that size.
    let ptr = unsafe { libc::malloc(size) } as *mut u8;
    if ptr.is_null() {
        return ptr;
    }
    // SAFETY: `ptr` is non-null and owns at least `bytes.len()` bytes, and the
    // source and destination cannot overlap since `ptr` was just allocated.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
    }
    ptr
}

/// Allocates a zeroed `T` with `malloc`, for a struct C will `free`.
///
/// Returns null if the allocation fails.
pub fn zeroed_struct<T>() -> *mut T {
    // SAFETY: size_of::<T>() is non-zero for every struct used here, and
    // calloc zeroes the allocation so no field is left uninitialised. The
    // result is null-checked by every caller.
    unsafe { libc::calloc(1, std::mem::size_of::<T>()) as *mut T }
}

/// Frees a `malloc`ed buffer.
///
/// Used only to unwind a partially built response after a later allocation
/// fails; anything successfully returned belongs to OpenSSH.
///
/// # Safety
///
/// `ptr` must be null, or a pointer returned by [`to_c_buffer`] or
/// [`zeroed_struct`] that has not already been freed.
pub unsafe fn free(ptr: *mut c_void) {
    if !ptr.is_null() {
        // SAFETY: delegated to the caller by this function's contract.
        unsafe { libc::free(ptr) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_buffer_round_trips_through_c_memory() {
        let source = [0xde, 0xad, 0xbe, 0xef];
        let ptr = to_c_buffer(&source);
        assert!(!ptr.is_null());
        // SAFETY: `ptr` owns 4 bytes copied from `source` just above.
        let seen = unsafe { std::slice::from_raw_parts(ptr, source.len()) };
        assert_eq!(seen, source);
        // SAFETY: `ptr` came from `to_c_buffer` and is freed exactly once.
        unsafe { free(ptr as *mut c_void) };
    }

    #[test]
    fn an_empty_slice_still_allocates() {
        // Otherwise "empty" and "allocation failed" are the same value.
        let ptr = to_c_buffer(&[]);
        assert!(!ptr.is_null());
        // SAFETY: `ptr` came from `to_c_buffer` and is freed exactly once.
        unsafe { free(ptr as *mut c_void) };
    }

    #[test]
    fn a_struct_comes_back_zeroed() {
        #[repr(C)]
        struct Thing {
            a: u64,
            b: *mut u8,
            c: usize,
        }
        let ptr = zeroed_struct::<Thing>();
        assert!(!ptr.is_null());
        // SAFETY: `zeroed_struct` returned a non-null, calloc-zeroed Thing.
        unsafe {
            assert_eq!((*ptr).a, 0);
            assert!((*ptr).b.is_null());
            assert_eq!((*ptr).c, 0);
            free(ptr as *mut c_void);
        }
    }

    #[test]
    fn freeing_null_is_a_no_op() {
        // SAFETY: null is explicitly permitted by the contract.
        unsafe { free(std::ptr::null_mut()) };
    }
}
