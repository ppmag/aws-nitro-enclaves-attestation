use aws_nitro_enclaves_attestation as nitro;
use libc::*;
use std::ffi::CString;

// if AD verification succeed, then return payload as JSON encoded string
// return NULL otherwise

#[no_mangle]
pub unsafe extern "C" fn na_ad_get_verified_payload_as_json(
    ad_blob_ptr: *const u8,
    len: usize,
    root_cert_der_ptr: *const u8,
    root_cert_der_len: usize,
    unix_ts_sec: u64,
) -> *const c_char {

    // ad document ptr & len
    if ad_blob_ptr.is_null() {
        return std::ptr::null();
    }
    let slice = std::slice::from_raw_parts(ad_blob_ptr, len);
    let ad_boxed_slice: Box<[u8]> = Box::from(slice);

    // root cert (in DER format) ptr & len
    if root_cert_der_ptr.is_null() {
        return std::ptr::null();
    }
    let slice = std::slice::from_raw_parts(root_cert_der_ptr, root_cert_der_len);
    let cert_boxed_slice: Box<[u8]> = Box::from(slice);

    // call Rust lib
    let nitro_addoc =
        nitro::NitroAdDoc::from_bytes(&ad_boxed_slice, &cert_boxed_slice, unix_ts_sec).unwrap();
    let js = nitro_addoc.to_json().unwrap();

    let c_str = CString::from_vec_unchecked(js.as_bytes().to_vec());

    c_str.into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn na_str_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }

    CString::from_raw(ptr);
}

#[cfg(test)]
mod tests {
    use inline_c::assert_c;

    #[test]
    #[rustfmt::skip]
    fn c_basic_interfacing() {
        (assert_c! {
            //====================================================================================
            #include <stdio.h>
            #include "nitroattest.h"
            #include "test_data.h"

            int main() {

                const char* s = na_ad_get_verified_payload_as_json( __nitro_ad_debug_bin, __nitro_ad_debug_bin_len,
                                                                   __aws_root_der, __aws_root_der_len,
                                                                   1614967200ULL );
                if (!s) {
                  fprintf(stderr, "Unable to pass verification process and obtain payload from specified AD!\n");  
                  return -1;
                }

                printf("AD payload: \n\n %s \n", s );
                na_str_free( (char*)s);
                
                return 0;
            }
            //====================================================================================
        })
        .success();
        //.stdout("");
    }
}
