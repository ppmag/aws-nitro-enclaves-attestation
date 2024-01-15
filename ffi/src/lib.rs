use aws_nitro_enclaves_attestation as nitro;
use libc::*;
use std::{ffi::CString};

// if AD verification succeed, then return payload as JSON encoded string
// return NULL otherwise

#[no_mangle]
pub unsafe extern "C" fn na_ad_get_verified_payload_as_json(
    ad_blob_ptr: *const u8,
    len: usize,
    root_cert_der_ptr: *const u8,
    root_cert_der_len: usize,
    unix_ts_sec: u64,
    address_document_or_error: *mut *mut c_char,
) -> u8 {
    // ad document ptr & len
    if ad_blob_ptr.is_null() {
        *address_document_or_error = CString::from_vec_unchecked("Attestation document is null".as_bytes().to_vec()).into_raw();
        return 1;
    }
    let slice = std::slice::from_raw_parts(ad_blob_ptr, len);
    let ad_boxed_slice: Box<[u8]> = Box::from(slice);

    // root cert (in DER format) ptr & len
    if root_cert_der_ptr.is_null() {
        *address_document_or_error = CString::from_vec_unchecked("Root cert is null.".as_bytes().to_vec()).into_raw();
        return 2;
    }
    let slice = std::slice::from_raw_parts(root_cert_der_ptr, root_cert_der_len);
    let cert_boxed_slice: Box<[u8]> = Box::from(slice);

    // call Rust lib
    let nitro_addoc =
        match nitro::NitroAdDoc::from_bytes(&ad_boxed_slice, &cert_boxed_slice, unix_ts_sec) {
            Ok(v) => v,
            Err(e) => {
                let error_prefix = "Error while parsing attestation document: ".to_owned();
                match e {
                    nitro::NitroAdError::Error(error) => {
                        *address_document_or_error = CString::from_vec_unchecked((error_prefix + &error).as_bytes().to_vec()).into_raw();
                    },
                    nitro::NitroAdError::COSEError(_error) => {
                        *address_document_or_error = CString::from_vec_unchecked((error_prefix + "COSE error").as_bytes().to_vec()).into_raw()
                    },
                    nitro::NitroAdError::CBORError(error) => {
                        *address_document_or_error = CString::from_vec_unchecked((error_prefix + &error.to_string()).as_bytes().to_vec()).into_raw();
                    },
                    nitro::NitroAdError::SerializationError(error) => {
                        *address_document_or_error = CString::from_vec_unchecked((error_prefix + &error.to_string()).as_bytes().to_vec()).into_raw();
                    },
                    #[cfg(not(target_arch = "wasm32"))]
                    nitro::NitroAdError::VerificationError(error) => {
                        *address_document_or_error = CString::from_vec_unchecked((error_prefix + &error.to_string()).as_bytes().to_vec()).into_raw();
                    },
                    _ => {
                        *address_document_or_error = CString::from_vec_unchecked((error_prefix + &e.to_string()).as_bytes().to_vec()).into_raw();
                    }
                }
                return 3;
            } // [TODO] add C API call to get Last Error with message
        };

    let js = match nitro_addoc.to_json() {
        Ok(v) => v,
        Err(e) => {
            let error_prefix = "Error while converting attestation document to json: ".to_owned();
            match e {
                nitro::NitroAdError::Error(error) => {
                    *address_document_or_error = CString::from_vec_unchecked((error_prefix + &error).as_bytes().to_vec()).into_raw();
                },
                nitro::NitroAdError::COSEError(_error) => {
                    *address_document_or_error = CString::from_vec_unchecked((error_prefix + "COSE error").as_bytes().to_vec()).into_raw()
                },
                nitro::NitroAdError::CBORError(error) => {
                    *address_document_or_error = CString::from_vec_unchecked((error_prefix + &error.to_string()).as_bytes().to_vec()).into_raw();
                },
                nitro::NitroAdError::SerializationError(error) => {
                    *address_document_or_error = CString::from_vec_unchecked((error_prefix + &error.to_string()).as_bytes().to_vec()).into_raw();
                },
                #[cfg(not(target_arch = "wasm32"))]
                nitro::NitroAdError::VerificationError(error) => {
                    *address_document_or_error = CString::from_vec_unchecked((error_prefix + &error.to_string()).as_bytes().to_vec()).into_raw();
                },
                _ => {
                    *address_document_or_error = CString::from_vec_unchecked((error_prefix + &e.to_string()).as_bytes().to_vec()).into_raw();
                }
            }
            return 4;
        }
    };

    let c_str = CString::from_vec_unchecked(js.as_bytes().to_vec());

    *address_document_or_error = c_str.into_raw();
    0
}

#[no_mangle]
pub unsafe extern "C" fn na_str_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }

    drop(CString::from_raw(ptr));
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
                  return 2;
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

    #[test]
    #[rustfmt::skip]
    fn c_failure_current_time_in_the_future() {
        (assert_c! {
            //====================================================================================
            #include <stdio.h>
            #include "nitroattest.h"
            #include "test_data.h"

            int main() {

                const char* s = na_ad_get_verified_payload_as_json( __nitro_ad_debug_bin, __nitro_ad_debug_bin_len,
                                                                   __aws_root_der, __aws_root_der_len,
                                                                   1614997200ULL );  // time in the future
                if (!s) {
                  fprintf(stderr, "Unable to pass verification process and obtain payload from specified AD!\n");  
                  return 2;
                }

                printf("AD payload: \n\n %s \n", s );
                na_str_free( (char*)s);
                
                return 0;
            }
            //====================================================================================
        })
        .failure()
        .code(2);
    }
}
