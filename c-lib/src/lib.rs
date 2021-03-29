use libc::*;
use aws_nitro_enclaves_attestation;
use std::ffi::CString;

#[repr(C)]
pub struct Slice_c_char {
    pointer: *const c_char,
    length: usize
}

// if AD verification succeed, then return payload as JSON encoded string
// return NULL otherwise

#[no_mangle]
pub extern "C" fn na_ad_get_verified_payload_as_json(ad_blob_ptr: *const u8) ->  *const c_char {

    //if ptr.is_null() {
    //    return;

    let c_str = CString::new("{\"a\": 3}").unwrap();

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

    use std::env::{set_var, remove_var};
    use inline_c::assert_c;

    #[test]
    fn it_works_www() {

        (assert_c! {
            //====================================================================================
            #include <stdio.h>
            #include "nitroattest.h"
    
            int main() {

                const char* s = na_ad_get_verified_payload_as_json(0);
                printf("parse: %s \n", s );

                na_str_free( (char*)s);
                
                return 0;
            }
            //====================================================================================
        })
        .success();
        //.stdout("parse: {\"a\": 3}\n");

    }
}
