use libc::*;
use aws_nitro_enclaves_attestation;

#[repr(C)]
pub struct Slice_c_char {
    pointer: *const c_char,
    length: usize
}

#[no_mangle]
pub extern "C" fn parse_ress(pointer: *const c_char) -> c_int {

    (2+2)
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

                printf("parse: %d \n", parse_ress(0) );
                
                return 0;
            }
            //====================================================================================
        })
        .success()
        .stdout("parse: 4 \n");

    }
}
