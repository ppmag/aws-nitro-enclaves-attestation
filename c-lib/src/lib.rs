use libc::*;
use aws_nitro_enclaves_attestation;

#[repr(C)]
pub struct Slice_c_char {
    pointer: *const c_char,
    length: usize
}

#[no_mangle]
pub extern "C" fn parse(pointer: *const c_char) -> c_int {

    2
}

/*
#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
*/