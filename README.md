# aws-nitro-enclaves-attestation
Attestation primitives and utilities Rust library (with C/C++ bindings) for use in AWS Nitro Enclave applications.

This library is usefull for developing C/C++ AWS Nitro Enclave applications with custom functionality like enclave-to-enclave 
secure communication and mutual attestation.

Unfortunately, AWS Nitro Enclaves SDK for this moment has a lot of gaps in functionality. 

This library is trying to fill them. 

# How to use

After
```bash
cargo build --all
```
you can find C headers and `nitroattest.so`, `nitroattest.a` library files in your target build dir.

For inline C language test snippet just look inside the `./ffi/src/lib.rs`

# Status

Ready to use. Basic unit test coverage. 
Production NOT ready. Alpha. Still under development.

Third-party audition required.

# Features

Feel free to open new issue with your proposals.

# Dependencies

* Attestation document parsing & COSE Signature validation:

[aws-nitro-enclaves-cose](https://crates.io/crates/aws-nitro-enclaves-cose)

* X.509 Certificate Validation: 

[webpki](https://crates.io/crates/webpki) 
