use cbindgen;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
//use std::{ffi::OsStr};

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_dir = env::var_os("OUT_DIR").unwrap();

    let dest_dir = Path::new(&out_dir).join("../../../headers/");
    let dest_path = Path::new(&dest_dir).join("nitroattest.h");

    /*cbindgen::Builder::new()
            .with_crate(crate_dir)
            .with_language(cbindgen::Language::C)
            .generate()
            .expect("Unable to generate bindings")
            .write_to_file(dest_path);
    */

    cbindgen::generate(crate_dir)
        .expect("Unable to generate bindings")
        .write_to_file(dest_path);

    let include_dir = dest_dir.as_path().to_string_lossy(); //env::var("CARGO_MANIFEST_DIR").unwrap();

    let mut shared_object_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    shared_object_dir.push(".."); // we need workspace dir
    shared_object_dir.push("target");
    shared_object_dir.push(env::var("PROFILE").unwrap());
    let shared_object_dir = shared_object_dir.as_path().to_string_lossy();

    // The following options mean:
    //
    // * `-I`, add `include_dir` to include search path,
    // * `-L`, add `shared_object_dir` to library search path,
    // * `-D_DEBUG`, enable debug mode to enable `assert.h`.
    println!(
        "cargo:rustc-env=INLINE_C_RS_CFLAGS=-I{I} -L{L} -D_DEBUG",
        I = include_dir,
        L = shared_object_dir.clone(),
    );

    // Here, we pass the fullpath to the shared object with
    // `LDFLAGS`.
    println!(
        "cargo:rustc-env=INLINE_C_RS_LDFLAGS={shared_object_dir}/{lib}",
        shared_object_dir = shared_object_dir,
        lib = if cfg!(target_os = "windows") {
            "nitroattest.dll".to_string()
        } else if cfg!(target_os = "macos") {
            "libnitroattest.dylib".to_string()
        } else {
            //"libfoo.so".to_string()
            "libnitroattest.so".to_string()
        }
    );
}
