use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let output_dir = PathBuf::from(&crate_dir).join("include");
    
    // Create include directory
    std::fs::create_dir_all(&output_dir).expect("Failed to create include directory");

    // Generate C header with cbindgen
    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_language(cbindgen::Language::C)
        .with_pragma_once(true)
        .with_include_guard("MAYAQUA_FFI_H")
        .with_documentation(true)
        .with_cpp_compat(true)
        .with_sys_include("stdint.h")
        .with_sys_include("stdbool.h")
        .generate()
        .expect("Unable to generate C bindings")
        .write_to_file(output_dir.join("mayaqua_ffi.h"));
    
    println!("cargo:rerun-if-changed=src/ffi.rs");
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=build.rs");
}
