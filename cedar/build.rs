use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let output_dir = PathBuf::from(&crate_dir).join("../include");

    // Create include directory if it doesn't exist
    std::fs::create_dir_all(&output_dir).expect("Failed to create include directory");

    let config = cbindgen::Config::from_file("cbindgen.toml")
        .expect("Failed to load cbindgen config");

    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(config)
        .generate()
        .expect("Unable to generate C bindings")
        .write_to_file(output_dir.join("cedar_ffi.h"));

    println!("cargo:rerun-if-changed=src/ffi.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");
}
