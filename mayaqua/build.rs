use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let output_dir = PathBuf::from(&crate_dir).join("include");

    // Create include directory
    std::fs::create_dir_all(&output_dir).expect("Failed to create include directory");

    // Generate C header with cbindgen (using cbindgen.toml config)
    // Note: Temporarily disabled due to config.rs serde attributes causing parse errors
    // We'll add config FFI exports manually later
    match cbindgen::generate(&crate_dir) {
        Ok(bindings) => {
            bindings.write_to_file(output_dir.join("mayaqua_ffi.h"));
        }
        Err(e) => {
            eprintln!("Warning: cbindgen failed ({}), using fallback header", e);
            // Create minimal header
            std::fs::write(
                output_dir.join("mayaqua_ffi.h"),
                b"/* Mayaqua FFI - See individual module headers */\n",
            )
            .ok();
        }
    }

    println!("cargo:rerun-if-changed=src/ffi.rs");
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=build.rs");
}
