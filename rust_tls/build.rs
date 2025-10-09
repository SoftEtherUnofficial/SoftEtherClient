// Build script for softether_tls
// This ensures rustls-ffi headers are available

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    
    // rustls-ffi will automatically generate headers via cbindgen
    // during its build process
}
