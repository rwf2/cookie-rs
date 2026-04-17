fn main() {
    println!("cargo:rustc-check-cfg=cfg(nightly)");

    if let Some(true) = version_check::supports_feature("doc_cfg") {
        println!("cargo:rustc-cfg=nightly");
    }
}
