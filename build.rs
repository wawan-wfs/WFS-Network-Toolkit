fn main() {
    println!("cargo:rerun-if-changed=assets/wfs.rc");
    println!("cargo:rerun-if-changed=assets/wfs.manifest");
    println!("cargo:rerun-if-changed=assets/WFS-Network-Toolkit.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        embed_resource::compile_for(
            "assets/wfs.rc",
            ["WFS-Network-Toolkit"],
            embed_resource::NONE,
        )
        .manifest_required()
        .expect("embed WFS application icon");
    }
}
