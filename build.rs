fn main() {
    println!("cargo:rerun-if-changed=app.rc");
    if std::env::var("CARGO_CFG_TARGET_OS").map(|s| s == "windows").unwrap_or(false) {
        embed_resource::compile("app.rc", embed_resource::NONE);
    }
}
