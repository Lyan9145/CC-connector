fn main() {
    // Embed the app icon into ccc.exe (shown in Explorer and the taskbar).
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/icon.ico");
        res.set("ProductName", "CC-connector");
        res.set("FileDescription", "CC-connector");
        if let Err(e) = res.compile() {
            println!("cargo:warning=could not embed Windows icon: {e}");
        }
    }
    println!("cargo:rerun-if-changed=assets/icon.ico");
}
