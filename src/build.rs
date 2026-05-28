fn main() {
    if cfg!(target_os = "windows") {
        let mut res = winres::WindowsResource::new();
        res.set_icon("wix/AppIcon.ico");
        res.set_manifest_file("2bsecret.exe.manifest");
        res.set_product_name("2bsecret");
        res.set_company_name("2BDeV Studio");
        res.compile().unwrap();
    }
}