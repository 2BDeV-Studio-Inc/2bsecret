// Build script: Windows célplatformon beágyazza a manifestet (asInvoker, nem kér
// rendszergazdai jogot) a kész .exe-be. Más célplatformon nem csinál semmit.
//
// A Cargo.toml-ban már szereplő `winres = "0.1"` build-dependency-t használja,
// új függőség nem kell. A "2bsecret.exe.manifest" fájlnak a projektgyökérben kell
// lennie. A korábbi `2bsecret-manifest.rc` ehhez már nem kell: a windres a
// build könyvtárban fut, ahol az .rc relatív útvonalai nem oldódnak fel, ezért a
// manifestet abszolút útvonallal adjuk át, és a winres generálja az .rc-t.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=2bsecret.exe.manifest");

    // A build.rs a gazdagépen fut, ezért a CÉLPLATFORMOT a Cargo env-jéből
    // nézzük (cfg! itt a host-ot jelenti, és keresztfordításnál téves lenne).
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winres::WindowsResource::new();

        // Nem-Windows gazdagépen (Linux/macOS keresztfordítás) a winres a sima
        // `windres`/`ar` nevet keresné a PATH-on, MinGW-nél viszont ezek
        // célplatform-előtaggal települnek (pl. x86_64-w64-mingw32-windres).
        // `cfg!(windows)` itt a gazdagépet jelenti, ami pont jó.
        if !cfg!(windows) {
            let prefix = match std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
                Ok("x86") => "i686-w64-mingw32",
                _ => "x86_64-w64-mingw32",
            };
            res.set_windres_path(&format!("{prefix}-windres"));
            res.set_ar_path(&format!("{prefix}-ar"));
        }

        let manifest_dir =
            std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is always set by Cargo");
        let manifest = std::path::Path::new(&manifest_dir).join("2bsecret.exe.manifest");
        res.set_manifest_file(
            manifest
                .to_str()
                .expect("manifest path must be valid UTF-8"),
        );

        res.compile()
            .expect("failed to embed the Windows manifest resource");

        // MinGW (gnu) célon a winres a resource objektumot statikus könyvtárként
        // linkeli, amiből a linker csak a hivatkozott tagokat veszi be — a
        // resource.o-ra pedig semmi nem hivatkozik, így a manifest csendben
        // kimaradna az .exe-ből. A whole-archive kikényszeríti a beemelését.
        if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("gnu") {
            println!("cargo:rustc-link-arg-bins=-Wl,--whole-archive");
            println!("cargo:rustc-link-arg-bins=-lresource");
            println!("cargo:rustc-link-arg-bins=-Wl,--no-whole-archive");
        }
    }
}
