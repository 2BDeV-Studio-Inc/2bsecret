use anyhow::{anyhow, Result};
use twobsecret::App; 

fn main() -> Result<()> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "2BSecret",
        options,
        Box::new(|_cc| Box::new(App::default())),
    )
    .map_err(|e| anyhow!(e.to_string()))?;
    Ok(())
}