//! 1. fázis: a megosztás felülete (névjegyek, meghívó, többcímzetteses
//! titkosítás, ismeretlen feladó kezelése). Az `App` állapotát bővíti, a
//! tényleges műveleteket a `sharing` modul végzi.

use super::*;

const WARN: egui::Color32 = egui::Color32::from_rgb(220, 140, 0);
const GOOD: egui::Color32 = egui::Color32::from_rgb(60, 170, 90);
const BAD: egui::Color32 = egui::Color32::from_rgb(220, 70, 70);

/// Mit választott a felhasználó az ismeretlen feladó párbeszédben?
enum UnknownChoice {
    AddAndDecrypt,
    DecryptOnce,
    Cancel,
}

fn short_fp(fp: &str) -> String {
    format_fingerprint(&fp[..fp.len().min(16)])
}

impl App {
    /// A névjegyek és a saját ujjlenyomat újratöltése lemezről.
    pub(crate) fn refresh_sharing_state(&mut self) {
        match load_contacts(&self.device_dir) {
            Ok(list) => {
                self.contacts = list;
                self.contacts_error = None;
            }
            Err(e) => {
                self.contacts.clear();
                self.contacts_error = Some(format!("{e:#}"));
            }
        }
        let contacts = &self.contacts;
        self.selected_contacts
            .retain(|fp| contacts.iter().any(|c| &c.fingerprint == fp));
        if let Some(fp) = &self.safety_view {
            if !self.contacts.iter().any(|c| &c.fingerprint == fp) {
                self.safety_view = None;
            }
        }
        self.own_fingerprint = own_identity_fingerprint(&self.device_dir).ok();
    }

    /// A kiválasztott fájl visszafejtése; v3–v5 fájlnál a régi úton, v6-nál a
    /// feladó ellenőrzésével. Ismeretlen feladónál a párbeszédet nyitja meg.
    pub(crate) fn decrypt_selected_file(&mut self, policy: SenderPolicy) {
        let Some(path) = self.selected_file.clone() else {
            self.status = "Select a file first.".to_string();
            return;
        };
        if self.master_password.is_empty() {
            self.status = "Enter the master password first.".to_string();
            return;
        }
        let version = match peek_file_version(&path) {
            Ok(v) => v,
            Err(e) => {
                self.status = format!("Decrypt error: {e:#}");
                return;
            }
        };
        if version != 6 {
            self.pending_unknown = None;
            match decrypt_on_this_device(&path, &self.device_dir, self.master_password.as_bytes()) {
                Ok(out) => self.status = format!("Decrypted to: {}", out.display()),
                Err(e) => self.status = format!("Decrypt error: {e:#}"),
            }
            return;
        }
        match decrypt_v6(&path, &self.device_dir, self.master_password.as_bytes(), policy) {
            Ok(out) => {
                self.pending_unknown = None;
                let who = match (&out.sender.contact_label, out.sender.verified) {
                    (Some(label), true) => format!("Sender: {label} (verified)"),
                    (Some(label), false) => format!(
                        "Sender: {label} (signature valid, but not yet verified — compare the safety number)"
                    ),
                    (None, _) => format!(
                        "Sender: UNKNOWN \"{}\" [{}] (signature valid, identity not confirmed)",
                        out.sender.claimed_name,
                        short_fp(&out.sender.fingerprint)
                    ),
                };
                self.status = format!("Decrypted to: {} | {}", out.path.display(), who);
            }
            Err(e) => match e.downcast_ref::<UnknownSenderError>() {
                Some(unknown) => {
                    self.pending_unknown = Some(unknown.clone());
                    self.status = "The sender is not in your contacts — choose how to continue below.".to_string();
                }
                None => {
                    self.pending_unknown = None;
                    self.status = format!("Decrypt error: {e:#}");
                }
            },
        }
    }

    pub(crate) fn sharing_ui(&mut self, ui: &mut egui::Ui) {
        ui.add_space(16.0);
        ui.separator();
        ui.heading("Share with contacts");
        ui.label(
            "Exchange invite files once (any channel), compare the safety number on a different \
             channel, then encrypt for one or several contacts. Files are signed by you and \
             authenticated on arrival. No server is needed.",
        );
        ui.add_space(6.0);

        if let Some(err) = &self.contacts_error {
            ui.colored_label(
                BAD,
                format!("Your contact list could not be loaded and sharing is disabled: {err}"),
            );
        }

        // ── Meghívó ──
        ui.horizontal(|ui| {
            ui.label("My name:");
            ui.add(egui::TextEdit::singleline(&mut self.display_name).desired_width(160.0));
        });
        ui.horizontal(|ui| {
            if ui.button("Create my invite…").clicked() {
                if self.master_password.is_empty() {
                    self.status = "Enter the master password first (it signs your invite).".to_string();
                } else if self.display_name.trim().is_empty() {
                    self.status = "Enter your name above first.".to_string();
                } else if let Some(path) = FileDialog::new()
                    .add_filter("2BSecret invite", &["2binvite"])
                    .set_file_name("my-invite.2binvite")
                    .save_file()
                {
                    let _ = save_display_name(&self.device_dir, &self.display_name);
                    match export_invite(
                        &self.device_dir,
                        self.master_password.as_bytes(),
                        &self.display_name,
                        &path,
                    ) {
                        Ok(()) => {
                            self.status = format!(
                                "Invite saved: {} — send it to your contact, then compare the safety number.",
                                path.display()
                            )
                        }
                        Err(e) => self.status = format!("Invite error: {e:#}"),
                    }
                    self.refresh_sharing_state();
                }
            }
            if ui.button("Import an invite…").clicked() {
                if let Some(path) = FileDialog::new()
                    .add_filter("2BSecret invite", &["2binvite", "json"])
                    .pick_file()
                {
                    match import_invite(&self.device_dir, &path, None) {
                        Ok((c, true)) => {
                            self.status = format!(
                                "Added \"{}\" [{}]. Not verified yet: compare the safety number with them.",
                                c.label,
                                short_fp(&c.fingerprint)
                            );
                            self.safety_view = Some(c.fingerprint);
                        }
                        Ok((c, false)) => {
                            self.status = format!("\"{}\" is already in your contacts (unchanged).", c.label)
                        }
                        Err(e) => self.status = format!("Invite import error: {e:#}"),
                    }
                    self.refresh_sharing_state();
                }
            }
        });
        if let Some(fp) = &self.own_fingerprint {
            ui.label(format!("My fingerprint: {}", format_fingerprint(fp)));
        } else {
            ui.label(
                "My fingerprint: shown after the first invite or encryption (that is when the \
                 signing keys are added to this identity).",
            );
        }

        // ── Ismeretlen feladó ──
        let mut choice: Option<UnknownChoice> = None;
        if let Some(u) = &self.pending_unknown {
            ui.add_space(6.0);
            ui.group(|ui| {
                ui.colored_label(WARN, format!("Unknown sender — claims to be \"{}\"", u.claimed_name));
                ui.label(format!("Fingerprint: {}", format_fingerprint(&u.fingerprint)));
                ui.label(
                    "The signature is checked, but nobody has confirmed that this key belongs to that \
                     person. Compare the fingerprint with them on another channel.",
                );
                ui.horizontal(|ui| {
                    if ui.button("Add as contact and decrypt").clicked() {
                        choice = Some(UnknownChoice::AddAndDecrypt);
                    }
                    if ui.button("Decrypt once, don't add").clicked() {
                        choice = Some(UnknownChoice::DecryptOnce);
                    }
                    if ui.button("Cancel").clicked() {
                        choice = Some(UnknownChoice::Cancel);
                    }
                });
            });
        }
        match choice {
            Some(UnknownChoice::AddAndDecrypt) => {
                if let Some(u) = self.pending_unknown.clone() {
                    match add_contact(&self.device_dir, u.bundle, &u.claimed_name) {
                        Ok(_) => {
                            self.refresh_sharing_state();
                            self.decrypt_selected_file(SenderPolicy::ContactsOnly);
                        }
                        Err(e) => self.status = format!("Could not add the contact: {e:#}"),
                    }
                }
            }
            Some(UnknownChoice::DecryptOnce) => self.decrypt_selected_file(SenderPolicy::AcceptUnknown),
            Some(UnknownChoice::Cancel) => {
                self.pending_unknown = None;
                self.status = "Cancelled.".to_string();
            }
            None => {}
        }

        // ── Névjegyek ──
        ui.add_space(8.0);
        ui.label(format!("Contacts ({}):", self.contacts.len()));
        if self.contacts.is_empty() {
            ui.label("No contacts yet. Import an invite from someone you want to share files with.");
        }
        let mut to_toggle_verified: Option<(String, bool)> = None;
        let mut to_remove: Option<String> = None;
        let mut to_show_safety: Option<String> = None;
        let contacts = self.contacts.clone();
        for c in &contacts {
            ui.horizontal(|ui| {
                let mut selected = self.selected_contacts.contains(&c.fingerprint);
                if ui.checkbox(&mut selected, "").changed() {
                    if selected {
                        self.selected_contacts.insert(c.fingerprint.clone());
                    } else {
                        self.selected_contacts.remove(&c.fingerprint);
                    }
                }
                ui.label(&c.label);
                if c.verified {
                    ui.colored_label(GOOD, "[verified]");
                } else {
                    ui.colored_label(WARN, "[not verified]");
                }
                ui.monospace(short_fp(&c.fingerprint));
                if ui.small_button("Safety number").clicked() {
                    to_show_safety = Some(c.fingerprint.clone());
                }
                if ui.small_button("Remove").clicked() {
                    to_remove = Some(c.fingerprint.clone());
                }
            });
        }
        if let Some(fp) = to_show_safety {
            self.safety_view = if self.safety_view.as_deref() == Some(fp.as_str()) { None } else { Some(fp) };
        }
        if let Some(fp) = to_remove {
            match remove_contact(&self.device_dir, &fp) {
                Ok(()) => self.status = "Contact removed.".to_string(),
                Err(e) => self.status = format!("Remove error: {e:#}"),
            }
            self.refresh_sharing_state();
        }

        // ── Biztonsági szám ──
        if let Some(fp) = self.safety_view.clone() {
            if let Some(c) = contacts.iter().find(|c| c.fingerprint == fp) {
                ui.group(|ui| {
                    ui.label(format!("Safety number with {}:", c.label));
                    match &self.own_fingerprint {
                        Some(own) => {
                            let number = safety_number(own, &c.fingerprint);
                            let groups: Vec<&str> = number.split(' ').collect();
                            ui.monospace(groups[..6].join("  "));
                            ui.monospace(groups[6..].join("  "));
                            ui.label(
                                "Read this aloud or compare it in person / over a call. Both of you must see \
                                 exactly the same 60 digits. If they differ, do NOT trust this contact.",
                            );
                            ui.label(format!("Their fingerprint: {}", format_fingerprint(&c.fingerprint)));
                            ui.horizontal(|ui| {
                                if !c.verified && ui.button("They match — mark as verified").clicked() {
                                    to_toggle_verified = Some((c.fingerprint.clone(), true));
                                }
                                if c.verified && ui.button("Mark as NOT verified").clicked() {
                                    to_toggle_verified = Some((c.fingerprint.clone(), false));
                                }
                                if ui.button("Close").clicked() {
                                    self.safety_view = None;
                                }
                            });
                        }
                        None => {
                            ui.colored_label(
                                WARN,
                                "Your own fingerprint is not available yet: create an invite or encrypt once \
                                 (this adds the signing keys to your identity), then try again.",
                            );
                        }
                    }
                });
            }
        }
        if let Some((fp, verified)) = to_toggle_verified {
            match set_contact_verified(&self.device_dir, &fp, verified) {
                Ok(()) => {
                    self.status = if verified {
                        "Contact marked as verified.".to_string()
                    } else {
                        "Contact marked as not verified.".to_string()
                    }
                }
                Err(e) => self.status = format!("Verify error: {e:#}"),
            }
            self.refresh_sharing_state();
        }

        // ── Titkosítás a kiválasztott névjegyeknek ──
        ui.add_space(8.0);
        ui.checkbox(
            &mut self.include_self,
            "Also encrypt for myself (so I can open my own sent files)",
        );
        if ui.button("Encrypt for selected contacts").clicked() {
            let chosen: Vec<Contact> = contacts
                .iter()
                .filter(|c| self.selected_contacts.contains(&c.fingerprint))
                .cloned()
                .collect();
            if self.contacts_error.is_some() {
                self.status = "Fix the contact list problem shown above first.".to_string();
            } else if self.selected_file.is_none() {
                self.status = "Select a file first.".to_string();
            } else if self.master_password.is_empty() {
                self.status = "Enter the master password first (it signs the file).".to_string();
            } else if chosen.is_empty() && !self.include_self {
                self.status = "Tick at least one contact (or \"encrypt for myself\").".to_string();
            } else if let Some(path) = self.selected_file.clone() {
                let _ = save_display_name(&self.device_dir, &self.display_name);
                let unverified = chosen.iter().filter(|c| !c.verified).count();
                match encrypt_for_contacts(
                    &path,
                    &self.device_dir,
                    self.master_password.as_bytes(),
                    &chosen,
                    self.include_self,
                    &self.display_name,
                    self.securely_delete_original,
                ) {
                    Ok(out) => {
                        self.status = format!("Encrypted and signed: {}", out.display());
                        if unverified > 0 {
                            self.status.push_str(&format!(
                                " | Note: {unverified} recipient(s) are not verified yet (compare their safety number)."
                            ));
                        }
                    }
                    Err(e) => self.status = format!("Encrypt error: {e:#}"),
                }
                self.refresh_sharing_state();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phase0_tests::{keystore_available, KEYSTORE_LOCK};

    fn run_frame(app: &mut App) {
        let ctx = egui::Context::default();
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| app.sharing_ui(ui));
        });
    }

    /// A felület minden állapotában (üres, névjegyekkel, biztonsági számmal,
    /// ismeretlen feladó párbeszéddel) egy képkockányi kirajzolás nem panikolhat.
    #[test]
    fn sharing_ui_renders_in_every_state() {
        let _g = KEYSTORE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if !keystore_available() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let pw = b"correct horse battery staple 42";
        let me = root.path().join("me");
        let other = root.path().join("other");
        generate_device_identity(&me, pw).unwrap();
        generate_device_identity(&other, pw).unwrap();

        let mut app = App::default();
        app.device_dir = me.clone();
        app.refresh_sharing_state();
        run_frame(&mut app);

        let bundle = own_public_bundle(&other).unwrap();
        let fp = bundle.fingerprint().unwrap();
        add_contact(&me, bundle.clone(), "Other").unwrap();
        app.refresh_sharing_state();
        assert_eq!(app.contacts.len(), 1);
        assert!(app.own_fingerprint.is_some());
        run_frame(&mut app);

        app.selected_contacts.insert(fp.clone());
        app.safety_view = Some(fp.clone());
        run_frame(&mut app);

        app.pending_unknown = Some(UnknownSenderError {
            fingerprint: fp,
            claimed_name: "Someone".into(),
            bundle,
        });
        run_frame(&mut app);

        app.contacts_error = Some("broken".into());
        run_frame(&mut app);
    }
}
