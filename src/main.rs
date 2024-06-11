#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

mod rijndael_aes;

use eframe::egui::{self, CentralPanel, Color32, Context, Frame, RichText, Vec2};
use native_dialog::{MessageDialog, MessageType};
use rijndael_aes::*;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_maximize_button(false)
            .with_resizable(false)
            .with_title("Aes encryption and decryption")
            .with_min_inner_size(Vec2::new(620.0, 600.0))
            .with_max_inner_size(Vec2::new(620.0, 600.0)),
        centered: true,
        ..Default::default()
    };
    eframe::run_native("aes-app", options, Box::new(|cc| Box::<AesApp>::default()))
}

struct AesApp {
    plaintext: String,
    encrypt_key: String,
    encrypt_result: String,
    encrypt_mode: AesMode,

    ciphertext: String,
    decrypt_key: String,
    decrypt_result: String,
    decrypt_mode: AesMode,
}

impl Default for AesApp {
    fn default() -> Self {
        Self {
            plaintext: "".to_owned(),
            encrypt_key: "".to_owned(),
            encrypt_result: "".to_owned(),
            ciphertext: "".to_owned(),
            decrypt_key: "".to_owned(),
            decrypt_result: "".to_owned(),
            encrypt_mode: AesMode::AES128,
            decrypt_mode: AesMode::AES128,
        }
    }
}

impl eframe::App for AesApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        CentralPanel::default()
            .frame(
                Frame::default()
                    .inner_margin(10.0)
                    .fill(Color32::from_rgb(220, 220, 220)),
            )
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.heading(
                        RichText::new("Aes encryption and decryption")
                            .color(Color32::from_rgb(0, 0, 0))
                            .size(36.0),
                    );
                    ui.add_space(25.0);
                    ui.horizontal_centered(|ui| {
                        ui.vertical(|ui| {
                            let label_plaintext = ui.label(
                                RichText::new("Encryption Text")
                                    .color(Color32::from_rgb(0, 0, 0))
                                    .size(18.0),
                            );
                            ui.text_edit_multiline(&mut self.plaintext)
                                .labelled_by(label_plaintext.id);
                            ui.add_space(10.0);
                            let label_key = ui.label(
                                RichText::new("Secret Key")
                                    .color(Color32::from_rgb(0, 0, 0))
                                    .size(18.0),
                            );
                            ui.text_edit_singleline(&mut self.encrypt_key)
                                .labelled_by(label_key.id);
                            ui.add_space(10.0);
                            ui.horizontal(|ui| {
                                ui.selectable_value(
                                    &mut self.encrypt_mode,
                                    AesMode::AES128,
                                    RichText::new("Aes-128")
                                        .color(Color32::from_rgb(0, 0, 0))
                                        .size(16.0),
                                );
                                ui.selectable_value(
                                    &mut self.encrypt_mode,
                                    AesMode::AES192,
                                    RichText::new("Aes-192")
                                        .color(Color32::from_rgb(0, 0, 0))
                                        .size(16.0),
                                );
                                ui.selectable_value(
                                    &mut self.encrypt_mode,
                                    AesMode::AES256,
                                    RichText::new("Aes-256")
                                        .color(Color32::from_rgb(0, 0, 0))
                                        .size(16.0),
                                );
                            });
                            ui.add_space(10.0);
                            if ui
                                .button(
                                    RichText::new("Encrypt")
                                        .color(Color32::from_rgb(0, 0, 0))
                                        .size(16.0),
                                )
                                .clicked()
                            {
                                match encrypt(
                                    &self.plaintext.as_bytes(),
                                    &self.encrypt_key.as_bytes(),
                                    self.encrypt_mode,
                                ) {
                                    Ok(ok) => self.encrypt_result = hex::encode(ok),
                                    Err(err) => {
                                        MessageDialog::new()
                                            .set_type(MessageType::Warning)
                                            .set_title("Error")
                                            .set_text(&err)
                                            .show_alert()
                                            .unwrap();
                                    }
                                }
                            }
                        });
                        ui.add_space(10.0);
                        ui.vertical(|ui| {
                            let label_encription_result = ui.label(
                                RichText::new("Encrypted Text")
                                    .color(Color32::from_rgb(0, 0, 0))
                                    .size(18.0),
                            );
                            ui.text_edit_multiline(&mut self.encrypt_result)
                                .labelled_by(label_encription_result.id);
                        });
                    });
                    ui.separator();
                    ui.horizontal_centered(|ui| {
                        ui.vertical(|ui| {
                            let label_ciphertext = ui.label(
                                RichText::new("Encrypted Text")
                                    .color(Color32::from_rgb(0, 0, 0))
                                    .size(18.0),
                            );
                            ui.text_edit_multiline(&mut self.ciphertext)
                                .labelled_by(label_ciphertext.id);
                            ui.add_space(10.0);
                            let label_key = ui.label(
                                RichText::new("Secret Key")
                                    .color(Color32::from_rgb(0, 0, 0))
                                    .size(18.0),
                            );
                            ui.text_edit_singleline(&mut self.decrypt_key)
                                .labelled_by(label_key.id);
                            ui.add_space(10.0);
                            ui.horizontal(|ui| {
                                ui.selectable_value(
                                    &mut self.decrypt_mode,
                                    AesMode::AES128,
                                    RichText::new("Aes-128")
                                        .color(Color32::from_rgb(0, 0, 0))
                                        .size(16.0),
                                );
                                ui.selectable_value(
                                    &mut self.decrypt_mode,
                                    AesMode::AES192,
                                    RichText::new("Aes-192")
                                        .color(Color32::from_rgb(0, 0, 0))
                                        .size(16.0),
                                );
                                ui.selectable_value(
                                    &mut self.decrypt_mode,
                                    AesMode::AES256,
                                    RichText::new("Aes-256")
                                        .color(Color32::from_rgb(0, 0, 0))
                                        .size(16.0),
                                );
                            });
                            ui.add_space(10.0);
                            if ui
                                .button(
                                    RichText::new("Decrypt")
                                        .color(Color32::from_rgb(0, 0, 0))
                                        .size(16.0),
                                )
                                .clicked()
                            {
                                match decrypt(
                                    &self.ciphertext,
                                    &self.decrypt_key.as_bytes(),
                                    self.decrypt_mode,
                                ) {
                                    Ok(ok) => self.decrypt_result = ok,
                                    Err(err) => {
                                        MessageDialog::new()
                                            .set_type(MessageType::Warning)
                                            .set_title("Error")
                                            .set_text(&err)
                                            .show_alert()
                                            .unwrap();
                                    }
                                }
                            }
                        });
                        ui.add_space(10.0);
                        ui.vertical(|ui| {
                            let label_decryption_result = ui.label(
                                RichText::new("Decrypted Text")
                                    .color(Color32::from_rgb(0, 0, 0))
                                    .size(18.0),
                            );
                            ui.text_edit_multiline(&mut self.decrypt_result)
                                .labelled_by(label_decryption_result.id);
                        });
                    });
                });
            });
    }
}
