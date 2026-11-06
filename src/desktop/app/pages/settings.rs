impl SettingsDraft {
    fn from_config(config: &Config, start_at_login: bool, context_menu_enabled: bool) -> Self {
        Self {
            download_dir: config.download_dir.display().to_string(),
            quarantine_dir: config.storage.quarantine_dir.display().to_string(),
            monitor_enabled: config.runtime.monitor_enabled,
            start_at_login,
            context_menu_enabled,
        }
    }

    fn runtime_settings(&self) -> Result<RuntimeSettings, String> {
        let settings = RuntimeSettings {
            download_dir: PathBuf::from(self.download_dir.trim()),
            quarantine_dir: PathBuf::from(self.quarantine_dir.trim()),
            monitor_enabled: self.monitor_enabled,
            start_at_login: self.start_at_login,
            context_menu_enabled: self.context_menu_enabled,
        };
        settings
            .validate()
            .map_err(|error| format!("{error:#}"))?;
        Ok(settings)
    }
}

impl DesktopApp {
    fn render_settings(&mut self, ui: &mut egui::Ui) {
        page_header(
            ui,
            "Settings",
            "Control monitoring, sign-in startup, and protected storage",
            Some("Path changes restart the monitor so no old directory stays watched."),
        );
        self.render_status(ui);

        let mut browse_downloads = false;
        let mut browse_quarantine = false;
        let mut save = false;
        let mut reset = false;
        let mut monitor_toggled = false;
        let drives = quarantine_drives();
        let validation = self.settings.runtime_settings();

        self.prepare_scroll_reveal(ui);
        ScrollArea::vertical()
            .auto_shrink([false, false])
            .scroll_bar_visibility(ScrollBarVisibility::VisibleWhenNeeded)
            .show(ui, |ui| {
                settings_card(ui, "MONITORING", |ui| {
                    let monitor_changed = ui
                        .add_enabled_ui(!self.busy, |ui| {
                            ui.scope(|ui| {
                                toggle_switch(
                                    ui,
                                    &mut self.settings.monitor_enabled,
                                    "Monitor downloads",
                                )
                            })
                            .inner
                        })
                        .inner
                        .changed();
                    monitor_toggled = monitor_changed;
                    if monitor_changed && !self.settings.monitor_enabled {
                        self.settings.start_at_login = false;
                    }
                    let startup_changed = ui
                        .checkbox(
                            &mut self.settings.start_at_login,
                            "Start the monitor when I sign in",
                        )
                        .changed();
                    if startup_changed && self.settings.start_at_login {
                        self.settings.monitor_enabled = true;
                    }
                    ui.checkbox(
                        &mut self.settings.context_menu_enabled,
                        "Add “Is It Safe?” to the file right-click menu",
                    );
                    ui.add_space(8.0);
                    let (color, text) = if self.monitor_running {
                        (ACCENT, "Monitor active")
                    } else {
                        (DANGER, "Monitor stopped")
                    };
                    ui.horizontal(|ui| {
                        let (dot, _) = ui.allocate_exact_size(Vec2::splat(8.0), Sense::hover());
                        ui.painter().circle_filled(dot.center(), 3.5, color);
                        ui.label(RichText::new(text).size(11.5).color(color));
                    });
                });

                ui.add_space(12.0);
                settings_card(ui, "DOWNLOAD DIRECTORY", |ui| {
                    ui.label(
                        RichText::new("Files created, renamed, or moved here are checked.")
                            .size(11.0)
                            .color(MUTED),
                    );
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        let width = (ui.available_width() - 96.0).max(280.0);
                        ui.add(
                            TextEdit::singleline(&mut self.settings.download_dir)
                                .desired_width(width),
                        );
                        if ui.button("Browse…").clicked() {
                            browse_downloads = true;
                        }
                    });
                    ui.label(
                        RichText::new(
                            "The download execution barrier is applied to this directory.",
                        )
                        .size(10.0)
                        .color(MUTED),
                    );
                });

                ui.add_space(12.0);
                settings_card(ui, "QUARANTINE STORAGE", |ui| {
                    ui.label(
                        RichText::new("Choose a folder on the disk that should hold quarantined files.")
                            .size(11.0)
                            .color(MUTED),
                    );
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Disk").size(11.0).color(MUTED));
                        let selected = selected_drive(&self.settings.quarantine_dir);
                        egui::ComboBox::from_id_salt("quarantine_drive")
                            .selected_text(selected)
                            .show_ui(ui, |ui| {
                                for drive in &drives {
                                    let label = drive.display().to_string();
                                    if ui.selectable_label(false, &label).clicked() {
                                        self.settings.quarantine_dir = drive
                                            .join("IsItSafe")
                                            .join("quarantine")
                                            .display()
                                            .to_string();
                                    }
                                }
                            });
                    });
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        let width = (ui.available_width() - 96.0).max(280.0);
                        ui.add(
                            TextEdit::singleline(&mut self.settings.quarantine_dir)
                                .desired_width(width),
                        );
                        if ui.button("Browse…").clicked() {
                            browse_quarantine = true;
                        }
                    });
                    ui.label(
                        RichText::new("Existing quarantined files stay at their recorded paths.")
                            .size(10.0)
                            .color(MUTED),
                    );
                });

                if let Err(error) = &validation {
                    ui.add_space(10.0);
                    ui.label(RichText::new(error).size(11.0).color(DANGER));
                }
                ui.add_space(16.0);
                ui.horizontal(|ui| {
                    save = ui
                        .add_enabled(
                            validation.is_ok() && !self.busy,
                            egui::Button::new(
                                RichText::new("Save settings").color(Color32::BLACK),
                            )
                            .fill(ACCENT),
                        )
                        .clicked();
                    reset = ui
                        .add_enabled(!self.busy, egui::Button::new("Reset"))
                        .clicked();
                });
            });

        if browse_downloads
            && let Some(path) = pick_folder("Choose the monitored download directory", None)
        {
            self.settings.download_dir = path.display().to_string();
        }
        if browse_quarantine
            && let Some(path) = pick_folder(
                "Choose the quarantine location",
                Some(Path::new(&self.settings.quarantine_dir)),
            )
        {
            self.settings.quarantine_dir = path.display().to_string();
        }
        if reset {
            self.settings =
                SettingsDraft::from_config(
                    &self.config.read(),
                    crate::startup::is_enabled(),
                    crate::context_menu::is_enabled(),
                );
            self.status = None;
        } else if save || monitor_toggled {
            match validation {
                Ok(settings) => self.save_settings(settings),
                Err(error) => {
                    self.status = Some(StatusMessage { text: error, error: true });
                }
            }
        }
    }

    fn save_settings(&mut self, settings: RuntimeSettings) {
        self.busy = true;
        self.busy_message = Some("Saving settings and updating the monitor…");
        self.status = None;
        if let Err(error) = self.worker.send(WorkerRequest::SaveSettings(settings)) {
            self.busy = false;
            self.busy_message = None;
            self.status = Some(StatusMessage { text: error, error: true });
        }
    }
}

fn settings_card(ui: &mut egui::Ui, title: &str, contents: impl FnOnce(&mut egui::Ui)) {
    Frame::new()
        .fill(PANEL)
        .stroke(Stroke::new(1.0, LINE))
        .inner_margin(egui::Margin::symmetric(16, 14))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(title).size(10.0).strong().color(ACCENT));
            ui.add_space(8.0);
            contents(ui);
        });
}

fn pick_folder(title: &str, directory: Option<&Path>) -> Option<PathBuf> {
    let mut dialog = rfd::FileDialog::new().set_title(title);
    if let Some(directory) = directory.filter(|path| path.is_dir()) {
        dialog = dialog.set_directory(directory);
    }
    dialog.pick_folder()
}

fn quarantine_drives() -> Vec<PathBuf> {
    (b'A'..=b'Z')
        .filter_map(|letter| {
            let root = PathBuf::from(format!("{}:\\", letter as char));
            root.is_dir().then_some(root)
        })
        .collect()
}

fn selected_drive(path: &str) -> String {
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' {
        format!("{}:", bytes[0] as char)
    } else {
        "Custom".into()
    }
}
