//! The daemon link's answers: how each one changes the app and the log.

use super::*;

/// Applies what the daemon link reported.
pub(super) fn handle_link_event(app: &mut App, event: LinkEvent) {
    match event {
        LinkEvent::Refreshed(Ok((status, peers, pairing))) => {
            app.refresh_in_flight = false;

            if !matches!(app.daemon, DaemonState::Up(_)) {
                app.push_log("[ INFO] Connected to the daemon");
            }

            let was_locked = matches!(&app.daemon, DaemonState::Up(s) if s.locked);
            let was_joining = matches!(&app.daemon, DaemonState::Up(s) if s.joining);
            let had_other_group = matches!(&app.daemon, DaemonState::Up(s) if s.other_group_nearby);
            if status.other_group_nearby && !had_other_group {
                app.push_log(OTHER_GROUP_HINT);
            }
            if was_joining && !status.joining {
                app.push_log(if status.saved {
                    "[ INFO] Joined the group: keys saved, sync on"
                } else {
                    "[ WARN] The join ended without joining (cancelled, timed out, or the passwords didn't match)"
                });
            }
            if status.locked && !was_locked {
                app.push_log(
                    "[ WARN] Saved keys are locked: enter the data password (Esc: later, Settings > Data key)",
                );
            }

            set_key_flags(app, status.auth_key_set, status.data_key_set);
            if status.locked {
                for label in [AUTH_KEY_LABEL, DATA_KEY_LABEL] {
                    if let Some(s) = app.setting_mut(label) {
                        s.kind = SettingKind::Locked;
                    }
                }
            }
            if let Some(s) = app.setting_mut(AUTO_LOGIN_LABEL) {
                s.kind = SettingKind::Bool(status.auto_login);
            }
            if let Some(s) = app.setting_mut(SYNC_LABEL) {
                s.kind = SettingKind::Bool(status.sync_enabled);
            }
            if let Some(s) = app.setting_mut(CLIPBOARD_LABEL) {
                s.kind = if status.clipboard_unavailable {
                    SettingKind::Unavailable
                } else {
                    SettingKind::Bool(status.clipboard_enabled)
                };
            }
            log_peer_changes(app, &peers);
            app.peers = peers;
            app.clamp_peer_selection();
            show_pairing(app, pairing);
            ask_unlock(app, &status);
            app.daemon = DaemonState::Up(status);
        }
        LinkEvent::Refreshed(Err(e)) => {
            app.refresh_in_flight = false;

            // once per change, not every refresh
            if app.daemon != DaemonState::Down(e) {
                app.push_log(format!("[ WARN] Daemon not reachable: {e}"));
            }

            // nothing is known about keys or peers without the daemon; a
            // daemon that comes back locked is a new locked spell: ask again
            app.unlock_asked = false;
            set_key_flags(app, false, false);
            app.peers.clear();
            app.clamp_peer_selection();
            app.daemon = DaemonState::Down(e);
            show_pairing(app, None);
        }
        LinkEvent::PasswordSet { kind, result } => {
            let name = match kind {
                KeyKind::Auth => "auth",
                KeyKind::Data => "data",
            };

            let paired = matches!(&app.daemon, DaemonState::Up(s) if s.trusted_peers > 0);
            match result {
                Ok(()) => {
                    app.push_log(format!("[ INFO] The daemon set the {name} key"));
                    if paired {
                        // no group-wide change yet: the others keep the old one
                        app.push_log(format!(
                            "[ WARN] Your paired devices still use the old {name} password: \
                             set the same new one on each of them. Until then they show \
                             \"incorrect password\" on Devices"
                        ));
                    }
                }
                Err(e) => app.push_log(format!("[ERROR] Setting the {name} password failed: {e}")),
            }

            app.request_refresh();
        }
        LinkEvent::Unlocked(result) => {
            match result {
                Ok(()) => app.push_log("[ INFO] Saved keys unlocked"),
                Err(IpcErrors::Daemon(DaemonError::WrongPassword)) => {
                    app.push_log("[ERROR] Wrong data password");
                    // ask again (the next refresh, unless a wait starts)
                    app.unlock_asked = false;
                }
                Err(IpcErrors::Daemon(DaemonError::UnlockDelayed)) => app.push_log(
                    "[ WARN] Too many wrong data passwords: wait (see the status bar), then try again",
                ),
                Err(e) => app.push_log(format!("[ERROR] Unlocking failed: {e}")),
            }
            app.request_refresh();
        }
        LinkEvent::AutoLoginSet { on, result } => {
            match (on, result) {
                (true, Ok(())) => {
                    app.push_log("[ WARN] Automatic login on: the data key is in the OS keychain")
                }
                (false, Ok(())) => {
                    app.push_log("[ INFO] Automatic login off: data key removed from the keychain")
                }
                (_, Err(e)) => {
                    app.push_log(format!("[ERROR] Changing automatic login failed: {e}"))
                }
            }
            app.request_refresh();
        }
        LinkEvent::SyncSet { on, result } => {
            match (on, result) {
                (true, Ok(())) => app.push_log(
                    "[ INFO] Sync on: listening for paired devices (n on Devices adds one)",
                ),
                (false, Ok(())) => app.push_log("[ INFO] Sync off: networking stopped"),
                (_, Err(IpcErrors::Daemon(DaemonError::NotSaved))) => {
                    app.push_log("[ WARN] Sync needs saved keys: set both passwords first")
                }
                (_, Err(e)) => app.push_log(format!("[ERROR] Changing sync failed: {e}")),
            }
            app.request_refresh();
        }
        LinkEvent::ClipboardSet { on, result } => {
            match (on, result) {
                (true, Ok(())) => app.push_log(
                    "[ INFO] Clipboard sync on: copied text goes to your paired devices (while Sync is on)",
                ),
                (false, Ok(())) => app.push_log("[ INFO] Clipboard sync off"),
                (_, Err(IpcErrors::Daemon(DaemonError::NotSaved))) => {
                    app.push_log("[ WARN] Clipboard sync needs saved keys: set both passwords first")
                }
                (_, Err(IpcErrors::Daemon(DaemonError::ClipboardUnavailable))) => {
                    app.push_log("[ WARN] Clipboard sync isn't supported on this platform yet")
                }
                (_, Err(e)) => app.push_log(format!("[ERROR] Changing clipboard sync failed: {e}")),
            }
            app.request_refresh();
        }
        LinkEvent::AddDeviceStarted(result) => {
            if let Err(e) = result {
                app.push_log(format!("[ERROR] Add device failed: {e}"));
            }
            app.request_refresh();
        }
        LinkEvent::PairingAnswered { accept, result } => {
            match (accept, result) {
                (true, Ok(())) => app
                    .push_log("[ INFO] Pairing accepted: paired once the other device accepts too"),
                (false, Ok(())) => app.push_log("[ INFO] Pairing rejected"),
                (_, Err(IpcErrors::Daemon(DaemonError::PairingExpired))) => {
                    app.push_log("[ WARN] Too late: that pairing request expired")
                }
                (_, Err(e)) => app.push_log(format!("[ERROR] Answering the pairing failed: {e}")),
            }
            app.request_refresh();
        }
        LinkEvent::JoinStarted(result) => {
            match result {
                Ok(()) => {}
                Err(IpcErrors::Daemon(DaemonError::AlreadyInGroup)) => app.push_log(
                    "[ WARN] This device has keys already: only a fresh device joins a group",
                ),
                Err(IpcErrors::Daemon(DaemonError::NotSaved)) => app.push_log(
                    "[ WARN] Joining needs saved keys, and this platform has no keychain backend yet",
                ),
                Err(e) => app.push_log(format!("[ERROR] Joining failed: {e}")),
            }
            app.request_refresh();
        }
        LinkEvent::AddDeviceStopped(result) => {
            if let Err(e) = result {
                app.push_log(format!("[ERROR] Stopping Add device failed: {e}"));
            }
            app.request_refresh();
        }
        LinkEvent::JoinCancelled(result) => {
            if let Err(e) = result {
                app.push_log(format!("[ERROR] Cancelling the join failed: {e}"));
            }
            app.request_refresh();
        }
        LinkEvent::PeerForgotten(result) => {
            match result {
                Ok(()) => app.push_log(
                    "[ INFO] Device forgotten here. It still knows the group passwords: to keep it out for good, change them on every device",
                ),
                Err(IpcErrors::Daemon(DaemonError::Locked)) => {
                    app.push_log("[ WARN] Saved keys are locked: unlock first")
                }
                Err(IpcErrors::Daemon(DaemonError::UnknownPeer)) => {
                    app.push_log("[ WARN] That device isn't paired any more")
                }
                Err(e) => app.push_log(format!("[ERROR] Forgetting the device failed: {e}")),
            }
            app.request_refresh();
        }
        LinkEvent::DeviceReset(result) => {
            match result {
                Ok(()) => app.push_log(
                    "[ INFO] Device reset: no keys, no paired devices. n on Devices joins a group",
                ),
                Err(e) => app.push_log(format!(
                    "[ERROR] Reset incomplete: {e}. Run it again (see the daemon log)"
                )),
            }
            app.request_refresh();
        }
        LinkEvent::WorkerStopped => {
            if app.daemon != DaemonState::NoLink {
                app.push_log("[ERROR] The daemon link stopped, restart the UI");
            }

            set_key_flags(app, false, false);
            app.peers.clear();
            app.clamp_peer_selection();
            app.daemon = DaemonState::NoLink;
            show_pairing(app, None);
        }
    }
}

/// Shows the pairing the daemon reports. Never on top of another popup (a
/// half-typed password stays untouched): it waits for the next refresh. A
/// shown prompt that the daemon no longer has expired and is closed.
pub(super) fn show_pairing(app: &mut App, pairing: Option<PairingPrompt>) {
    match (&app.active_popup, pairing) {
        // the whole prompt, not just the id: ids start again after a
        // daemon restart, and the user must see the code they answer
        (ActivePopup::Pairing(shown), Some(prompt)) if *shown == prompt => {}
        (ActivePopup::Pairing(_) | ActivePopup::None, Some(prompt)) => {
            app.push_log(format!(
                "[ INFO] {} wants to pair: compare the code with the other device",
                prompt.name
            ));
            app.active_popup = ActivePopup::Pairing(prompt);
        }
        (ActivePopup::Pairing(_), None) => {
            app.push_log("[ WARN] The pairing request expired");
            app.active_popup = ActivePopup::None;
        }
        _ => {}
    }
}

pub(super) fn set_key_flags(app: &mut App, auth: bool, data: bool) {
    for (label, configured) in [(AUTH_KEY_LABEL, auth), (DATA_KEY_LABEL, data)] {
        if let Some(s) = app.setting_mut(label) {
            s.kind = SettingKind::Secret { configured };
        }
    }
}

/// What a paired device's state means, for the Devices tab.
pub(super) fn peer_state_text(state: PeerState) -> (&'static str, Color) {
    match state {
        PeerState::Unknown => ("not contacted yet", Color::DarkGray),
        PeerState::Ok => ("connected, passwords match", Color::Green),
        PeerState::AuthPasswordDiffers => {
            ("incorrect password (auth password differs)", Color::Red)
        }
        PeerState::DataPasswordDiffers => {
            ("incorrect password (data password differs)", Color::Red)
        }
        PeerState::Unreachable => ("not reachable at its last address", Color::Yellow),
    }
}

/// Logs once when a paired device starts showing an incorrect password.
pub(super) fn log_peer_changes(app: &mut App, peers: &[PeerInfo]) {
    for peer in peers {
        let before = app
            .peers
            .iter()
            .find(|old| old.fingerprint == peer.fingerprint)
            .map(|old| old.state);
        if before == Some(peer.state) {
            continue;
        }
        let which = match peer.state {
            PeerState::AuthPasswordDiffers => "auth",
            PeerState::DataPasswordDiffers => "data",
            PeerState::Unknown | PeerState::Ok | PeerState::Unreachable => continue,
        };
        app.push_log(format!(
            "[ WARN] {}: incorrect password. The {which} password differs between this device and it: \
             set the same one on both",
            peer.name
        ));
    }
}
