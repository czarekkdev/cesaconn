//! Keys: what each key does on each tab and in each popup.

use super::*;

// ── Input handling ────────────────────────────────────────────────────────────

/// One key press: Ctrl-C quits; otherwise an open popup takes it, then q
/// (quit) and Tab, then the active tab.
pub(super) fn handle_input(app: &mut App) -> io::Result<()> {
    let Event::Key(key) = event::read()? else {
        return Ok(());
    };
    if key.kind != KeyEventKind::Press {
        return Ok(());
    }

    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        app.should_quit = true;
        return Ok(());
    }

    let popup = app.active_popup.clone();
    match popup {
        ActivePopup::Pairing(prompt) => {
            handle_pairing_input(app, key.code, &prompt);
            return Ok(());
        }
        ActivePopup::EditSetting => {
            handle_edit_setting_input(app, key.code);
            return Ok(());
        }
        ActivePopup::SecurityWarning { idx } => {
            handle_security_warning_input(app, key.code, idx);
            return Ok(());
        }
        ActivePopup::ConfirmPasswordChange(_) => {
            handle_confirm_change_input(app, key.code);
            return Ok(());
        }
        ActivePopup::JoinGroup(step) => {
            handle_join_input(app, key.code, step);
            return Ok(());
        }
        ActivePopup::ConfirmForget(peer) => {
            handle_confirm_forget_input(app, key.code, &peer);
            return Ok(());
        }
        ActivePopup::ConfirmReset => {
            handle_confirm_reset_input(app, key.code);
            return Ok(());
        }
        ActivePopup::Unlock => {
            handle_unlock_input(app, key.code);
            return Ok(());
        }
        ActivePopup::UnlockBoth(step) => {
            handle_unlock_both_input(app, key.code, step);
            return Ok(());
        }
        ActivePopup::ConfirmEnhanced(on) => {
            handle_confirm_enhanced_input(app, key.code, on);
            return Ok(());
        }
        ActivePopup::VaultOutdated => {
            handle_vault_outdated_input(app, key.code);
            return Ok(());
        }
        ActivePopup::DeviceAddress => {
            handle_address_input(app, key.code);
            return Ok(());
        }
        ActivePopup::None => {}
    }

    match key.code {
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Tab => app.next_tab(),
        KeyCode::BackTab => app.prev_tab(),
        _ => {}
    }

    match app.active_tab {
        Tab::Devices => match key.code {
            KeyCode::Up | KeyCode::Char('k') => app.prev_peer(),
            KeyCode::Down | KeyCode::Char('j') => app.next_peer(),
            KeyCode::Char('n') => start_add_device(app),
            KeyCode::Char('a') => start_add_at(app),
            KeyCode::Char('x') => stop_or_cancel(app),
            KeyCode::Char('d') => ask_forget_selected(app),
            _ => {}
        },
        Tab::Settings => match key.code {
            KeyCode::Up | KeyCode::Char('k') => app.prev_setting(),
            KeyCode::Down | KeyCode::Char('j') => app.next_setting(),
            KeyCode::Enter => handle_settings_enter(app),
            _ => {}
        },
        Tab::Logs => match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                app.log_follow = false;
                app.log_scroll = app.log_scroll.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                app.log_scroll = app.log_scroll.saturating_add(1);
            }
            KeyCode::Char('f') => {
                app.log_follow = !app.log_follow;
            }
            _ => {}
        },
    }

    Ok(())
}

/// Enter on Settings: Reset asks for `RESET`, a switch goes to the daemon
/// (automatic login warns first, Enhanced security says what it means), a
/// password field opens its popup (or the unlock prompt while locked).
pub(super) fn handle_settings_enter(app: &mut App) {
    let idx = app.settings_selected;

    if matches!(app.settings.get(idx).map(|s| s.label), Some(RESET_LABEL)) {
        clear_input(app);
        app.active_popup = ActivePopup::ConfirmReset;
        return;
    }

    let kind = app.active_settings().get(idx).map(|s| s.kind.clone());
    match kind {
        Some(SettingKind::Recommended(on)) => {
            app.active_popup = ActivePopup::ConfirmEnhanced(!on);
            return;
        }
        Some(SettingKind::ExcludedByEnhanced) => {
            app.push_log(
                "[ WARN] Automatic login can't be on with Enhanced security: turn Enhanced security off first",
            );
            return;
        }
        Some(SettingKind::Outdated) => {
            app.active_popup = ActivePopup::VaultOutdated;
            return;
        }
        Some(SettingKind::Locked) if is_enhanced(app) && unlock_wait(app) == 0 => {
            // both passwords open it: the two-step prompt, not one field
            open_unlock_both(app);
            return;
        }
        _ => {}
    }

    let (is_bool, currently_on, has_warning) = app
        .active_settings()
        .get(idx)
        .map(|s| match &s.kind {
            SettingKind::Bool(v) => (true, *v, s.warn_message.is_some()),
            _ => (false, false, false),
        })
        .unwrap_or_default();

    if is_bool {
        if !currently_on && has_warning {
            app.active_popup = ActivePopup::SecurityWarning { idx };
        } else if is_auto_login(app, idx) {
            // turning it off: the daemon deletes d_key from the keychain
            app.outbox.push(Command::SetAutoLogin(false));
            app.push_log("[ INFO] Turning automatic login off");
        } else if is_sync(app, idx) {
            // the daemon decides and saves it; the switch follows its status
            app.outbox.push(Command::SetSync(!currently_on));
            app.push_log(if currently_on {
                "[ INFO] Turning sync off"
            } else {
                "[ INFO] Turning sync on"
            });
        } else if is_clipboard(app, idx) {
            // the daemon decides and saves it; the switch follows its status
            app.outbox.push(Command::SetClipboard(!currently_on));
            app.push_log(if currently_on {
                "[ INFO] Turning clipboard sync off"
            } else {
                "[ INFO] Turning clipboard sync on"
            });
        }
    } else if matches!(
        app.active_settings().get(idx).map(|s| &s.kind),
        Some(SettingKind::Unavailable)
    ) {
        app.push_log(if is_auto_login(app, idx) {
            "[ WARN] Automatic login needs an OS keychain, and this platform has no backend yet"
        } else {
            "[ WARN] Clipboard sync isn't supported on this platform yet"
        });
    } else if matches!(
        app.active_settings().get(idx).map(|s| &s.kind),
        Some(SettingKind::Locked)
    ) && unlock_wait(app) > 0
    {
        // the daemon would refuse it: don't let a password be typed for nothing
        log_unlock_wait(app);
    } else if let Some(kind) = selected_key_kind(app)
        && matches!(
            app.active_settings().get(idx).map(|s| &s.kind),
            Some(SettingKind::Secret { configured: true })
        )
    {
        // changing a password that is already set: ask first
        app.active_popup = ActivePopup::ConfirmPasswordChange(kind);
    } else {
        clear_input(app);
        app.active_popup = ActivePopup::EditSetting;
    }
}

/// Seconds the daemon still refuses `Unlock` (0 = now, or unknown).
pub(super) fn unlock_wait(app: &App) -> u16 {
    match &app.daemon {
        DaemonState::Up(status) if status.locked => status.unlock_wait_secs,
        _ => 0,
    }
}

/// Logs how long the daemon still refuses `Unlock`.
pub(super) fn log_unlock_wait(app: &mut App) {
    let secs = unlock_wait(app);
    app.push_log(format!(
        "[ WARN] Too many wrong passwords: try again in {secs} s"
    ));
}

/// y: go on to typing the new password; anything that cancels: nothing changes.
pub(super) fn handle_confirm_change_input(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            clear_input(app);
            app.active_popup = ActivePopup::EditSetting;
        }
        KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
            app.active_popup = ActivePopup::None;
        }
        _ => {}
    }
}

/// Opens the unlock prompt when the daemon is locked and would take a
/// password now, once per locked spell and never over another popup (it
/// waits for the next refresh): one password, or both with Enhanced
/// security; for an outdated vault it says why nothing can be typed.
/// Closes it when the vault got unlocked some other way (automatic login,
/// another UI), and swaps it (wiping what was typed) when the vault's mode
/// changed while it was open.
pub(super) fn ask_unlock(app: &mut App, status: &Status) {
    let unlock_open = matches!(
        app.active_popup,
        ActivePopup::Unlock | ActivePopup::UnlockBoth(_)
    );

    if !status.locked {
        app.unlock_asked = false;
        app.unlock_error = None;
        if unlock_open {
            clear_input(app);
            app.join_auth.zeroize();
            app.active_popup = ActivePopup::None;
        }
        if app.active_popup == ActivePopup::VaultOutdated {
            app.active_popup = ActivePopup::None;
        }
        return;
    }

    // an open prompt that no longer fits the vault: closed and wiped, the
    // right one opens below
    let fits = match app.active_popup {
        ActivePopup::Unlock => !status.enhanced && !status.vault_outdated,
        ActivePopup::UnlockBoth(_) => status.enhanced && !status.vault_outdated,
        _ => true,
    };
    if !fits {
        clear_input(app);
        app.join_auth.zeroize();
        app.active_popup = ActivePopup::None;
        app.unlock_asked = false;
    }

    if app.unlock_asked || app.active_popup != ActivePopup::None {
        return;
    }
    if status.vault_outdated {
        app.active_popup = ActivePopup::VaultOutdated;
        app.unlock_asked = true;
    } else if status.unlock_wait_secs == 0 {
        if status.enhanced {
            open_unlock_both(app);
        } else {
            clear_input(app);
            app.active_popup = ActivePopup::Unlock;
        }
        app.unlock_asked = true;
    }
}

/// Enter / Esc close the "older version" notice; nothing can be typed.
pub(super) fn handle_vault_outdated_input(app: &mut App, code: KeyCode) {
    if matches!(code, KeyCode::Enter | KeyCode::Esc) {
        app.active_popup = ActivePopup::None;
    }
}

/// The saved vault is in Enhanced mode (both passwords unlock it).
pub(super) fn is_enhanced(app: &App) -> bool {
    matches!(&app.daemon, DaemonState::Up(status) if status.enhanced)
}

/// Opens the two-step unlock prompt with nothing typed.
pub(super) fn open_unlock_both(app: &mut App) {
    clear_input(app);
    app.join_auth.zeroize();
    app.active_popup = ActivePopup::UnlockBoth(JoinStep::Auth);
}

/// The Enhanced unlock prompt: the auth password, Enter, the data
/// password, Enter sends both exactly as typed; Esc leaves it for later
/// and wipes both.
pub(super) fn handle_unlock_both_input(app: &mut App, code: KeyCode, step: JoinStep) {
    match code {
        KeyCode::Esc => {
            clear_input(app);
            app.join_auth.zeroize();
            app.active_popup = ActivePopup::None;
            app.push_log("[ INFO] Unlock later: Settings > Data key");
        }
        KeyCode::Enter if app.input_buf.is_empty() => {}
        KeyCode::Enter => match step {
            JoinStep::Auth => {
                // the buffer is pre-sized: this copy never reallocates
                app.join_auth.zeroize();
                app.join_auth.extend_from_slice(app.input_buf.as_bytes());
                clear_input(app);
                app.active_popup = ActivePopup::UnlockBoth(JoinStep::Data);
            }
            JoinStep::Data => {
                app.outbox.push(Command::UnlockBoth(JoinPasswords {
                    auth: PasswordUpdate {
                        password: Zeroizing::new(app.join_auth.to_vec()),
                    },
                    data: PasswordUpdate {
                        password: Zeroizing::new(app.input_buf.as_bytes().to_vec()),
                    },
                }));
                app.join_auth.zeroize();
                clear_input(app);
                app.active_popup = ActivePopup::None;
                app.push_log(
                    "[ INFO] Unlocking the saved keys with both passwords (takes a moment)",
                );
            }
        },
        KeyCode::Backspace => {
            app.input_buf.pop();
        }
        KeyCode::Char(c) => push_input(app, c),
        _ => {}
    }
}

/// Whether automatic login is on (the daemon says so).
pub(super) fn auto_login_on(app: &App) -> bool {
    matches!(&app.daemon, DaemonState::Up(status) if status.auto_login)
}

/// Whether there is a keychain for automatic login here at all.
fn keychain_here(app: &App) -> bool {
    matches!(&app.daemon, DaemonState::Up(status) if !status.keychain_unavailable)
}

/// Why the daemon would refuse to change Enhanced security right now
/// (shown in the popup, where the user is looking), if it would.
pub(super) fn enhanced_blocker(app: &App) -> Option<&'static str> {
    match &app.daemon {
        DaemonState::Up(status) if status.locked => Some("Unlock the saved keys first."),
        DaemonState::Up(status) if !status.saved && status.auth_key_set && status.data_key_set => {
            Some("The keys couldn't be saved: see the daemon log.")
        }
        DaemonState::Up(status) if !status.saved => {
            Some("Set both passwords first: nothing is saved yet.")
        }
        DaemonState::Up(_) => None,
        _ => Some("The daemon isn't reachable."),
    }
}

/// y: turn Enhanced security on (automatic login off first, the two
/// can't both be on: always sent where there is a keychain, since a change
/// sent a moment ago may not be in the status yet) or off, unless the
/// daemon would refuse (the popup says why and stays open); anything that
/// cancels: nothing changes.
pub(super) fn handle_confirm_enhanced_input(app: &mut App, code: KeyCode, on: bool) {
    match code {
        KeyCode::Char('y') | KeyCode::Char('Y') if enhanced_blocker(app).is_some() => {}
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            if on && keychain_here(app) {
                // sent in order by the one link worker, so it also wins over
                // a "turn automatic login on" still on its way
                app.outbox.push(Command::SetAutoLogin(false));
            }
            app.outbox.push(Command::SetEnhanced(on));
            app.push_log(if on {
                "[ INFO] Turning Enhanced security on"
            } else {
                "[ WARN] Turning Enhanced security off: the auth key goes back into the vault"
            });
            app.active_popup = ActivePopup::None;
        }
        KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
            app.active_popup = ActivePopup::None;
        }
        _ => {}
    }
}

/// The unlock prompt: Enter sends the data password exactly as typed, Esc
/// leaves it for later (Settings > Data key). The input is wiped either way.
pub(super) fn handle_unlock_input(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc => {
            clear_input(app);
            app.active_popup = ActivePopup::None;
            app.push_log("[ INFO] Unlock later: Settings > Data key");
        }
        KeyCode::Enter if app.input_buf.is_empty() => {}
        KeyCode::Enter => {
            app.outbox.push(Command::Unlock(PasswordUpdate {
                password: Zeroizing::new(app.input_buf.as_bytes().to_vec()),
            }));
            clear_input(app);
            app.active_popup = ActivePopup::None;
            app.push_log("[ INFO] Unlocking the saved keys (takes a moment)");
        }
        KeyCode::Backspace => {
            app.input_buf.pop();
        }
        KeyCode::Char(c) => push_input(app, c),
        _ => {}
    }
}

/// `d` on Devices: asks before forgetting the selected device.
pub(super) fn ask_forget_selected(app: &mut App) {
    if let Some(peer) = app.selected_peer().cloned() {
        app.active_popup = ActivePopup::ConfirmForget(peer);
    }
}

/// y: forget the device; anything that cancels: nothing changes.
pub(super) fn handle_confirm_forget_input(app: &mut App, code: KeyCode, peer: &PeerInfo) {
    match code {
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            app.outbox.push(Command::ForgetPeer(peer.fingerprint));
            app.push_log(format!("[ INFO] Forgetting {}", peer.name));
            app.active_popup = ActivePopup::None;
        }
        KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
            app.active_popup = ActivePopup::None;
        }
        _ => {}
    }
}

/// Typing [`RESET_WORD`] then Enter resets; Esc cancels. Anything else
/// typed and Enter does nothing (no reset by a stray key).
pub(super) fn handle_confirm_reset_input(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc => {
            clear_input(app);
            app.active_popup = ActivePopup::None;
        }
        KeyCode::Enter if app.input_buf.as_str() == RESET_WORD => {
            clear_input(app);
            app.active_popup = ActivePopup::None;
            app.outbox.push(Command::ResetDevice);
            app.push_log("[ WARN] Resetting this device");
        }
        KeyCode::Enter => {}
        KeyCode::Backspace => {
            app.input_buf.pop();
        }
        KeyCode::Char(c) => push_input(app, c),
        _ => {}
    }
}

/// `n` on Devices. A member with networking on opens its "Add device"
/// window (invite); a fresh device asks for the group's passwords and
/// joins; anything else says what is missing.
pub(super) fn start_add_device(app: &mut App) {
    match &app.daemon {
        DaemonState::Up(status) if status.network_running => {
            app.outbox.push(Command::AddDevice);
            app.push_log(
                "[ INFO] Add device open for 2 min (x stops it): press n on the new device (or on another of yours), then compare the code",
            );
        }
        DaemonState::Up(status) if status.joining => {
            app.push_log("[ INFO] Joining already: x cancels");
        }
        DaemonState::Up(status) if is_fresh(status) => {
            clear_input(app);
            app.join_auth.zeroize();
            app.join_at = None;
            app.active_popup = ActivePopup::JoinGroup(JoinStep::Auth);
        }
        _ => app.push_log("[ WARN] Turn Sync on first (Settings > Sync)"),
    }
}

/// `a` on Devices: like `n`, for a device discovery can't reach (another
/// network, a VPN): asks for its IPv4 address first. A member connects to it
/// within its "Add device" window, a fresh device joins through it.
pub(super) fn start_add_at(app: &mut App) {
    match &app.daemon {
        DaemonState::Up(status) if status.joining => {
            app.push_log("[ INFO] Joining already: x cancels");
        }
        DaemonState::Up(status) if status.network_running || is_fresh(status) => {
            clear_input(app);
            app.active_popup = ActivePopup::DeviceAddress;
        }
        _ => app.push_log("[ WARN] Turn Sync on first (Settings > Sync)"),
    }
}

/// Typing the other device's address: Enter checks it (an IP this device
/// can reach) and goes on, Esc cancels.
pub(super) fn handle_address_input(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc => {
            app.active_popup = ActivePopup::None;
            clear_input(app);
        }
        KeyCode::Enter => {
            let Some(at) = DeviceAddress::parse(&app.input_buf) else {
                // stays open with what was typed, and says why
                app.address_invalid = true;
                return;
            };
            clear_input(app);
            match &app.daemon {
                DaemonState::Up(status) if status.network_running => {
                    app.active_popup = ActivePopup::None;
                    app.outbox.push(Command::AddDeviceAt(at));
                    app.push_log(format!(
                        "[ INFO] Add device open for 2 min (x stops it): connecting to {at} as soon as Add device is open there too, then compare the code"
                    ));
                }
                DaemonState::Up(status) if is_fresh(status) => {
                    app.join_auth.zeroize();
                    app.join_at = Some(at);
                    app.active_popup = ActivePopup::JoinGroup(JoinStep::Auth);
                }
                _ => {
                    app.active_popup = ActivePopup::None;
                    app.push_log("[ WARN] Turn Sync on first (Settings > Sync)");
                }
            }
        }
        KeyCode::Backspace => {
            app.input_buf.pop();
            app.address_invalid = false;
        }
        KeyCode::Char(c) => {
            push_input(app, c);
            app.address_invalid = false;
        }
        _ => {}
    }
}

/// No keys and nothing saved: this device can join a group.
pub(super) fn is_fresh(status: &Status) -> bool {
    !status.auth_key_set && !status.data_key_set && !status.locked && !status.saved
}

/// `x` on Devices: ends a running join, or the "Add device" window. The
/// window is stopped whenever networking runs, not only once the status
/// shows it open: `x` right after `n` comes before the next refresh, and
/// stopping a window that isn't open does nothing.
pub(super) fn stop_or_cancel(app: &mut App) {
    match &app.daemon {
        DaemonState::Up(status) if status.joining => {
            app.outbox.push(Command::CancelJoin);
            app.push_log("[ INFO] Cancelling the join");
        }
        DaemonState::Up(status) if status.network_running => {
            app.outbox.push(Command::StopAddDevice);
            app.push_log("[ INFO] Stopping Add device: no longer visible to new devices");
        }
        _ => {}
    }
}

/// Typing the two group passwords: Enter goes on (then sends), Esc
/// cancels and wipes both. Passwords are taken exactly as typed.
pub(super) fn handle_join_input(app: &mut App, code: KeyCode, step: JoinStep) {
    match code {
        KeyCode::Esc => {
            clear_input(app);
            app.join_auth.zeroize();
            app.join_at = None;
            app.active_popup = ActivePopup::None;
        }
        KeyCode::Enter if app.input_buf.is_empty() => {}
        KeyCode::Enter => match step {
            JoinStep::Auth => {
                // the buffer is pre-sized: this copy never reallocates
                app.join_auth.zeroize();
                app.join_auth.extend_from_slice(app.input_buf.as_bytes());
                clear_input(app);
                app.active_popup = ActivePopup::JoinGroup(JoinStep::Data);
            }
            JoinStep::Data => {
                let passwords = JoinPasswords {
                    auth: PasswordUpdate {
                        password: Zeroizing::new(app.join_auth.to_vec()),
                    },
                    data: PasswordUpdate {
                        password: Zeroizing::new(app.input_buf.as_bytes().to_vec()),
                    },
                };
                match app.join_at.take() {
                    Some(at) => {
                        app.outbox.push(Command::JoinGroupAt(at, passwords));
                        app.push_log(format!(
                            "[ INFO] Joining through {at}: waiting for Add device to be open there (takes a moment)"
                        ));
                    }
                    None => {
                        app.outbox.push(Command::JoinGroup(passwords));
                        app.push_log(
                            "[ INFO] Joining: looking for a device with Add device open (takes a moment)",
                        );
                    }
                }
                app.join_auth.zeroize();
                clear_input(app);
                app.active_popup = ActivePopup::None;
            }
        },
        KeyCode::Backspace => {
            app.input_buf.pop();
        }
        KeyCode::Char(c) => push_input(app, c),
        _ => {}
    }
}

/// y: the codes match, pair; n / Esc: reject. Anything else waits.
pub(super) fn handle_pairing_input(app: &mut App, code: KeyCode, prompt: &PairingPrompt) {
    let accept = match code {
        KeyCode::Char('y') | KeyCode::Char('Y') => true,
        KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => false,
        _ => return,
    };

    // the code goes along: the daemon only takes the answer for exactly
    // the pairing the user looked at
    app.outbox.push(Command::AnswerPairing {
        id: prompt.id,
        code: prompt.code,
        accept,
    });
    app.active_popup = ActivePopup::None;
}

/// The pairing code as `emoji name` cells (the name is always shown: an
/// emoji can look different, or like a box, in another terminal).
pub(super) fn pairing_code_cells(prompt: &PairingPrompt) -> Vec<String> {
    prompt
        .code
        .iter()
        .map(|&index| match pairing_code::symbol(index) {
            Some((emoji, name)) => format!("{emoji} {name}"),
            None => "?".to_owned(),
        })
        .collect()
}

/// Typing into the password popup (Settings > Auth key / Data key): Enter
/// sends, but a new password below the minimum keeps the popup open with
/// what was typed and the red warning; Esc cancels and wipes the input.
pub(super) fn handle_edit_setting_input(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc => {
            app.active_popup = ActivePopup::None;
            clear_input(app);
        }
        KeyCode::Enter => {
            // every editable setting is a password: exactly as typed (never
            // trimmed), straight to the daemon
            if !send_password_from_input(app) {
                // too short: the popup says so and keeps what was typed
                app.password_too_short = true;
                return;
            }
            app.active_popup = ActivePopup::None;
            clear_input(app);
        }
        KeyCode::Backspace => {
            app.input_buf.pop();
        }
        KeyCode::Char(c) => push_input(app, c),
        _ => {}
    }
}

/// Most bytes a popup input can hold (passwords included).
pub(super) const INPUT_CAPACITY: usize = 512;

/// Appends `c` unless it would outgrow [`INPUT_CAPACITY`]: growing the
/// buffer reallocates and leaves the old copy (maybe a password) un-wiped.
pub(super) fn push_input(app: &mut App, c: char) {
    if app.input_buf.len().saturating_add(c.len_utf8()) <= INPUT_CAPACITY {
        app.input_buf.push(c);
    }
}

/// Wipes the whole input buffer (spare capacity too), keeping its allocation,
/// and the too-short warning that belonged to it.
pub(super) fn clear_input(app: &mut App) {
    app.input_buf.zeroize();
    app.password_too_short = false;
    app.address_invalid = false;
}

/// Which key the selected setting is, if it is one.
pub(super) fn selected_key_kind(app: &App) -> Option<KeyKind> {
    match app.active_settings().get(app.settings_selected)?.label {
        AUTH_KEY_LABEL => Some(KeyKind::Auth),
        DATA_KEY_LABEL => Some(KeyKind::Data),
        _ => None,
    }
}

/// Hands the typed password to the daemon link. The only copy is an
/// exact-size zeroizing buffer that the link drops right after sending; the
/// caller wipes the input buffer. The daemon picks and keeps the salt.
/// Returns `false` only for a new password below the minimum (nothing
/// sent, the popup stays open); `true` when the popup can close.
pub(super) fn send_password_from_input(app: &mut App) -> bool {
    let Some(kind) = selected_key_kind(app) else {
        return true;
    };

    if app.input_buf.is_empty() {
        return true;
    }

    let name = match kind {
        KeyKind::Auth => "auth",
        KeyKind::Data => "data",
    };

    let locked = matches!(&app.daemon, DaemonState::Up(status) if status.locked);

    if locked {
        if kind == KeyKind::Data && unlock_wait(app) > 0 {
            // the daemon would refuse it without looking at the password
            log_unlock_wait(app);
        } else if kind == KeyKind::Data {
            app.outbox.push(Command::Unlock(PasswordUpdate {
                password: Zeroizing::new(app.input_buf.as_bytes().to_vec()),
            }));
            app.push_log("[ INFO] Unlocking the saved keys (takes a moment)");
        } else {
            app.push_log("[ WARN] Saved keys are locked: unlock with the data password first");
        }
        return true;
    }

    // the daemon checks this too; this only saves a round trip
    if app.input_buf.chars().count() < MIN_NEW_PASSWORD_LEN {
        app.push_log(format!(
            "[ WARN] The {name} password is too short: use at least {MIN_NEW_PASSWORD_LEN} characters, nothing sent"
        ));
        return false;
    }

    app.outbox.push(Command::SetPassword {
        kind,
        update: PasswordUpdate {
            password: Zeroizing::new(app.input_buf.as_bytes().to_vec()),
        },
    });
    app.push_log(format!(
        "[ INFO] Sending the {name} password to the daemon (deriving the key takes a moment)"
    ));
    true
}

/// Whether setting `idx` is the clipboard sync switch.
pub(super) fn is_clipboard(app: &App, idx: usize) -> bool {
    matches!(
        app.settings.get(idx).map(|s| s.label),
        Some(CLIPBOARD_LABEL)
    )
}

/// Whether setting `idx` is the Sync switch.
pub(super) fn is_sync(app: &App, idx: usize) -> bool {
    matches!(app.settings.get(idx).map(|s| s.label), Some(SYNC_LABEL))
}

/// Whether setting `idx` is the automatic-login switch.
pub(super) fn is_auto_login(app: &App, idx: usize) -> bool {
    matches!(
        app.settings.get(idx).map(|s| s.label),
        Some(AUTO_LOGIN_LABEL)
    )
}

/// y: turn automatic login on (the only switch with a warning); anything
/// that cancels: nothing changes.
pub(super) fn handle_security_warning_input(app: &mut App, code: KeyCode, idx: usize) {
    match code {
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            if is_auto_login(app, idx) {
                // the daemon decides; the switch follows its status
                app.outbox.push(Command::SetAutoLogin(true));
                app.push_log(
                    "[ WARN] Turning automatic login on: your data key goes to the OS keychain",
                );
            }
            app.active_popup = ActivePopup::None;
        }
        KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
            app.active_popup = ActivePopup::None;
        }
        _ => {}
    }
}
