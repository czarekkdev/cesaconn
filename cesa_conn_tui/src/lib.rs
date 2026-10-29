#![forbid(unsafe_code)]

//! CesaConn terminal UI.
//!
//! Talks to the daemon over IPC ([`daemon_link`]): passwords go to the daemon,
//! which derives and keeps the keys and their salts; the UI only shows status
//! and paired devices. It keeps nothing key-related: a typed password lives in
//! the zeroizing input buffer until Enter, is handed to the daemon link and
//! wiped right away.

mod daemon_link;

use cesa_conn_system::ipc::{
    DaemonError, IpcErrors, JoinPasswords, MIN_NEW_PASSWORD_LEN, PairingPrompt, PasswordUpdate,
    PeerInfo, Status,
};
use cesa_conn_system::pairing_code;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Clear, List, ListItem, ListState, Paragraph, Tabs},
};
use std::{
    io,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

use daemon_link::{Command, DaemonLink, KeyKind, LinkEvent};

/* setting labels the daemon link reads or writes */
const AUTH_KEY_LABEL: &str = "Auth key";
const DATA_KEY_LABEL: &str = "Data key";
const AUTO_LOGIN_LABEL: &str = "Automatic login";
const SYNC_LABEL: &str = "Sync";

/// Logged once when "Add device" finds a device of another group.
const OTHER_GROUP_HINT: &str = "[ WARN] A device nearby is in a different group (other passwords setup): \
     it can't pair with this one. On that device: reset it (no passwords set), then n there joins this group";

/// How often the daemon's status is asked for (seconds).
const REFRESH_INTERVAL: u64 = 2;

// ── Data types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum SettingKind {
    Secret {
        configured: bool,
    },
    /// A secret saved in the locked vault: editing it unlocks instead.
    Locked,
    Bool(bool),
}

#[derive(Debug, Clone)]
pub struct Setting {
    pub label: &'static str,
    pub kind: SettingKind,
    /// If Some, enabling this Bool shows a security warning with this message.
    pub warn_message: Option<&'static str>,
}

impl Setting {
    fn display_value(&self) -> (&str, Color) {
        match &self.kind {
            SettingKind::Secret { configured: true } => ("[configured]", Color::Green),
            SettingKind::Secret { configured: false } => ("[not configured]", Color::DarkGray),
            SettingKind::Locked => ("[locked: Enter to unlock]", Color::Yellow),
            SettingKind::Bool(true) => ("on", Color::Green),
            SettingKind::Bool(false) => ("off", Color::DarkGray),
        }
    }
}

/// What the UI last heard from the daemon.
#[derive(Debug, Clone, PartialEq)]
pub enum DaemonState {
    /// Not asked yet.
    Unknown,
    /// Reachable, with its last status.
    Up(Status),
    /// Not reachable (not running, wrong user, ...).
    Down(IpcErrors),
    /// The link worker isn't running, nothing is sent any more.
    NoLink,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Tab {
    Devices,
    Settings,
    Logs,
}

#[derive(Debug, Clone, PartialEq)]
enum ActivePopup {
    None,
    /// A new device wants to pair: compare the code, then y / n.
    Pairing(PairingPrompt),
    EditSetting,
    SecurityWarning {
        idx: usize,
    },
    /// "Are you sure?" before changing a password that is already set.
    /// Asked before typing, so no password waits for the answer.
    ConfirmPasswordChange(KeyKind),
    /// Joining a group: the group's auth password, then its data password.
    JoinGroup(JoinStep),
}

/// Which password the join popup asks for.
#[derive(Debug, Clone, Copy, PartialEq)]
enum JoinStep {
    Auth,
    Data,
}

// ── App state ─────────────────────────────────────────────────────────────────

pub struct App {
    active_tab: Tab,

    /// Which paired device the Devices tab shows.
    peer_list_state: ListState,

    pub settings: Vec<Setting>,
    settings_selected: usize,

    pub logs: Vec<String>,
    log_scroll: u16,
    log_follow: bool,

    active_popup: ActivePopup,
    /// Text typed into a popup. Can hold a password, so it is pre-sized
    /// (never reallocates, which would leave un-wiped copies) and wiped on clear.
    input_buf: Zeroizing<String>,
    /// The join's auth password while the data password is typed; pre-sized
    /// like `input_buf` and wiped as soon as the join is sent or cancelled.
    join_auth: Zeroizing<Vec<u8>>,

    pub should_quit: bool,

    pub daemon: DaemonState,
    /// Paired devices as reported by the daemon (public data only).
    pub peers: Vec<PeerInfo>,
    /// Commands waiting to be handed to the daemon link.
    outbox: Vec<Command>,
    /// A refresh is queued or running; don't stack more.
    refresh_in_flight: bool,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        Self {
            active_tab: Tab::Devices,
            peer_list_state: ListState::default(),
            // only settings the daemon really has: nothing that does nothing
            settings: vec![
                Setting {
                    label: AUTH_KEY_LABEL,
                    kind: SettingKind::Secret { configured: false },
                    warn_message: None,
                },
                Setting {
                    label: DATA_KEY_LABEL,
                    kind: SettingKind::Secret { configured: false },
                    warn_message: None,
                },
                Setting {
                    label: AUTO_LOGIN_LABEL,
                    kind: SettingKind::Bool(false),
                    warn_message: Some(
                        "Your data key will be stored in the OS keychain.\n\
                         Its security then depends on your OS and account:\n\
                         anyone who can unlock your session can use it.\n\
                         We can't vouch for that.",
                    ),
                },
                Setting {
                    label: SYNC_LABEL,
                    kind: SettingKind::Bool(false),
                    warn_message: None,
                },
            ],
            settings_selected: 0,
            logs: Vec::new(),
            log_scroll: 0,
            log_follow: true,
            active_popup: ActivePopup::None,
            input_buf: Zeroizing::new(String::with_capacity(INPUT_CAPACITY)),
            join_auth: Zeroizing::new(Vec::with_capacity(INPUT_CAPACITY)),
            should_quit: false,
            daemon: DaemonState::Unknown,
            peers: Vec::new(),
            outbox: Vec::new(),
            refresh_in_flight: false,
        }
    }

    /// Queues a status refresh unless one is already on its way.
    fn request_refresh(&mut self) {
        if !self.refresh_in_flight {
            self.refresh_in_flight = true;
            self.outbox.push(Command::Refresh);
        }
    }

    fn setting_mut(&mut self, label: &str) -> Option<&mut Setting> {
        self.settings.iter_mut().find(|s| s.label == label)
    }

    pub fn push_log(&mut self, msg: impl Into<String>) {
        self.logs.push(msg.into());
    }

    fn active_settings(&self) -> &Vec<Setting> {
        &self.settings
    }

    fn next_tab(&mut self) {
        self.active_tab = match self.active_tab {
            Tab::Devices => Tab::Settings,
            Tab::Settings => Tab::Logs,
            Tab::Logs => Tab::Devices,
        };
    }

    fn prev_tab(&mut self) {
        self.active_tab = match self.active_tab {
            Tab::Devices => Tab::Logs,
            Tab::Settings => Tab::Devices,
            Tab::Logs => Tab::Settings,
        };
    }

    fn next_peer(&mut self) {
        if self.peers.is_empty() {
            return;
        }
        let i = self
            .peer_list_state
            .selected()
            .map_or(0, |i| wrap_next(i, self.peers.len()));
        self.peer_list_state.select(Some(i));
    }

    fn prev_peer(&mut self) {
        if self.peers.is_empty() {
            return;
        }
        let i = self
            .peer_list_state
            .selected()
            .map_or(0, |i| wrap_prev(i, self.peers.len()));
        self.peer_list_state.select(Some(i));
    }

    fn selected_peer(&self) -> Option<&PeerInfo> {
        self.peer_list_state
            .selected()
            .and_then(|i| self.peers.get(i))
    }

    /// Keeps the selection on a device that exists after the list changed.
    fn clamp_peer_selection(&mut self) {
        let selected = match (self.peer_list_state.selected(), self.peers.len()) {
            (_, 0) => None,
            (Some(i), len) => Some(i.min(len.saturating_sub(1))),
            (None, _) => Some(0),
        };
        self.peer_list_state.select(selected);
    }

    fn next_setting(&mut self) {
        let len = self.active_settings().len();
        if len > 0 {
            self.settings_selected = wrap_next(self.settings_selected, len);
        }
    }

    fn prev_setting(&mut self) {
        let len = self.active_settings().len();
        if len > 0 {
            self.settings_selected = wrap_prev(self.settings_selected, len);
        }
    }
}

// ── Input handling ────────────────────────────────────────────────────────────

fn handle_input(app: &mut App) -> io::Result<()> {
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
            KeyCode::Char('x') => stop_or_cancel(app),
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

fn handle_settings_enter(app: &mut App) {
    let idx = app.settings_selected;

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
        }
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
fn unlock_wait(app: &App) -> u16 {
    match &app.daemon {
        DaemonState::Up(status) if status.locked => status.unlock_wait_secs,
        _ => 0,
    }
}

fn log_unlock_wait(app: &mut App) {
    let secs = unlock_wait(app);
    app.push_log(format!(
        "[ WARN] Too many wrong data passwords: try again in {secs} s"
    ));
}

/// y: go on to typing the new password; anything that cancels: nothing changes.
fn handle_confirm_change_input(app: &mut App, code: KeyCode) {
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

/// `n` on Devices. A member with networking on opens its "Add device"
/// window (invite); a fresh device asks for the group's passwords and
/// joins; anything else says what is missing.
fn start_add_device(app: &mut App) {
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
            app.active_popup = ActivePopup::JoinGroup(JoinStep::Auth);
        }
        _ => app.push_log("[ WARN] Turn Sync on first (Settings > Sync)"),
    }
}

/// No keys and nothing saved: this device can join a group.
fn is_fresh(status: &Status) -> bool {
    !status.auth_key_set && !status.data_key_set && !status.locked && !status.saved
}

/// `x` on Devices: ends a running join, or the "Add device" window. The
/// window is stopped whenever networking runs, not only once the status
/// shows it open: `x` right after `n` comes before the next refresh, and
/// stopping a window that isn't open does nothing.
fn stop_or_cancel(app: &mut App) {
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
fn handle_join_input(app: &mut App, code: KeyCode, step: JoinStep) {
    match code {
        KeyCode::Esc => {
            clear_input(app);
            app.join_auth.zeroize();
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
                app.outbox.push(Command::JoinGroup(JoinPasswords {
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
                    "[ INFO] Joining: looking for a device with Add device open (takes a moment)",
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

/// y: the codes match, pair; n / Esc: reject. Anything else waits.
fn handle_pairing_input(app: &mut App, code: KeyCode, prompt: &PairingPrompt) {
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
fn pairing_code_cells(prompt: &PairingPrompt) -> Vec<String> {
    prompt
        .code
        .iter()
        .map(|&index| match pairing_code::symbol(index) {
            Some((emoji, name)) => format!("{emoji} {name}"),
            None => "?".to_owned(),
        })
        .collect()
}

fn handle_edit_setting_input(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc => {
            app.active_popup = ActivePopup::None;
            clear_input(app);
        }
        KeyCode::Enter => {
            // every editable setting is a password: exactly as typed (never
            // trimmed), straight to the daemon
            send_password_from_input(app);
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
const INPUT_CAPACITY: usize = 512;

/// Appends `c` unless it would outgrow [`INPUT_CAPACITY`]: growing the
/// buffer reallocates and leaves the old copy (maybe a password) un-wiped.
fn push_input(app: &mut App, c: char) {
    if app.input_buf.len().saturating_add(c.len_utf8()) <= INPUT_CAPACITY {
        app.input_buf.push(c);
    }
}

/// Wipes the whole input buffer (spare capacity too), keeping its allocation.
fn clear_input(app: &mut App) {
    app.input_buf.zeroize();
}

/// Which key the selected setting is, if it is one.
fn selected_key_kind(app: &App) -> Option<KeyKind> {
    match app.active_settings().get(app.settings_selected)?.label {
        AUTH_KEY_LABEL => Some(KeyKind::Auth),
        DATA_KEY_LABEL => Some(KeyKind::Data),
        _ => None,
    }
}

/// Hands the typed password to the daemon link. The only copy is an
/// exact-size zeroizing buffer that the link drops right after sending; the
/// caller wipes the input buffer. The daemon picks and keeps the salt.
fn send_password_from_input(app: &mut App) {
    let Some(kind) = selected_key_kind(app) else {
        return;
    };

    if app.input_buf.is_empty() {
        return;
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
        return;
    }

    // the daemon checks this too; this only saves a round trip
    if app.input_buf.chars().count() < MIN_NEW_PASSWORD_LEN {
        app.push_log(format!(
            "[ WARN] Use at least {MIN_NEW_PASSWORD_LEN} characters, nothing sent"
        ));
        return;
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
}

/// Applies what the daemon link reported.
fn handle_link_event(app: &mut App, event: LinkEvent) {
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
                    "[ WARN] Saved keys are locked: enter the data password (Settings > Data key)",
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
            app.peers = peers;
            app.clamp_peer_selection();
            app.daemon = DaemonState::Up(status);
            show_pairing(app, pairing);
        }
        LinkEvent::Refreshed(Err(e)) => {
            app.refresh_in_flight = false;

            // once per change, not every refresh
            if app.daemon != DaemonState::Down(e) {
                app.push_log(format!("[ WARN] Daemon not reachable: {e}"));
            }

            // nothing is known about keys or peers without the daemon
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

            match result {
                Ok(()) => app.push_log(format!("[ INFO] The daemon set the {name} key")),
                Err(e) => app.push_log(format!("[ERROR] Setting the {name} password failed: {e}")),
            }

            app.request_refresh();
        }
        LinkEvent::Unlocked(result) => {
            match result {
                Ok(()) => app.push_log("[ INFO] Saved keys unlocked"),
                Err(IpcErrors::Daemon(DaemonError::WrongPassword)) => {
                    app.push_log("[ERROR] Wrong data password")
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
fn show_pairing(app: &mut App, pairing: Option<PairingPrompt>) {
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

fn set_key_flags(app: &mut App, auth: bool, data: bool) {
    for (label, configured) in [(AUTH_KEY_LABEL, auth), (DATA_KEY_LABEL, data)] {
        if let Some(s) = app.setting_mut(label) {
            s.kind = SettingKind::Secret { configured };
        }
    }
}

/// Whether setting `idx` is the Sync switch.
fn is_sync(app: &App, idx: usize) -> bool {
    matches!(app.settings.get(idx).map(|s| s.label), Some(SYNC_LABEL))
}

/// Whether setting `idx` is the automatic-login switch.
fn is_auto_login(app: &App, idx: usize) -> bool {
    matches!(
        app.settings.get(idx).map(|s| s.label),
        Some(AUTO_LOGIN_LABEL)
    )
}

/// y: turn automatic login on (the only switch with a warning); anything
/// that cancels: nothing changes.
fn handle_security_warning_input(app: &mut App, code: KeyCode, idx: usize) {
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

// ── Rendering ─────────────────────────────────────────────────────────────────

fn ui(frame: &mut Frame, app: &mut App) {
    let area = frame.area();

    // two status lines: the daemon's state above, the keys below, so a long
    // state never covers the keys the user needs
    let [header, content, statusbar] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(0),
        Constraint::Length(2),
    ])
    .areas(area);

    render_header(frame, header, app);
    render_content(frame, content, app);
    render_statusbar(frame, statusbar, app);

    match app.active_popup.clone() {
        ActivePopup::Pairing(prompt) => render_pairing_popup(frame, area, &prompt),
        ActivePopup::EditSetting => render_edit_setting_popup(frame, area, app),
        ActivePopup::SecurityWarning { idx } => {
            render_security_warning_popup(frame, area, idx, app)
        }
        ActivePopup::ConfirmPasswordChange(kind) => render_confirm_change_popup(frame, area, kind),
        ActivePopup::JoinGroup(step) => render_join_popup(frame, area, step, app),
        ActivePopup::None => {}
    }
}

fn render_header(frame: &mut Frame, area: Rect, app: &App) {
    let tabs = Tabs::new(["  Devices  ", "  Settings  ", "  Logs  "])
        .block(
            Block::bordered()
                .title(" CesaConn ")
                .title_alignment(Alignment::Center)
                .border_type(BorderType::Rounded),
        )
        .select(match app.active_tab {
            Tab::Devices => 0,
            Tab::Settings => 1,
            Tab::Logs => 2,
        })
        .style(Style::default().fg(Color::DarkGray))
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );

    frame.render_widget(tabs, area);
}

fn render_content(frame: &mut Frame, area: Rect, app: &mut App) {
    match app.active_tab {
        Tab::Devices => render_devices(frame, area, app),
        Tab::Settings => render_settings(frame, area, app),
        Tab::Logs => render_logs(frame, area, app),
    }
}

fn render_devices(frame: &mut Frame, area: Rect, app: &mut App) {
    let [list_area, detail_area] =
        Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)]).areas(area);

    // paired devices come from the daemon (public data only)
    let paired: Vec<ListItem> = if app.peers.is_empty() {
        vec![ListItem::new(Span::styled(
            "  none yet: n adds one",
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        app.peers
            .iter()
            .map(|p| {
                ListItem::new(Line::from(vec![
                    Span::styled("◆ ", Style::default().fg(Color::Green)),
                    Span::raw(p.name.as_str()),
                ]))
            })
            .collect()
    };

    let list = List::new(paired)
        .block(
            Block::bordered()
                .title(" Paired devices ")
                .border_type(BorderType::Rounded),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
    frame.render_stateful_widget(list, list_area, &mut app.peer_list_state);

    let mut lines = vec![Line::from("")];
    match app.selected_peer() {
        Some(peer) => {
            lines.push(Line::from(vec![
                Span::styled("  Name        : ", Style::default().fg(Color::DarkGray)),
                Span::styled(peer.name.as_str(), Style::default().fg(Color::Cyan)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  Fingerprint : ", Style::default().fg(Color::DarkGray)),
                Span::raw(fingerprint_hex(&peer.fingerprint)),
            ]));
        }
        None => lines.push(Line::from(Span::styled(
            "  No paired device yet",
            Style::default().fg(Color::DarkGray),
        ))),
    }

    // what this device is doing right now, from the daemon's status
    let (activity, color) = match &app.daemon {
        DaemonState::Up(s) if s.joining => (
            "Joining a group: compare the code when it appears (x cancels)",
            Color::Yellow,
        ),
        DaemonState::Up(s) if s.adding_device && s.other_group_nearby => (
            "A device nearby is in another group: reset it, then n there joins",
            Color::Red,
        ),
        DaemonState::Up(s) if s.adding_device => (
            "Add device is open: visible to new devices (x stops it)",
            Color::Yellow,
        ),
        DaemonState::Up(s) if s.network_running => {
            ("Sync on: paired devices can connect", Color::Green)
        }
        DaemonState::Up(s) if s.locked => ("Locked: Settings > Data key unlocks it", Color::Yellow),
        DaemonState::Up(s) if is_fresh(s) => (
            "New device: n joins a group (or set both passwords to start one)",
            Color::Cyan,
        ),
        DaemonState::Up(s) if s.sync_enabled => (
            "Sync on, but networking failed: see the daemon log",
            Color::Red,
        ),
        DaemonState::Up(_) => ("Sync off: Settings > Sync", Color::DarkGray),
        _ => ("Daemon not reachable", Color::DarkGray),
    };
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!("  {activity}"),
        Style::default().fg(color),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  n: add device / join    x: stop / cancel join",
        Style::default().fg(Color::DarkGray),
    )));

    frame.render_widget(
        Paragraph::new(lines).block(
            Block::bordered()
                .title(" Details ")
                .border_type(BorderType::Rounded),
        ),
        detail_area,
    );
}

fn render_settings(frame: &mut Frame, area: Rect, app: &App) {
    let outer_block = Block::bordered()
        .title(" Settings ")
        .border_type(BorderType::Rounded);
    let inner = outer_block.inner(area);
    frame.render_widget(outer_block, area);

    let [_, list_area] = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(inner);

    const LABEL_WIDTH: usize = 30;
    let settings = app.active_settings();
    let items: Vec<ListItem> = settings
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let selected = i == app.settings_selected;
            let label_style = if selected {
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Reset)
            };
            let (val_str, val_color) = s.display_value();
            let label = format!("  {:<LABEL_WIDTH$}", s.label);
            ListItem::new(Line::from(vec![
                Span::styled(label, label_style),
                Span::styled(val_str, Style::default().fg(val_color)),
            ]))
        })
        .collect();

    let mut list_state = ListState::default();
    list_state.select(Some(app.settings_selected));

    frame.render_stateful_widget(
        List::new(items)
            .highlight_style(Style::default().bg(Color::DarkGray))
            .highlight_symbol("▶ "),
        list_area,
        &mut list_state,
    );
}

fn render_logs(frame: &mut Frame, area: Rect, app: &mut App) {
    let inner_height = area.height.saturating_sub(2) as usize;

    if app.log_follow {
        app.log_scroll = to_u16(app.logs.len().saturating_sub(inner_height));
    }

    let lines: Vec<Line> = app
        .logs
        .iter()
        .map(|entry| {
            let color = if entry.contains("ERROR") {
                Color::Red
            } else if entry.contains("WARN") {
                Color::Yellow
            } else if entry.contains("DEBUG") {
                Color::DarkGray
            } else {
                Color::Reset
            };
            Line::from(Span::styled(entry.as_str(), Style::default().fg(color)))
        })
        .collect();

    let title = if app.log_follow {
        " Logs [follow] "
    } else {
        " Logs "
    };

    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::bordered()
                    .title(title)
                    .border_type(BorderType::Rounded),
            )
            .scroll((app.log_scroll, 0)),
        area,
    );
}

fn render_statusbar(frame: &mut Frame, area: Rect, app: &App) {
    let help = match app.active_tab {
        Tab::Devices => " q:Quit  Tab:Switch  ↑↓:Select  n:Add device/Join  x:Stop ",
        Tab::Settings => " q:Quit  Tab:Switch  ↑↓:Navigate  Enter:Edit ",
        Tab::Logs => " q:Quit  Tab:Switch  ↑↓:Scroll  f:Follow ",
    };

    let (daemon_str, daemon_color) = match &app.daemon {
        DaemonState::Unknown => ("daemon: …".to_owned(), Color::DarkGray),
        DaemonState::Up(s) if s.locked && s.unlock_wait_secs > 0 => (
            format!(
                "daemon: locked, too many wrong passwords: try again in {} s",
                s.unlock_wait_secs
            ),
            Color::Red,
        ),
        DaemonState::Up(s) if s.locked => (
            "daemon: locked, enter the data password".to_owned(),
            Color::Yellow,
        ),
        DaemonState::Up(s) => (
            format!(
                "daemon: keys {}/2 {}, network {}, {} paired",
                u8::from(s.auth_key_set).saturating_add(u8::from(s.data_key_set)),
                if s.saved {
                    "(saved, encrypted)"
                } else {
                    "(memory only)"
                },
                match (s.network_running, s.adding_device, s.sync_enabled) {
                    _ if s.joining => "joining a group",
                    (true, true, _) => "on, adding a device",
                    (true, false, _) => "on",
                    // switched on, but the listener couldn't start (see the daemon log)
                    (false, _, true) => "failed",
                    (false, _, false) => "off",
                },
                s.trusted_peers
            ),
            Color::Green,
        ),
        DaemonState::Down(_) => ("daemon: not reachable".to_owned(), Color::Yellow),
        DaemonState::NoLink => ("daemon: link stopped".to_owned(), Color::Red),
    };

    let status_str = format!(" {daemon_str}");

    // each on its own full-width line: the state can be as long as it
    // needs (it is cut at the edge), the keys are never covered
    let [status_area, help_area] =
        Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(area);

    frame.render_widget(
        Paragraph::new(status_str).style(Style::default().fg(daemon_color)),
        status_area,
    );
    frame.render_widget(
        Paragraph::new(help).style(Style::default().fg(Color::DarkGray)),
        help_area,
    );
}

fn render_pairing_popup(frame: &mut Frame, area: Rect, prompt: &PairingPrompt) {
    let w = 68u16.min(area.width);
    let h = 13u16.min(area.height);
    let popup = centered_rect(area, w, h);

    let cells = pairing_code_cells(prompt);
    let code_style = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD);
    // two rows of four, each cell padded so the columns line up
    let code_line = |row: &[String]| {
        Line::from(Span::styled(
            format!(
                "  {}",
                row.iter()
                    .map(|cell| format!("{cell:<14}"))
                    .collect::<String>()
            ),
            code_style,
        ))
    };
    let (first, second) = cells.split_at(cells.len().min(4));

    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::styled(prompt.name.as_str(), Style::default().fg(Color::Yellow)),
            Span::raw(" wants to pair with this device."),
        ]),
        Line::from("  Check that the other device shows exactly this code:"),
        Line::from(""),
        code_line(first),
        code_line(second),
        Line::from(""),
        Line::from(Span::styled(
            "  Different code, or you didn't start this? Reject it.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(vec![
            Span::styled(
                "  y",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                ": they match, pair   ",
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                "n/Esc",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::styled(": reject", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(Span::styled(
            "  No answer within 60 s rejects.",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::bordered()
                .title(" Pair new device? ")
                .title_alignment(Alignment::Center)
                .border_type(BorderType::Double)
                .style(Style::default().fg(Color::Cyan)),
        ),
        popup,
    );
}

fn render_edit_setting_popup(frame: &mut Frame, area: Rect, app: &App) {
    let Some(setting) = app.active_settings().get(app.settings_selected) else {
        return;
    };

    let is_secret = matches!(
        setting.kind,
        SettingKind::Secret { .. } | SettingKind::Locked
    );
    let display_input = if is_secret {
        // one star per character, the byte length would leak more than the length
        "*".repeat(app.input_buf.chars().count())
    } else {
        app.input_buf.to_string()
    };

    let title = format!(" Edit: {} ", setting.label);
    let w = to_u16(title.len())
        .saturating_add(10)
        .max(52)
        .min(area.width);
    let h = 5u16.min(area.height);
    let popup = centered_rect(area, w, h);

    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(format!(" {}", display_input)).block(
            Block::bordered()
                .title(title)
                .title_alignment(Alignment::Center)
                .border_type(BorderType::Double)
                .style(Style::default().fg(Color::Cyan)),
        ),
        popup,
    );

    frame.set_cursor_position((
        popup
            .x
            .saturating_add(2)
            .saturating_add(to_u16(display_input.len())),
        popup.y.saturating_add(1),
    ));
}

fn render_join_popup(frame: &mut Frame, area: Rect, step: JoinStep, app: &App) {
    let (title, which) = match step {
        JoinStep::Auth => (" Join a group (1/2) ", "auth"),
        JoinStep::Data => (" Join a group (2/2) ", "data"),
    };
    // one star per character, the byte length would leak more than the length
    let stars = "*".repeat(app.input_buf.chars().count());

    let w = 64u16.min(area.width);
    let h = 8u16.min(area.height);
    let popup = centered_rect(area, w, h);

    let lines = vec![
        Line::from(Span::styled(
            "  On a device of the group: Devices > n (Add device) first.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            format!("  The group's {which} password:"),
            Style::default().fg(Color::Cyan),
        )),
        Line::from(format!("  {stars}")),
        Line::from(""),
        Line::from(Span::styled(
            "  Enter: next   Esc: cancel",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::bordered()
                .title(title)
                .title_alignment(Alignment::Center)
                .border_type(BorderType::Double)
                .style(Style::default().fg(Color::Cyan)),
        ),
        popup,
    );

    frame.set_cursor_position((
        popup
            .x
            .saturating_add(3)
            .saturating_add(to_u16(stars.len())),
        popup.y.saturating_add(3),
    ));
}

fn render_confirm_change_popup(frame: &mut Frame, area: Rect, kind: KeyKind) {
    let name = match kind {
        KeyKind::Auth => "auth",
        KeyKind::Data => "data",
    };

    let w = 60u16.min(area.width);
    let h = 9u16.min(area.height);
    let popup = centered_rect(area, w, h);

    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("  Change the {name} password?"),
            Style::default().fg(Color::Yellow),
        )),
        Line::from(Span::styled(
            "  Every paired device must use the same new password,",
            Style::default().fg(Color::Yellow),
        )),
        Line::from(Span::styled(
            "  or it stops syncing with this one.",
            Style::default().fg(Color::Yellow),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "  y",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::styled(": yes, change it   ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                "Esc/n",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(": cancel", Style::default().fg(Color::DarkGray)),
        ]),
    ];

    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::bordered()
                .title(" Are you sure? ")
                .title_alignment(Alignment::Center)
                .border_type(BorderType::Double)
                .style(Style::default().fg(Color::Yellow)),
        ),
        popup,
    );
}

fn render_security_warning_popup(frame: &mut Frame, area: Rect, idx: usize, app: &App) {
    let Some(setting) = app.settings.get(idx) else {
        return;
    };
    let Some(warn_msg) = setting.warn_message else {
        return;
    };

    let w = 60u16.min(area.width);
    let h = 11u16.min(area.height);
    let popup = centered_rect(area, w, h);

    let mut lines = vec![Line::from("")];
    for msg_line in warn_msg.lines() {
        lines.push(Line::from(Span::styled(
            format!("  {}", msg_line),
            Style::default().fg(Color::Yellow),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Enable anyway?",
        Style::default().fg(Color::Reset),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(
            "  y",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
        Span::styled(": confirm   ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            "Esc/n",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(": cancel", Style::default().fg(Color::DarkGray)),
    ]));

    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::bordered()
                .title(" ⚠ Security Warning ")
                .title_alignment(Alignment::Center)
                .border_type(BorderType::Double)
                .style(Style::default().fg(Color::Yellow)),
        ),
        popup,
    );
}

// ── Main loop ─────────────────────────────────────────────────────────────────

pub fn run(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> io::Result<()> {
    let link = match DaemonLink::spawn() {
        Ok(link) => Some(link),
        Err(e) => {
            app.push_log(format!("[ERROR] Failed to start the daemon link: {e}"));
            app.daemon = DaemonState::NoLink;
            None
        }
    };
    let mut last_refresh: Option<Instant> = None;

    // say plainly how much the daemon is checked before a password goes to it
    if !cesa_conn_system::ipc::daemon_requirement_valid() {
        app.push_log(
            "[ERROR] CESA_IPC_DAEMON_CODE_REQUIREMENT doesn't parse (or this platform has no \
             code signing): every daemon is refused, rebuild with a valid requirement",
        );
    } else if !cesa_conn_system::ipc::daemon_signature_checked() {
        app.push_log(if cfg!(target_os = "macos") {
            "[ WARN] Daemon signature check disabled (built without \
             CESA_IPC_DAEMON_CODE_REQUIREMENT): any process of this user holding the socket \
             would receive your passwords"
        } else {
            "[ WARN] No OS code signing here: the daemon is checked by user id only"
        });
    }

    loop {
        if let Some(link) = &link {
            pump_link(app, link, &mut last_refresh);
        }

        terminal.draw(|frame| ui(frame, app))?;
        if event::poll(Duration::from_millis(50))? {
            handle_input(app)?;
        }
        if app.should_quit {
            return Ok(());
        }
    }
}

/// Refreshes on schedule, hands queued commands to the link and applies
/// whatever came back. Never blocks.
fn pump_link(app: &mut App, link: &DaemonLink, last_refresh: &mut Option<Instant>) {
    if app.daemon == DaemonState::NoLink {
        return;
    }

    let due = last_refresh.is_none_or(|t| t.elapsed() >= Duration::from_secs(REFRESH_INTERVAL));
    if due {
        app.request_refresh();
        *last_refresh = Some(Instant::now());
    }

    // taken out first; anything not sent (a password too) is wiped on drop
    for command in std::mem::take(&mut app.outbox) {
        if !link.send(command) {
            handle_link_event(app, LinkEvent::WorkerStopped);
            return;
        }
    }

    while let Some(event) = link.try_recv() {
        let stopped = event == LinkEvent::WorkerStopped;

        handle_link_event(app, event);

        if stopped {
            return;
        }
    }
}

/// First bytes of a peer's key as hex, for display.
fn fingerprint_hex(fingerprint: &[u8]) -> String {
    fingerprint.iter().map(|b| format!("{b:02x}")).collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Next index in a list of `len` items, wrapping to 0 (len 0 -> 0).
fn wrap_next(i: usize, len: usize) -> usize {
    i.saturating_add(1).checked_rem(len).unwrap_or(0)
}

/// Previous index in a list of `len` items, wrapping to the last one.
fn wrap_prev(i: usize, len: usize) -> usize {
    i.checked_sub(1).unwrap_or(len.saturating_sub(1))
}

/// usize -> u16 for terminal coordinates, clamped instead of truncated.
fn to_u16(n: usize) -> u16 {
    u16::try_from(n).unwrap_or(u16::MAX)
}

/// A `w` x `h` rect centered in `area` (no overflow/underflow).
fn centered_rect(area: Rect, w: u16, h: u16) -> Rect {
    Rect::new(
        area.x.saturating_add(area.width.saturating_sub(w) / 2),
        area.y.saturating_add(area.height.saturating_sub(h) / 2),
        w,
        h,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that input stops at INPUT_CAPACITY, so the buffer never reallocates
    #[test]
    fn test_input_never_outgrows_its_buffer() {
        let mut app = App::new();
        let capacity = app.input_buf.capacity();

        for _ in 0..(INPUT_CAPACITY * 2) {
            push_input(&mut app, 'ą'); // 2 bytes in UTF-8
        }

        assert!(app.input_buf.len() <= INPUT_CAPACITY);
        assert_eq!(app.input_buf.capacity(), capacity);
    }

    /// Test that clearing wipes the input and keeps the allocation
    #[test]
    fn test_clear_input_wipes() {
        let mut app = App::new();
        let capacity = app.input_buf.capacity();

        for c in "hunter2".chars() {
            push_input(&mut app, c);
        }
        clear_input(&mut app);

        assert!(app.input_buf.is_empty());
        assert_eq!(app.input_buf.capacity(), capacity);
    }

    // ── App::new ──────────────────────────────────────────────────────────

    #[test]
    fn new_starts_with_empty_state() {
        let app = App::new();
        assert!(app.peers.is_empty());
        assert!(app.logs.is_empty());
        assert!(!app.should_quit);
    }

    /// Test that only settings the daemon really has are offered: no
    /// switch or field that does nothing
    #[test]
    fn new_has_only_real_settings() {
        let app = App::new();
        let labels: Vec<_> = app.settings.iter().map(|s| s.label).collect();
        assert_eq!(
            labels,
            [AUTH_KEY_LABEL, DATA_KEY_LABEL, AUTO_LOGIN_LABEL, SYNC_LABEL]
        );
    }

    // ── Settings display ──────────────────────────────────────────────────

    #[test]
    fn secret_unconfigured_shows_not_configured() {
        let s = Setting {
            label: "Auth key",
            kind: SettingKind::Secret { configured: false },
            warn_message: None,
        };
        let (text, _) = s.display_value();
        assert_eq!(text, "[not configured]");
    }

    #[test]
    fn secret_configured_shows_configured() {
        let s = Setting {
            label: "Auth key",
            kind: SettingKind::Secret { configured: true },
            warn_message: None,
        };
        let (text, _) = s.display_value();
        assert_eq!(text, "[configured]");
    }

    #[test]
    fn bool_setting_shows_on_off() {
        let on = Setting {
            label: "x",
            kind: SettingKind::Bool(true),
            warn_message: None,
        };
        let off = Setting {
            label: "x",
            kind: SettingKind::Bool(false),
            warn_message: None,
        };
        assert_eq!(on.display_value().0, "on");
        assert_eq!(off.display_value().0, "off");
    }

    // ── daemon link ───────────────────────────────────────────────────────

    fn select(app: &mut App, label: &str) {
        app.settings_selected = app
            .active_settings()
            .iter()
            .position(|s| s.label == label)
            .unwrap();
    }

    fn up(auth: bool, data: bool) -> LinkEvent {
        LinkEvent::Refreshed(Ok((
            Status {
                auth_key_set: auth,
                data_key_set: data,
                network_running: false,
                trusted_peers: 1,
                ..Status::default()
            },
            vec![PeerInfo {
                fingerprint: [0xab; 8],
                name: "laptop".into(),
            }],
            None,
        )))
    }

    fn type_and_enter(app: &mut App, text: &str) {
        app.active_popup = ActivePopup::EditSetting;
        for c in text.chars() {
            handle_edit_setting_input(app, KeyCode::Char(c));
        }
        handle_edit_setting_input(app, KeyCode::Enter);
    }

    /// Test that a typed password goes out exactly as typed (spaces kept),
    /// the input is wiped, nothing salt-like exists in the UI, the password is
    /// never logged, and "configured" waits for the daemon
    #[test]
    fn test_password_sent_as_typed_and_wiped() {
        let mut app = App::new();
        select(&mut app, AUTH_KEY_LABEL);

        type_and_enter(&mut app, " hunter two 2 ");

        let [Command::SetPassword { kind, update }] = app.outbox.as_slice() else {
            panic!("expected one SetPassword command");
        };
        assert_eq!(*kind, KeyKind::Auth);
        assert_eq!(update.password.as_slice(), b" hunter two 2 ");

        assert!(app.input_buf.is_empty());
        assert!(!app.logs.iter().any(|l| l.contains("hunter")));
        assert!(
            !app.settings
                .iter()
                .any(|s| s.label.to_lowercase().contains("salt"))
        );
        assert_eq!(
            app.setting_mut(AUTH_KEY_LABEL).unwrap().kind,
            SettingKind::Secret { configured: false }
        );
    }

    /// Test that the data key setting sends a data password, and an empty one nothing
    #[test]
    fn test_data_password_and_empty_input() {
        let mut app = App::new();
        select(&mut app, DATA_KEY_LABEL);

        type_and_enter(&mut app, "");
        assert!(app.outbox.is_empty());

        type_and_enter(&mut app, "data password 1");
        assert!(matches!(
            app.outbox.as_slice(),
            [Command::SetPassword {
                kind: KeyKind::Data,
                ..
            }]
        ));
    }

    fn up_locked(locked: bool, auto_login: bool) -> LinkEvent {
        LinkEvent::Refreshed(Ok((
            Status {
                locked,
                saved: true,
                auto_login,
                auth_key_set: !locked,
                data_key_set: !locked,
                ..Status::default()
            },
            Vec::new(),
            None,
        )))
    }

    /// Test that a new password below the minimum is not sent at all
    #[test]
    fn test_short_new_password_not_sent() {
        let mut app = App::new();
        select(&mut app, DATA_KEY_LABEL);

        type_and_enter(&mut app, &"a".repeat(MIN_NEW_PASSWORD_LEN - 1));

        assert!(app.outbox.is_empty());
        assert!(app.input_buf.is_empty());
        assert!(app.logs.iter().any(|l| l.contains("at least")));
    }

    /// Test that while the vault is locked the data key field unlocks (any
    /// length: it must accept the existing password), the auth key sends nothing
    #[test]
    fn test_locked_unlocks_with_data_password() {
        let mut app = App::new();
        handle_link_event(&mut app, up_locked(true, false));

        assert_eq!(
            app.setting_mut(DATA_KEY_LABEL).unwrap().kind,
            SettingKind::Locked
        );
        assert!(app.logs.iter().any(|l| l.contains("locked")));

        select(&mut app, AUTH_KEY_LABEL);
        type_and_enter(&mut app, "auth password 1");
        assert!(app.outbox.is_empty());

        select(&mut app, DATA_KEY_LABEL);
        type_and_enter(&mut app, "data password 1");
        let [Command::Unlock(update)] = app.outbox.as_slice() else {
            panic!("expected one Unlock command");
        };
        assert_eq!(update.password.as_slice(), b"data password 1");
        assert!(app.input_buf.is_empty());
        assert!(!app.logs.iter().any(|l| l.contains("data password 1")));
    }

    /// Test that automatic login is asked of the daemon (after the warning),
    /// and the switch shows only what the daemon reports
    #[test]
    fn test_auto_login_goes_through_daemon() {
        let mut app = App::new();
        handle_link_event(&mut app, up_locked(false, false));
        select(&mut app, AUTO_LOGIN_LABEL);
        let idx = app.settings_selected;

        // turning on shows the warning first
        handle_settings_enter(&mut app);
        assert_eq!(app.active_popup, ActivePopup::SecurityWarning { idx });
        handle_security_warning_input(&mut app, KeyCode::Char('n'), idx);
        assert!(app.outbox.is_empty());

        handle_settings_enter(&mut app);
        handle_security_warning_input(&mut app, KeyCode::Char('y'), idx);
        assert!(matches!(
            app.outbox.as_slice(),
            [Command::SetAutoLogin(true)]
        ));
        // not on until the daemon says so
        assert_eq!(
            app.setting_mut(AUTO_LOGIN_LABEL).unwrap().kind,
            SettingKind::Bool(false)
        );

        app.outbox.clear();
        handle_link_event(&mut app, up_locked(false, true));
        assert_eq!(
            app.setting_mut(AUTO_LOGIN_LABEL).unwrap().kind,
            SettingKind::Bool(true)
        );

        // turning off: no warning, straight to the daemon
        handle_settings_enter(&mut app);
        assert!(matches!(
            app.outbox.as_slice(),
            [Command::SetAutoLogin(false)]
        ));
    }

    /// Test that a wrong data password on unlock is reported clearly
    #[test]
    fn test_wrong_unlock_password_reported() {
        let mut app = App::new();
        handle_link_event(
            &mut app,
            LinkEvent::Unlocked(Err(IpcErrors::Daemon(DaemonError::WrongPassword))),
        );
        assert!(app.logs.iter().any(|l| l.contains("Wrong data password")));
        assert!(matches!(app.outbox.as_slice(), [Command::Refresh]));
    }

    /// Test that while the daemon refuses unlocks, the unlock field doesn't
    /// open and nothing is sent; the status bar shows the wait
    #[test]
    fn test_unlock_wait_blocks_unlock() {
        let mut app = App::new();
        handle_link_event(
            &mut app,
            LinkEvent::Refreshed(Ok((
                Status {
                    locked: true,
                    saved: true,
                    unlock_wait_secs: 32,
                    ..Status::default()
                },
                Vec::new(),
                None,
            ))),
        );
        app.outbox.clear();
        app.active_tab = Tab::Settings;
        select(&mut app, DATA_KEY_LABEL);

        handle_settings_enter(&mut app);
        assert_eq!(app.active_popup, ActivePopup::None);
        assert!(app.logs.iter().any(|l| l.contains("try again in 32 s")));

        // a field opened just before the wait started sends nothing either
        type_and_enter(&mut app, "data password 1");
        assert!(app.outbox.is_empty());
        assert!(app.input_buf.is_empty());

        // once the wait is over, unlocking works again
        handle_link_event(&mut app, up_locked(true, false));
        app.outbox.clear();
        type_and_enter(&mut app, "data password 1");
        assert!(matches!(app.outbox.as_slice(), [Command::Unlock(_)]));
    }

    /// Test that a refused (delayed) unlock is reported as a wait, not a failure
    #[test]
    fn test_delayed_unlock_reported() {
        let mut app = App::new();
        handle_link_event(
            &mut app,
            LinkEvent::Unlocked(Err(IpcErrors::Daemon(DaemonError::UnlockDelayed))),
        );
        assert!(
            app.logs
                .iter()
                .any(|l| l.contains("Too many wrong data passwords"))
        );
        assert!(matches!(app.outbox.as_slice(), [Command::Refresh]));
    }

    /// Test that changing a password that is already set asks first, before
    /// anything is typed; n cancels, y opens the password field
    #[test]
    fn test_password_change_asks_first() {
        let mut app = App::new();
        handle_link_event(&mut app, up(true, true));
        select(&mut app, DATA_KEY_LABEL);

        handle_settings_enter(&mut app);
        assert_eq!(
            app.active_popup,
            ActivePopup::ConfirmPasswordChange(KeyKind::Data)
        );

        // typing while asked goes nowhere
        handle_confirm_change_input(&mut app, KeyCode::Char('x'));
        assert!(app.input_buf.is_empty());

        handle_confirm_change_input(&mut app, KeyCode::Char('n'));
        assert_eq!(app.active_popup, ActivePopup::None);
        assert!(app.outbox.is_empty());

        handle_settings_enter(&mut app);
        handle_confirm_change_input(&mut app, KeyCode::Char('y'));
        assert_eq!(app.active_popup, ActivePopup::EditSetting);
    }

    /// Test that first-time setup and unlocking don't ask
    #[test]
    fn test_setup_and_unlock_dont_ask() {
        let mut app = App::new();
        select(&mut app, AUTH_KEY_LABEL);
        handle_settings_enter(&mut app);
        assert_eq!(app.active_popup, ActivePopup::EditSetting);

        let mut app = App::new();
        handle_link_event(&mut app, up_locked(true, false));
        select(&mut app, DATA_KEY_LABEL);
        handle_settings_enter(&mut app);
        assert_eq!(app.active_popup, ActivePopup::EditSetting);
    }

    /// Test that daemon status drives the key flags and the paired list
    #[test]
    fn test_status_updates_flags_and_peers() {
        let mut app = App::new();
        app.request_refresh();

        handle_link_event(&mut app, up(true, false));

        assert!(matches!(app.daemon, DaemonState::Up(_)));
        assert!(!app.refresh_in_flight);
        assert_eq!(app.peers.len(), 1);
        assert_eq!(
            app.setting_mut(AUTH_KEY_LABEL).unwrap().kind,
            SettingKind::Secret { configured: true }
        );
        assert_eq!(
            app.setting_mut(DATA_KEY_LABEL).unwrap().kind,
            SettingKind::Secret { configured: false }
        );
    }

    /// Test that a lost daemon clears what we knew and is logged once, not per refresh
    #[test]
    fn test_daemon_down_clears_state_and_logs_once() {
        let mut app = App::new();
        handle_link_event(&mut app, up(true, true));

        for _ in 0..3 {
            handle_link_event(
                &mut app,
                LinkEvent::Refreshed(Err(IpcErrors::FailedToConnect)),
            );
        }

        assert_eq!(app.daemon, DaemonState::Down(IpcErrors::FailedToConnect));
        assert!(app.peers.is_empty());
        assert_eq!(
            app.setting_mut(AUTH_KEY_LABEL).unwrap().kind,
            SettingKind::Secret { configured: false }
        );
        assert_eq!(
            app.logs
                .iter()
                .filter(|l| l.contains("not reachable"))
                .count(),
            1
        );
    }

    /// Test that refreshes don't pile up while one is in flight
    #[test]
    fn test_refresh_not_stacked() {
        let mut app = App::new();

        app.request_refresh();
        app.request_refresh();
        assert_eq!(app.outbox.len(), 1);

        handle_link_event(&mut app, up(false, false));
        app.request_refresh();
        assert_eq!(app.outbox.len(), 2);
    }

    /// A refresh where networking runs and `pairing` waits for the user.
    fn up_network(sync: bool, pairing: Option<PairingPrompt>) -> LinkEvent {
        LinkEvent::Refreshed(Ok((
            Status {
                auth_key_set: true,
                data_key_set: true,
                saved: true,
                network_running: sync,
                sync_enabled: sync,
                pending_pairings: u8::from(pairing.is_some()),
                ..Status::default()
            },
            Vec::new(),
            pairing,
        )))
    }

    fn prompt(id: u32) -> PairingPrompt {
        PairingPrompt {
            id,
            name: "192.168.1.7:50123".into(),
            code: [0, 9, 18, 27, 36, 45, 54, 63],
        }
    }

    /// Test that the Sync switch follows the daemon and Enter asks the
    /// daemon to flip it (nothing changes locally)
    #[test]
    fn test_sync_switch_goes_through_daemon() {
        let mut app = App::new();
        handle_link_event(&mut app, up_network(true, None));
        assert_eq!(
            app.setting_mut(SYNC_LABEL).unwrap().kind,
            SettingKind::Bool(true)
        );

        app.outbox.clear();
        select(&mut app, SYNC_LABEL);
        handle_settings_enter(&mut app);
        assert!(matches!(app.outbox.as_slice(), [Command::SetSync(false)]));
        // still on until the daemon says otherwise
        assert_eq!(
            app.setting_mut(SYNC_LABEL).unwrap().kind,
            SettingKind::Bool(true)
        );

        handle_link_event(&mut app, up_network(false, None));
        app.outbox.clear();
        handle_settings_enter(&mut app);
        assert!(matches!(app.outbox.as_slice(), [Command::SetSync(true)]));
    }

    /// Test that "Add device" goes to the daemon only while networking runs
    #[test]
    fn test_add_device_needs_networking() {
        let mut app = App::new();
        handle_link_event(&mut app, up_network(false, None));
        app.outbox.clear();

        start_add_device(&mut app);
        assert!(app.outbox.is_empty());
        assert!(app.logs.iter().any(|l| l.contains("Turn Sync on")));

        handle_link_event(&mut app, up_network(true, None));
        app.outbox.clear();
        start_add_device(&mut app);
        assert!(matches!(app.outbox.as_slice(), [Command::AddDevice]));
    }

    fn fresh_status(joining: bool) -> LinkEvent {
        LinkEvent::Refreshed(Ok((
            Status {
                joining,
                ..Status::default()
            },
            Vec::new(),
            None,
        )))
    }

    fn type_text(app: &mut App, text: &str) {
        for c in text.chars() {
            let popup = app.active_popup.clone();
            if let ActivePopup::JoinGroup(step) = popup {
                handle_join_input(app, KeyCode::Char(c), step);
            }
        }
    }

    fn press_in_join(app: &mut App, code: KeyCode) {
        let ActivePopup::JoinGroup(step) = app.active_popup.clone() else {
            panic!("the join popup isn't open");
        };
        handle_join_input(app, code, step);
    }

    /// Test that n on a fresh device asks for both group passwords and
    /// sends them exactly as typed, wiping the kept auth password
    #[test]
    fn test_join_on_fresh_device() {
        let mut app = App::new();
        handle_link_event(&mut app, fresh_status(false));
        app.outbox.clear();

        start_add_device(&mut app);
        assert_eq!(app.active_popup, ActivePopup::JoinGroup(JoinStep::Auth));

        // an empty Enter does nothing
        press_in_join(&mut app, KeyCode::Enter);
        assert_eq!(app.active_popup, ActivePopup::JoinGroup(JoinStep::Auth));

        type_text(&mut app, " auth pw ");
        press_in_join(&mut app, KeyCode::Enter);
        assert_eq!(app.active_popup, ActivePopup::JoinGroup(JoinStep::Data));
        assert!(app.input_buf.is_empty());

        type_text(&mut app, "data pw");
        press_in_join(&mut app, KeyCode::Enter);
        assert_eq!(app.active_popup, ActivePopup::None);
        assert!(app.join_auth.is_empty());
        assert!(app.input_buf.is_empty());

        let [Command::JoinGroup(sent)] = app.outbox.as_slice() else {
            panic!("no JoinGroup sent");
        };
        assert_eq!(sent.auth.password.as_slice(), b" auth pw ");
        assert_eq!(sent.data.password.as_slice(), b"data pw");
    }

    /// Test that Esc in the join popup sends nothing and wipes the kept
    /// auth password
    #[test]
    fn test_join_cancelled_in_popup_wipes() {
        let mut app = App::new();
        handle_link_event(&mut app, fresh_status(false));
        app.outbox.clear();
        start_add_device(&mut app);

        type_text(&mut app, "auth secret");
        press_in_join(&mut app, KeyCode::Enter);
        assert_eq!(app.join_auth.as_slice(), b"auth secret");
        type_text(&mut app, "half");
        press_in_join(&mut app, KeyCode::Esc);

        assert_eq!(app.active_popup, ActivePopup::None);
        assert!(app.join_auth.is_empty());
        assert!(app.input_buf.is_empty());
        assert!(app.outbox.is_empty());
    }

    /// Test that a device with keys never offers a join, and that x cancels
    /// a running join (only then; with networking off there is nothing to
    /// stop)
    #[test]
    fn test_join_only_fresh_and_cancel() {
        let mut app = App::new();
        handle_link_event(&mut app, up_network(false, None));
        app.outbox.clear();
        start_add_device(&mut app);
        assert_eq!(app.active_popup, ActivePopup::None);
        assert!(app.outbox.is_empty());

        stop_or_cancel(&mut app);
        assert!(app.outbox.is_empty());

        handle_link_event(&mut app, fresh_status(true));
        app.outbox.clear();
        start_add_device(&mut app);
        assert_eq!(app.active_popup, ActivePopup::None);
        stop_or_cancel(&mut app);
        assert!(matches!(app.outbox.as_slice(), [Command::CancelJoin]));

        // the end of the join is reported
        handle_link_event(&mut app, fresh_status(false));
        assert!(app.logs.iter().any(|l| l.contains("ended without joining")));
    }

    /// Test that x stops "Add device" whenever networking runs (also right
    /// after n, before the status shows the window), and that the stop is
    /// reported back
    #[test]
    fn test_x_stops_add_device() {
        let mut app = App::new();
        handle_link_event(&mut app, up_network(true, None));
        app.outbox.clear();

        start_add_device(&mut app);
        stop_or_cancel(&mut app);
        assert!(matches!(
            app.outbox.as_slice(),
            [Command::AddDevice, Command::StopAddDevice]
        ));

        app.outbox.clear();
        handle_link_event(&mut app, LinkEvent::AddDeviceStopped(Ok(())));
        assert!(matches!(app.outbox.as_slice(), [Command::Refresh]));
    }

    /// Test that a long daemon state never covers the key help: on a narrow
    /// terminal every key of the Devices tab is still shown in full
    #[test]
    fn test_statusbar_keys_never_covered() {
        use ratatui::{Terminal, backend::TestBackend};

        let mut app = App::new();
        handle_link_event(&mut app, up_network(true, None));
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|frame| ui(frame, &mut app)).unwrap();

        let buffer = terminal.backend().buffer();
        let row = |y: u16| -> String {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect()
        };
        let (status, keys) = (row(22), row(23));

        assert!(status.contains("daemon: keys 2/2"), "status: {status}");
        for key in ["q:Quit", "n:Add device/Join", "x:Stop"] {
            assert!(keys.contains(key), "{key} missing in: {keys}");
        }
    }

    fn screen(app: &mut App) -> String {
        use ratatui::{Terminal, backend::TestBackend};

        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|frame| ui(frame, app)).unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    fn status_with(peers: &[&str], status: Status) -> LinkEvent {
        LinkEvent::Refreshed(Ok((
            status,
            peers
                .iter()
                .enumerate()
                .map(|(i, name)| PeerInfo {
                    fingerprint: [u8::try_from(i).unwrap(); 8],
                    name: (*name).into(),
                })
                .collect(),
            None,
        )))
    }

    /// Test that the Devices tab lists the daemon's paired devices with the
    /// selected one's details and what this device is doing now, and has no
    /// made-up "connected" count
    #[test]
    fn test_devices_tab_shows_paired_and_activity() {
        let mut app = App::new();
        let mut status = Status {
            auth_key_set: true,
            data_key_set: true,
            saved: true,
            network_running: true,
            sync_enabled: true,
            trusted_peers: 2,
            ..Status::default()
        };
        handle_link_event(&mut app, status_with(&["laptop", "phone"], status));

        let shown = screen(&mut app);
        assert!(shown.contains("laptop") && shown.contains("phone"));
        assert!(shown.contains(&fingerprint_hex(&[0; 8])));
        assert!(shown.contains("Sync on"));
        assert!(!shown.contains("connected"));

        app.next_peer();
        assert!(screen(&mut app).contains(&fingerprint_hex(&[1; 8])));

        status.adding_device = true;
        handle_link_event(&mut app, status_with(&["laptop", "phone"], status));
        assert!(screen(&mut app).contains("Add device is open"));

        // the hint fits the state: a fresh device joins, a locked one unlocks
        handle_link_event(&mut app, status_with(&[], Status::default()));
        assert!(screen(&mut app).contains("n joins a group"));
        let locked = Status {
            locked: true,
            saved: true,
            ..Status::default()
        };
        handle_link_event(&mut app, status_with(&[], locked));
        assert!(screen(&mut app).contains("Locked"));
    }

    /// Test that a device of another group is reported once in the log and
    /// shown on the Devices tab while the window is open
    #[test]
    fn test_other_group_hint() {
        let mut app = App::new();
        let mut status = Status {
            auth_key_set: true,
            data_key_set: true,
            saved: true,
            network_running: true,
            sync_enabled: true,
            adding_device: true,
            other_group_nearby: true,
            ..Status::default()
        };
        handle_link_event(&mut app, status_with(&[], status));
        handle_link_event(&mut app, status_with(&[], status));

        let hints = app
            .logs
            .iter()
            .filter(|l| l.contains("different group"))
            .count();
        assert_eq!(hints, 1);
        assert!(screen(&mut app).contains("another group"));

        status.other_group_nearby = false;
        handle_link_event(&mut app, status_with(&[], status));
        assert!(!screen(&mut app).contains("another group"));
    }

    /// Test that the selection follows the list: it moves back when the
    /// selected device goes, and there is none when the list is empty
    #[test]
    fn test_peer_selection_clamped() {
        let mut app = App::new();
        handle_link_event(&mut app, status_with(&["a", "b", "c"], Status::default()));
        assert_eq!(app.peer_list_state.selected(), Some(0));
        app.prev_peer();
        assert_eq!(app.selected_peer().unwrap().name, "c");

        handle_link_event(&mut app, status_with(&["a"], Status::default()));
        assert_eq!(app.selected_peer().unwrap().name, "a");

        handle_link_event(&mut app, status_with(&[], Status::default()));
        assert_eq!(app.peer_list_state.selected(), None);
        app.next_peer();
        assert!(app.selected_peer().is_none());
    }

    /// Test that the join popup shows stars, never the password
    #[test]
    fn test_join_popup_masks_password() {
        use ratatui::{Terminal, backend::TestBackend};

        let mut app = App::new();
        handle_link_event(&mut app, fresh_status(false));
        start_add_device(&mut app);
        type_text(&mut app, "topsecret");

        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|frame| ui(frame, &mut app)).unwrap();
        let screen: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect();

        assert!(screen.contains("Join a group (1/2)"));
        assert!(screen.contains("*********"));
        assert!(!screen.contains("topsecret"));
    }

    /// Test that a waiting pairing opens the prompt with every symbol's
    /// name, y / n answer exactly that pairing, and other keys do nothing
    #[test]
    fn test_pairing_prompt_answered() {
        let mut app = App::new();
        handle_link_event(&mut app, up_network(true, Some(prompt(4))));
        assert_eq!(app.active_popup, ActivePopup::Pairing(prompt(4)));

        let cells = pairing_code_cells(&prompt(4));
        assert_eq!(cells.len(), 8);
        assert_eq!(cells[0], "🐶 dog");
        assert_eq!(cells[7], "👑 crown");

        app.outbox.clear();
        handle_pairing_input(&mut app, KeyCode::Char('x'), &prompt(4));
        assert!(app.outbox.is_empty());
        assert_eq!(app.active_popup, ActivePopup::Pairing(prompt(4)));

        handle_pairing_input(&mut app, KeyCode::Char('y'), &prompt(4));
        assert!(matches!(
            app.outbox.as_slice(),
            [Command::AnswerPairing {
                id: 4,
                code: [0, 9, 18, 27, 36, 45, 54, 63],
                accept: true
            }]
        ));
        assert_eq!(app.active_popup, ActivePopup::None);

        // the next one, rejected with Esc
        handle_link_event(&mut app, up_network(true, Some(prompt(5))));
        app.outbox.clear();
        handle_pairing_input(&mut app, KeyCode::Esc, &prompt(5));
        assert!(matches!(
            app.outbox.as_slice(),
            [Command::AnswerPairing {
                id: 5,
                code: [0, 9, 18, 27, 36, 45, 54, 63],
                accept: false
            }]
        ));
    }

    /// Test that the drawn prompt shows the peer and every symbol's name
    /// (names survive terminals that draw emoji as boxes)
    #[test]
    fn test_pairing_popup_renders_names() {
        use ratatui::{Terminal, backend::TestBackend};

        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        let mut app = App::new();
        handle_link_event(&mut app, up_network(true, Some(prompt(3))));

        terminal.draw(|frame| ui(frame, &mut app)).unwrap();
        let screen: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect();

        assert!(screen.contains("Pair new device?"));
        assert!(screen.contains("192.168.1.7:50123"));
        for (_, name) in prompt(3)
            .code
            .iter()
            .filter_map(|&i| pairing_code::symbol(i))
        {
            assert!(screen.contains(name), "{name} not on screen");
        }
    }

    /// Test that a pairing never covers a half-typed password, and that a
    /// shown prompt the daemon dropped (expired) is closed
    #[test]
    fn test_pairing_prompt_waits_and_expires() {
        let mut app = App::new();
        app.active_popup = ActivePopup::EditSetting;
        handle_link_event(&mut app, up_network(true, Some(prompt(1))));
        assert_eq!(app.active_popup, ActivePopup::EditSetting);

        app.active_popup = ActivePopup::None;
        handle_link_event(&mut app, up_network(true, Some(prompt(1))));
        assert_eq!(app.active_popup, ActivePopup::Pairing(prompt(1)));

        // same id, another pairing (daemon restarted): the new code is shown
        let mut other = prompt(1);
        other.code = [1; 8];
        handle_link_event(&mut app, up_network(true, Some(other.clone())));
        assert_eq!(app.active_popup, ActivePopup::Pairing(other));

        handle_link_event(&mut app, up_network(true, None));
        assert_eq!(app.active_popup, ActivePopup::None);
        assert!(app.logs.iter().any(|l| l.contains("expired")));
    }

    /// Test that a finished password request triggers a fresh status
    #[test]
    fn test_password_result_refreshes() {
        let mut app = App::new();

        handle_link_event(
            &mut app,
            LinkEvent::PasswordSet {
                kind: KeyKind::Auth,
                result: Err(IpcErrors::Daemon(
                    cesa_conn_system::ipc::DaemonError::KeyDerivationFailed,
                )),
            },
        );

        assert!(app.logs.iter().any(|l| l.contains("ERROR")));
        assert!(matches!(app.outbox.as_slice(), [Command::Refresh]));
    }

    // ── push_log ──────────────────────────────────────────────────────────

    #[test]
    fn push_log_accepts_str_and_string() {
        let mut app = App::new();
        app.push_log("static str");
        app.push_log(String::from("owned string"));
        assert_eq!(app.logs.len(), 2);
    }
}
