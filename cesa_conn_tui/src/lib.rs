#![forbid(unsafe_code)]

//! CesaConn terminal UI.
//!
//! Talks to the daemon over IPC ([`daemon_link`]): passwords go to the daemon,
//! which derives and keeps the keys and their salts; the UI only shows status
//! and paired devices. It keeps nothing key-related: a typed password lives in
//! the zeroizing input buffer until Enter, is handed to the daemon link and
//! wiped right away.

mod daemon_link;
// the UI's parts: keys, the daemon's answers, drawing
mod events;
mod input;
mod render;

// shared by the parts (each one is `use super::*`)
use events::*;
use input::*;
use render::*;

use cesa_conn_system::ipc::{
    DaemonError, DeviceAddress, IpcErrors, JoinPasswords, MIN_NEW_PASSWORD_LEN, PairingPrompt,
    PasswordUpdate, PeerInfo, PeerState, Status,
};
use cesa_conn_system::pairing_code;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Clear, List, ListItem, ListState, Paragraph, Tabs, Wrap},
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
const CLIPBOARD_LABEL: &str = "Clipboard sync";
const RESET_LABEL: &str = "Reset this device";

/// What the user types to confirm a reset (a key press alone is too easy).
const RESET_WORD: &str = "RESET";

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
    /// A switch this platform doesn't support yet.
    Unavailable,
    /// Not a value: Enter starts something (after asking).
    Action,
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
            SettingKind::Unavailable => ("[not supported on this platform yet]", Color::DarkGray),
            SettingKind::Action => ("[Enter: wipe keys, vault, paired devices]", Color::Red),
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
    /// "Forget this device?" (y / n).
    ConfirmForget(PeerInfo),
    /// "Reset this device?": the user types [`RESET_WORD`].
    ConfirmReset,
    /// The daemon (re)started locked: the data password, asked for
    /// without a trip to Settings.
    Unlock,
    /// `a` on Devices: the IPv4 address of a device on another network (a
    /// VPN, a routed subnet) that discovery can't reach.
    DeviceAddress,
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
    /// Enter was pressed on a new password below the minimum: the edit
    /// popup stays open and says so (in red) until the input is cleared.
    password_too_short: bool,
    /// Enter was pressed on something that isn't a usable IP address: the
    /// address popup stays open and says so until the input is cleared.
    address_invalid: bool,
    /// The typed address a join goes through (`a` on a fresh device), kept
    /// while the two passwords are typed. Not a secret.
    join_at: Option<DeviceAddress>,
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
    /// The unlock prompt was shown for this locked spell (Esc keeps it
    /// closed; a wrong password or a new lock asks again).
    unlock_asked: bool,
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
                Setting {
                    label: CLIPBOARD_LABEL,
                    kind: SettingKind::Bool(false),
                    warn_message: None,
                },
                Setting {
                    label: RESET_LABEL,
                    kind: SettingKind::Action,
                    warn_message: None,
                },
            ],
            settings_selected: 0,
            logs: Vec::new(),
            log_scroll: 0,
            log_follow: true,
            active_popup: ActivePopup::None,
            input_buf: Zeroizing::new(String::with_capacity(INPUT_CAPACITY)),
            password_too_short: false,
            address_invalid: false,
            join_at: None,
            join_auth: Zeroizing::new(Vec::with_capacity(INPUT_CAPACITY)),
            should_quit: false,
            daemon: DaemonState::Unknown,
            peers: Vec::new(),
            outbox: Vec::new(),
            refresh_in_flight: false,
            unlock_asked: false,
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
            [
                AUTH_KEY_LABEL,
                DATA_KEY_LABEL,
                AUTO_LOGIN_LABEL,
                SYNC_LABEL,
                CLIPBOARD_LABEL,
                RESET_LABEL
            ]
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
                state: PeerState::Ok,
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
        assert!(app.logs.iter().any(|l| l.contains("too short")));
        // the popup stays open with what was typed, and says why in red
        assert_eq!(app.active_popup, ActivePopup::EditSetting);
        assert_eq!(app.input_buf.chars().count(), MIN_NEW_PASSWORD_LEN - 1);
        assert!(screen(&mut app).contains("Too short (11/12)"));

        // typing on to the minimum: long enough, sent, closed and wiped
        handle_edit_setting_input(&mut app, KeyCode::Char('a'));
        assert!(screen(&mut app).contains("long enough"));
        handle_edit_setting_input(&mut app, KeyCode::Enter);
        assert!(matches!(
            app.outbox.as_slice(),
            [Command::SetPassword { .. }]
        ));
        assert_eq!(app.active_popup, ActivePopup::None);
        assert!(app.input_buf.is_empty());
        assert!(!app.password_too_short);
    }

    /// Test that the new-password popup counts characters against the
    /// minimum while typing, and Esc wipes the input and the warning
    #[test]
    fn test_password_length_hint() {
        let mut app = App::new();
        select(&mut app, AUTH_KEY_LABEL);
        app.active_popup = ActivePopup::EditSetting;

        assert!(screen(&mut app).contains("0/12 characters"));
        for c in "abcde".chars() {
            handle_edit_setting_input(&mut app, KeyCode::Char(c));
        }
        assert!(screen(&mut app).contains("5/12 characters"));
        handle_edit_setting_input(&mut app, KeyCode::Enter);
        assert!(app.password_too_short);

        handle_edit_setting_input(&mut app, KeyCode::Esc);
        assert_eq!(app.active_popup, ActivePopup::None);
        assert!(app.input_buf.is_empty());
        assert!(!app.password_too_short);
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

    /// Locked, as after a daemon restart, with `wait` seconds until the
    /// daemon takes an unlock again.
    fn locked_with_wait(wait: u16) -> LinkEvent {
        LinkEvent::Refreshed(Ok((
            Status {
                locked: true,
                saved: true,
                unlock_wait_secs: wait,
                ..Status::default()
            },
            Vec::new(),
            None,
        )))
    }

    /// The passwords of the queued unlocks, borrowed (no copies).
    fn unlocks(app: &App) -> Vec<&[u8]> {
        app.outbox
            .iter()
            .filter_map(|c| match c {
                Command::Unlock(update) => Some(update.password.as_slice()),
                _ => None,
            })
            .collect()
    }

    /// Test that a locked daemon asks for the data password right away (on
    /// any tab), sends it exactly as typed, masks it and wipes the input
    #[test]
    fn test_unlock_prompt_on_start() {
        let mut app = App::new();
        app.active_tab = Tab::Logs;
        handle_link_event(&mut app, up_locked(true, false));
        assert_eq!(app.active_popup, ActivePopup::Unlock);

        for c in " data pw ".chars() {
            handle_unlock_input(&mut app, KeyCode::Char(c));
        }
        let shown = screen(&mut app);
        assert!(shown.contains("Data password") && shown.contains("*********"));
        assert!(!shown.contains("data pw"));

        handle_unlock_input(&mut app, KeyCode::Enter);
        assert_eq!(unlocks(&app), [b" data pw ".as_slice()]);
        assert!(app.input_buf.is_empty());
        assert_eq!(app.active_popup, ActivePopup::None);
        assert!(!app.logs.iter().any(|l| l.contains("data pw")));
    }

    /// Test that Esc keeps the prompt closed for this locked spell, a wrong
    /// password asks again, and a daemon that comes back locked asks again
    #[test]
    fn test_unlock_prompt_esc_and_retry() {
        let mut app = App::new();
        handle_link_event(&mut app, up_locked(true, false));
        handle_unlock_input(&mut app, KeyCode::Char('x'));
        handle_unlock_input(&mut app, KeyCode::Esc);
        assert_eq!(app.active_popup, ActivePopup::None);
        assert!(app.input_buf.is_empty());

        handle_link_event(&mut app, up_locked(true, false));
        assert_eq!(app.active_popup, ActivePopup::None);

        handle_link_event(
            &mut app,
            LinkEvent::Unlocked(Err(IpcErrors::Daemon(DaemonError::WrongPassword))),
        );
        handle_link_event(&mut app, up_locked(true, false));
        assert_eq!(app.active_popup, ActivePopup::Unlock);
        handle_unlock_input(&mut app, KeyCode::Esc);

        // the daemon went away and came back locked: a new spell
        handle_link_event(
            &mut app,
            LinkEvent::Refreshed(Err(IpcErrors::FailedToConnect)),
        );
        handle_link_event(&mut app, up_locked(true, false));
        assert_eq!(app.active_popup, ActivePopup::Unlock);
    }

    /// Test that the prompt waits while the daemon refuses unlocks, never
    /// covers another popup, and closes (wiped) once unlocked elsewhere
    #[test]
    fn test_unlock_prompt_waits_and_closes() {
        let mut app = App::new();
        handle_link_event(&mut app, locked_with_wait(30));
        assert_eq!(app.active_popup, ActivePopup::None);
        handle_link_event(&mut app, locked_with_wait(0));
        assert_eq!(app.active_popup, ActivePopup::Unlock);

        // another popup first: the prompt waits for it
        let mut app = App::new();
        app.active_popup = ActivePopup::ConfirmReset;
        handle_link_event(&mut app, locked_with_wait(0));
        assert_eq!(app.active_popup, ActivePopup::ConfirmReset);
        app.active_popup = ActivePopup::None;
        handle_link_event(&mut app, locked_with_wait(0));
        assert_eq!(app.active_popup, ActivePopup::Unlock);

        // unlocked by automatic login or another UI: closed, input wiped
        handle_unlock_input(&mut app, KeyCode::Char('p'));
        handle_link_event(&mut app, up_locked(false, true));
        assert_eq!(app.active_popup, ActivePopup::None);
        assert!(app.input_buf.is_empty());
        // Enter on an empty prompt sends nothing
        handle_link_event(&mut app, locked_with_wait(0));
        handle_unlock_input(&mut app, KeyCode::Enter);
        assert!(unlocks(&app).is_empty());
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

    fn type_address(app: &mut App, text: &str) {
        for c in text.chars() {
            handle_address_input(app, KeyCode::Char(c));
        }
    }

    fn member_running() -> LinkEvent {
        LinkEvent::Refreshed(Ok((
            Status {
                auth_key_set: true,
                data_key_set: true,
                saved: true,
                sync_enabled: true,
                network_running: true,
                ..Status::default()
            },
            Vec::new(),
            None,
        )))
    }

    /// Test that a on a member asks for an address, keeps the popup open
    /// with a red reason for anything that isn't a usable IP, and sends
    /// AddDeviceAt with the address once it is one
    #[test]
    fn test_add_device_at_address() {
        let mut app = App::new();
        handle_link_event(&mut app, member_running());
        app.outbox.clear();

        start_add_at(&mut app);
        assert_eq!(app.active_popup, ActivePopup::DeviceAddress);
        assert!(screen(&mut app).contains("Device on another network"));

        for bad in ["laptop.local", "127.0.0.1", "10.0.0.1:3232", "fd00::5"] {
            type_address(&mut app, bad);
            handle_address_input(&mut app, KeyCode::Enter);
            assert_eq!(app.active_popup, ActivePopup::DeviceAddress, "{bad}");
            assert!(app.address_invalid);
            assert!(screen(&mut app).contains("Not usable"));
            assert!(app.outbox.is_empty());
            // typing on clears the warning
            for _ in bad.chars() {
                handle_address_input(&mut app, KeyCode::Backspace);
            }
            assert!(!app.address_invalid);
        }

        type_address(&mut app, " 10.211.55.4 ");
        handle_address_input(&mut app, KeyCode::Enter);
        assert_eq!(app.active_popup, ActivePopup::None);
        assert!(app.input_buf.is_empty());
        let [Command::AddDeviceAt(at)] = app.outbox.as_slice() else {
            panic!("no AddDeviceAt sent");
        };
        assert_eq!(at.to_string(), "10.211.55.4");
    }

    /// Test that a on a fresh device asks for the address, then both
    /// passwords, and joins through that address; Esc forgets it, so a
    /// later n searches the LAN again
    #[test]
    fn test_join_at_address() {
        let mut app = App::new();
        handle_link_event(&mut app, fresh_status(false));
        app.outbox.clear();

        start_add_at(&mut app);
        type_address(&mut app, "172.17.243.179");
        handle_address_input(&mut app, KeyCode::Enter);
        assert_eq!(app.active_popup, ActivePopup::JoinGroup(JoinStep::Auth));
        assert!(screen(&mut app).contains("Through 172.17.243.179"));

        type_text(&mut app, "auth pw");
        press_in_join(&mut app, KeyCode::Enter);
        type_text(&mut app, "data pw");
        press_in_join(&mut app, KeyCode::Enter);
        assert_eq!(app.active_popup, ActivePopup::None);
        assert!(app.join_at.is_none());
        let [Command::JoinGroupAt(at, sent)] = app.outbox.as_slice() else {
            panic!("no JoinGroupAt sent");
        };
        assert_eq!(at.to_string(), "172.17.243.179");
        assert_eq!(sent.auth.password.as_slice(), b"auth pw");
        assert_eq!(sent.data.password.as_slice(), b"data pw");

        // an address, then Esc in the join: n afterwards is a plain join
        app.outbox.clear();
        start_add_at(&mut app);
        type_address(&mut app, "10.0.0.9");
        handle_address_input(&mut app, KeyCode::Enter);
        press_in_join(&mut app, KeyCode::Esc);
        assert!(app.join_at.is_none());
        start_add_device(&mut app);
        type_text(&mut app, "auth pw");
        press_in_join(&mut app, KeyCode::Enter);
        type_text(&mut app, "data pw");
        press_in_join(&mut app, KeyCode::Enter);
        assert!(matches!(app.outbox.as_slice(), [Command::JoinGroup(_)]));
    }

    /// Test that a does nothing but say so without networking on a member,
    /// and Esc in the address popup sends nothing
    #[test]
    fn test_add_at_needs_sync_and_esc_cancels() {
        let mut app = App::new();
        handle_link_event(&mut app, up(true, true));
        app.outbox.clear();
        start_add_at(&mut app);
        assert_eq!(app.active_popup, ActivePopup::None);
        assert!(app.logs.iter().any(|l| l.contains("Turn Sync on")));

        handle_link_event(&mut app, member_running());
        start_add_at(&mut app);
        type_address(&mut app, "10.0.0.9");
        handle_address_input(&mut app, KeyCode::Esc);
        assert_eq!(app.active_popup, ActivePopup::None);
        assert!(app.input_buf.is_empty());
        assert!(app.outbox.is_empty());
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
        for key in ["q:Quit", "n:Add/Join", "a:By IP", "x:Stop", "d:Forget"] {
            assert!(keys.contains(key), "{key} missing in: {keys}");
        }
    }

    /// Test that the Details keys are never cut off (the one-line help was
    /// cut after "d: for"): whole on one line from 80 columns, wrapped but
    /// complete when narrower
    #[test]
    fn test_details_keys_not_cut() {
        use ratatui::{Terminal, backend::TestBackend};

        for width in [60, 80, 120] {
            let mut app = App::new();
            handle_link_event(&mut app, up_network(true, None));
            let mut terminal = Terminal::new(TestBackend::new(width, 24)).unwrap();
            terminal.draw(|frame| ui(frame, &mut app)).unwrap();

            // only the Details panel: from its left border to the screen edge
            let buffer = terminal.backend().buffer();
            let cells = |y: u16| (0..buffer.area.width).map(move |x| buffer[(x, y)].symbol());
            let title_row = (0..buffer.area.height)
                .find(|&y| cells(y).collect::<String>().contains("Details"))
                .unwrap();
            let left = (0..buffer.area.width)
                .rfind(|&x| buffer[(x, title_row)].symbol() == "╭")
                .unwrap();
            let rows: Vec<String> = (0..buffer.area.height)
                .map(|y| {
                    (left.saturating_add(1)..buffer.area.width.saturating_sub(1))
                        .map(|x| buffer[(x, y)].symbol())
                        .collect()
                })
                .collect();
            let words: Vec<&str> = rows.iter().flat_map(|row| row.split_whitespace()).collect();
            for key in [
                "n: add device / join",
                "a: by IP (VPN)",
                "x: stop / cancel",
                "d: forget",
            ] {
                if width >= 80 {
                    assert!(
                        rows.iter().any(|row| row.contains(key)),
                        "{key} not whole at width {width}"
                    );
                } else {
                    let needed: Vec<&str> = key.split_whitespace().collect();
                    assert!(
                        words.windows(needed.len()).any(|w| w == needed.as_slice()),
                        "{key} cut at width {width}"
                    );
                }
            }
        }
    }

    /// Test that wrapping keeps every character, fits the width, breaks at
    /// spaces when it can, and always ends (zero width, wide chars)
    #[test]
    fn test_wrap_to_width() {
        use unicode_width::UnicodeWidthStr;

        assert_eq!(render::wrap_to_width("", 10), vec![""]);
        assert_eq!(render::wrap_to_width("short", 10), vec!["short"]);
        assert_eq!(
            render::wrap_to_width("peer locked out after five", 12),
            vec!["peer locked ", "out after ", "five"]
        );
        assert_eq!(
            render::wrap_to_width("abcdefgh", 3),
            vec!["abc", "def", "gh"]
        );
        assert_eq!(render::wrap_to_width("ab", 0), vec!["a", "b"]);
        // a char wider than the width still moves on
        assert_eq!(render::wrap_to_width("日本", 1), vec!["日", "本"]);

        for (text, width) in [
            (
                "ERROR cesa_conn_networker: guess limiter full, refusing a new source peer_addr=10.0.0.7:5122",
                17,
            ),
            ("x  y   z", 2),
            ("日本語のテキスト mixed", 5),
        ] {
            let pieces = render::wrap_to_width(text, width);
            assert_eq!(pieces.concat(), text);
            for piece in &pieces {
                assert!(
                    piece.width() <= width.max(2),
                    "{piece:?} wider than {width}"
                );
            }
        }
    }

    /// Test that long log lines wrap instead of being cut, and following
    /// still shows the newest line on a small terminal
    #[test]
    fn test_logs_wrap_and_follow() {
        use ratatui::{Terminal, backend::TestBackend};

        let mut app = App::new();
        app.active_tab = Tab::Logs;
        app.push_log("WARN first: a long line that is much wider than the window END-OF-FIRST");
        for i in 0..30 {
            app.push_log(format!("INFO line {i} with some more words to wrap here"));
        }
        app.push_log("INFO the newest line, long enough to wrap too NEWEST-TAIL");

        let mut terminal = Terminal::new(TestBackend::new(40, 16)).unwrap();
        terminal.draw(|frame| ui(frame, &mut app)).unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(text.contains("NEWEST-TAIL"), "newest line not followed");

        // scrolled to the top, the first line is complete
        app.log_follow = false;
        app.log_scroll = 0;
        terminal.draw(|frame| ui(frame, &mut app)).unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(text.contains("END-OF-FIRST"), "first line cut");
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
                    state: PeerState::Unknown,
                })
                .collect(),
            None,
        )))
    }

    /// Test that `d` asks before forgetting, sends the selected device's
    /// fingerprint only after y, and does nothing without a device
    #[test]
    fn test_forget_asks_first() {
        let mut app = App::new();
        ask_forget_selected(&mut app);
        assert_eq!(app.active_popup, ActivePopup::None);

        handle_link_event(
            &mut app,
            status_with(&["phone", "laptop"], Status::default()),
        );
        app.next_peer();
        ask_forget_selected(&mut app);
        let ActivePopup::ConfirmForget(peer) = app.active_popup.clone() else {
            panic!("no confirmation");
        };
        assert_eq!(peer.name, "laptop");
        assert!(screen(&mut app).contains("Forget laptop"));

        // other keys wait, n cancels
        handle_confirm_forget_input(&mut app, KeyCode::Char('x'), &peer);
        assert!(matches!(app.active_popup, ActivePopup::ConfirmForget(_)));
        handle_confirm_forget_input(&mut app, KeyCode::Char('n'), &peer);
        assert_eq!(app.active_popup, ActivePopup::None);
        assert!(
            app.outbox
                .iter()
                .all(|c| !matches!(c, Command::ForgetPeer(_)))
        );

        handle_confirm_forget_input(&mut app, KeyCode::Char('y'), &peer);
        assert!(matches!(
            app.outbox.last(),
            Some(Command::ForgetPeer([1, 1, 1, 1, 1, 1, 1, 1]))
        ));
        assert_eq!(app.active_popup, ActivePopup::None);
    }

    /// Test that a reset needs the exact word typed and Enter, and that Esc
    /// cancels and wipes what was typed
    #[test]
    fn test_reset_needs_the_word() {
        let mut app = App::new();
        app.settings_selected = app
            .settings
            .iter()
            .position(|s| s.label == RESET_LABEL)
            .unwrap();
        let resets = |app: &App| {
            app.outbox
                .iter()
                .filter(|c| matches!(c, Command::ResetDevice))
                .count()
        };

        handle_settings_enter(&mut app);
        assert_eq!(app.active_popup, ActivePopup::ConfirmReset);
        assert!(screen(&mut app).contains("Type RESET"));

        // Enter alone, a wrong word, lower case: nothing
        handle_confirm_reset_input(&mut app, KeyCode::Enter);
        for c in "reset".chars() {
            handle_confirm_reset_input(&mut app, KeyCode::Char(c));
        }
        handle_confirm_reset_input(&mut app, KeyCode::Enter);
        assert_eq!(resets(&app), 0);
        assert_eq!(app.active_popup, ActivePopup::ConfirmReset);

        // Esc: cancelled, typed text wiped
        handle_confirm_reset_input(&mut app, KeyCode::Esc);
        assert_eq!(app.active_popup, ActivePopup::None);
        assert!(app.input_buf.is_empty());

        handle_settings_enter(&mut app);
        for c in RESET_WORD.chars() {
            handle_confirm_reset_input(&mut app, KeyCode::Char(c));
        }
        handle_confirm_reset_input(&mut app, KeyCode::Enter);
        assert_eq!(resets(&app), 1);
        assert_eq!(app.active_popup, ActivePopup::None);
        assert!(app.input_buf.is_empty());
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

    /// Test that the clipboard switch follows the daemon, Enter asks the
    /// daemon to flip it, and a platform without a clipboard says so
    /// instead of offering a switch that does nothing
    #[test]
    fn test_clipboard_switch_goes_through_daemon() {
        let mut app = App::new();
        let status = Status {
            saved: true,
            clipboard_enabled: true,
            ..Status::default()
        };
        handle_link_event(&mut app, status_with(&[], status));
        assert_eq!(
            app.setting_mut(CLIPBOARD_LABEL).unwrap().kind,
            SettingKind::Bool(true)
        );

        app.outbox.clear();
        select(&mut app, CLIPBOARD_LABEL);
        handle_settings_enter(&mut app);
        assert!(matches!(
            app.outbox.as_slice(),
            [Command::SetClipboard(false)]
        ));
        // still on until the daemon says otherwise
        assert_eq!(
            app.setting_mut(CLIPBOARD_LABEL).unwrap().kind,
            SettingKind::Bool(true)
        );

        let unavailable = Status {
            clipboard_unavailable: true,
            ..Status::default()
        };
        handle_link_event(&mut app, status_with(&[], unavailable));
        assert_eq!(
            app.setting_mut(CLIPBOARD_LABEL).unwrap().kind,
            SettingKind::Unavailable
        );
        app.outbox.clear();
        handle_settings_enter(&mut app);
        assert!(app.outbox.is_empty());
        assert!(app.logs.last().unwrap().contains("isn't supported"));
    }

    fn peers_with(states: &[PeerState]) -> Vec<PeerInfo> {
        states
            .iter()
            .enumerate()
            .map(|(i, state)| PeerInfo {
                fingerprint: [u8::try_from(i).unwrap(); 8],
                name: format!("device {i}"),
                state: *state,
            })
            .collect()
    }

    fn refreshed(peers: Vec<PeerInfo>) -> LinkEvent {
        let status = Status {
            saved: true,
            network_running: true,
            sync_enabled: true,
            trusted_peers: u32::try_from(peers.len()).unwrap(),
            ..Status::default()
        };
        LinkEvent::Refreshed(Ok((status, peers, None)))
    }

    /// Test that a paired device with an incorrect password shows it on the
    /// Devices tab, and the log says it once (not every refresh)
    #[test]
    fn test_incorrect_password_shown_and_logged_once() {
        let mut app = App::new();
        handle_link_event(&mut app, refreshed(peers_with(&[PeerState::Ok])));
        assert!(screen(&mut app).contains("passwords match"));

        handle_link_event(
            &mut app,
            refreshed(peers_with(&[PeerState::AuthPasswordDiffers])),
        );
        assert!(screen(&mut app).contains("incorrect password (auth password differs)"));
        let warned = |app: &App| {
            app.logs
                .iter()
                .filter(|line| line.contains("device 0: incorrect password"))
                .count()
        };
        assert_eq!(warned(&app), 1);
        assert!(app.logs.last().unwrap().contains("auth password differs"));

        // the next refresh with the same state logs nothing new
        handle_link_event(
            &mut app,
            refreshed(peers_with(&[PeerState::AuthPasswordDiffers])),
        );
        assert_eq!(warned(&app), 1);

        handle_link_event(
            &mut app,
            refreshed(peers_with(&[PeerState::DataPasswordDiffers])),
        );
        assert!(screen(&mut app).contains("incorrect password (data password differs)"));
        assert_eq!(warned(&app), 2);
        assert!(app.logs.last().unwrap().contains("data password differs"));

        // fine or unreachable: shown, but no warning
        handle_link_event(&mut app, refreshed(peers_with(&[PeerState::Unreachable])));
        assert!(screen(&mut app).contains("not reachable"));
        handle_link_event(&mut app, refreshed(peers_with(&[PeerState::Unknown])));
        assert!(screen(&mut app).contains("not contacted yet"));
        assert_eq!(warned(&app), 2);
    }

    /// Test that changing a password while devices are paired says that
    /// they still have the old one (until it is changed there too)
    #[test]
    fn test_password_change_with_paired_devices_warns() {
        let mut app = App::new();
        handle_link_event(&mut app, refreshed(peers_with(&[PeerState::Ok])));
        handle_link_event(
            &mut app,
            LinkEvent::PasswordSet {
                kind: KeyKind::Auth,
                result: Ok(()),
            },
        );
        assert!(
            app.logs
                .last()
                .unwrap()
                .contains("still use the old auth password")
        );

        // no paired device: nothing to warn about
        let mut app = App::new();
        handle_link_event(&mut app, refreshed(Vec::new()));
        handle_link_event(
            &mut app,
            LinkEvent::PasswordSet {
                kind: KeyKind::Data,
                result: Ok(()),
            },
        );
        assert!(
            !app.logs
                .iter()
                .any(|line| line.contains("still use the old"))
        );
    }
}
