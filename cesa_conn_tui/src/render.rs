//! Drawing: the tabs, the status bar and every popup.

use super::*;

// ── Rendering ─────────────────────────────────────────────────────────────────

pub(super) fn ui(frame: &mut Frame, app: &mut App) {
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
        ActivePopup::ConfirmForget(peer) => render_confirm_forget_popup(frame, area, &peer),
        ActivePopup::ConfirmReset => render_confirm_reset_popup(frame, area, app),
        ActivePopup::Unlock => render_unlock_popup(frame, area, app),
        ActivePopup::DeviceAddress => render_address_popup(frame, area, app),
        ActivePopup::None => {}
    }
}

pub(super) fn render_header(frame: &mut Frame, area: Rect, app: &App) {
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

pub(super) fn render_content(frame: &mut Frame, area: Rect, app: &mut App) {
    match app.active_tab {
        Tab::Devices => render_devices(frame, area, app),
        Tab::Settings => render_settings(frame, area, app),
        Tab::Logs => render_logs(frame, area, app),
    }
}

pub(super) fn render_devices(frame: &mut Frame, area: Rect, app: &mut App) {
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
                // the marker's colour is the connection state
                let (_, color) = peer_state_text(p.state);
                ListItem::new(Line::from(vec![
                    Span::styled("◆ ", Style::default().fg(color)),
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
            let (state, color) = peer_state_text(peer.state);
            lines.push(Line::from(vec![
                Span::styled("  Connection  : ", Style::default().fg(Color::DarkGray)),
                Span::styled(state, Style::default().fg(color)),
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
        "  n: add device / join    a: by IP (VPN)    x: stop / cancel    d: forget",
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

pub(super) fn render_settings(frame: &mut Frame, area: Rect, app: &App) {
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

pub(super) fn render_logs(frame: &mut Frame, area: Rect, app: &mut App) {
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

pub(super) fn render_statusbar(frame: &mut Frame, area: Rect, app: &App) {
    let help = match app.active_tab {
        Tab::Devices => " q:Quit  Tab:Switch  ↑↓:Select  n:Add/Join  x:Stop  d:Forget ",
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

pub(super) fn render_pairing_popup(frame: &mut Frame, area: Rect, prompt: &PairingPrompt) {
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

/// The password popup: one star per typed character and, for a new
/// password, a line counting characters against the minimum (yellow while
/// short, green when long enough, red after Enter on a short one).
pub(super) fn render_edit_setting_popup(frame: &mut Frame, area: Rect, app: &App) {
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

    // a new password: how many characters so far against the minimum (an
    // unlock takes the existing password, any length)
    let typed = app.input_buf.chars().count();
    let hint = match setting.kind {
        SettingKind::Secret { .. } if app.password_too_short && typed < MIN_NEW_PASSWORD_LEN => {
            Some(Line::from(Span::styled(
                format!(
                    " Too short ({typed}/{MIN_NEW_PASSWORD_LEN}): at least {MIN_NEW_PASSWORD_LEN} characters"
                ),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )))
        }
        SettingKind::Secret { .. } if typed < MIN_NEW_PASSWORD_LEN => {
            Some(Line::from(Span::styled(
                format!(
                    " {typed}/{MIN_NEW_PASSWORD_LEN} characters (at least {MIN_NEW_PASSWORD_LEN})"
                ),
                Style::default().fg(Color::Yellow),
            )))
        }
        SettingKind::Secret { .. } => Some(Line::from(Span::styled(
            format!(" {typed} characters: long enough"),
            Style::default().fg(Color::Green),
        ))),
        _ => None,
    };

    let title = format!(" Edit: {} ", setting.label);
    let w = to_u16(title.len())
        .saturating_add(10)
        .max(60)
        .min(area.width);
    let h = if hint.is_some() { 6u16 } else { 5u16 }.min(area.height);
    let popup = centered_rect(area, w, h);

    let mut lines = vec![Line::from(format!(" {display_input}"))];
    lines.extend(hint);

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
            .saturating_add(2)
            .saturating_add(to_u16(display_input.len())),
        popup.y.saturating_add(1),
    ));
}

/// The address popup: what was typed, in red why it can't be used after
/// Enter, and what the other device must do.
pub(super) fn render_address_popup(frame: &mut Frame, area: Rect, app: &App) {
    let typed = app.input_buf.to_string();

    let w = 66u16.min(area.width);
    let h = 8u16.min(area.height);
    let popup = centered_rect(area, w, h);

    let status = if app.address_invalid {
        Line::from(Span::styled(
            "  Not usable: an IPv4 address like 10.0.0.5, no name, no port",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ))
    } else {
        Line::from(Span::styled(
            "  On that device: Devices > n (Add device) too.",
            Style::default().fg(Color::DarkGray),
        ))
    };

    let lines = vec![
        Line::from(Span::styled(
            "  The other device's IPv4 address (e.g. its VPN address):",
            Style::default().fg(Color::Cyan),
        )),
        Line::from(format!("  {typed}")),
        Line::from(""),
        status,
        Line::from(Span::styled(
            "  Enter: connect   Esc: cancel",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::bordered()
                .title(" Device on another network ")
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
            .saturating_add(to_u16(typed.chars().count())),
        popup.y.saturating_add(2),
    ));
}

pub(super) fn render_join_popup(frame: &mut Frame, area: Rect, step: JoinStep, app: &App) {
    let (title, which) = match step {
        JoinStep::Auth => (" Join a group (1/2) ", "auth"),
        JoinStep::Data => (" Join a group (2/2) ", "data"),
    };
    // one star per character, the byte length would leak more than the length
    let stars = "*".repeat(app.input_buf.chars().count());

    let w = 64u16.min(area.width);
    let h = 8u16.min(area.height);
    let popup = centered_rect(area, w, h);

    let first = match app.join_at {
        Some(at) => format!("  Through {at}: Devices > n (Add device) there."),
        None => "  On a device of the group: Devices > n (Add device) first.".to_owned(),
    };
    let lines = vec![
        Line::from(Span::styled(first, Style::default().fg(Color::DarkGray))),
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

pub(super) fn render_confirm_change_popup(frame: &mut Frame, area: Rect, kind: KeyKind) {
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

pub(super) fn render_unlock_popup(frame: &mut Frame, area: Rect, app: &App) {
    // one star per character, the byte length would leak more than the length
    let stars = "*".repeat(app.input_buf.chars().count());

    let w = 60u16.min(area.width);
    let h = 8u16.min(area.height);
    let popup = centered_rect(area, w, h);

    let lines = vec![
        Line::from(Span::styled(
            "  The saved keys are locked (the daemon restarted).",
            Style::default().fg(Color::Yellow),
        )),
        Line::from(Span::styled(
            "  Data password:",
            Style::default().fg(Color::Reset),
        )),
        Line::from(""),
        Line::from(format!("  {stars}")),
        Line::from(""),
        Line::from(Span::styled(
            "  Enter: unlock    Esc: later (Settings > Data key)",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::bordered()
                .title(" Unlock ")
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
        popup.y.saturating_add(4),
    ));
}

pub(super) fn render_confirm_forget_popup(frame: &mut Frame, area: Rect, peer: &PeerInfo) {
    let w = 64u16.min(area.width);
    let h = 10u16.min(area.height);
    let popup = centered_rect(area, w, h);

    let yellow = Style::default().fg(Color::Yellow);
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            format!(
                "  Forget {} ({})?",
                peer.name,
                fingerprint_hex(&peer.fingerprint)
            ),
            yellow,
        )),
        Line::from(Span::styled(
            "  It can't connect to this device any more.",
            yellow,
        )),
        Line::from(Span::styled(
            "  It still knows the group passwords: it can pair again",
            yellow,
        )),
        Line::from(Span::styled("  if you accept it in Add device.", yellow)),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "  y",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::styled(": forget   ", Style::default().fg(Color::DarkGray)),
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
                .title(" Forget device ")
                .title_alignment(Alignment::Center)
                .border_type(BorderType::Double)
                .style(yellow),
        ),
        popup,
    );
}

pub(super) fn render_confirm_reset_popup(frame: &mut Frame, area: Rect, app: &App) {
    let w = 66u16.min(area.width);
    let h = 13u16.min(area.height);
    let popup = centered_rect(area, w, h);

    let red = Style::default().fg(Color::Red);
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Reset this device? It leaves its group.",
            red,
        )),
        Line::from(Span::styled(
            "  Deleted: both keys, the encrypted vault, the keychain",
            red,
        )),
        Line::from(Span::styled(
            "  items and every paired device. Other devices keep theirs.",
            red,
        )),
        Line::from(Span::styled(
            "  Afterwards: n on Devices joins a group again.",
            Style::default().fg(Color::Reset),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!("  Type {RESET_WORD} and press Enter:"),
            Style::default().fg(Color::Reset),
        )),
        Line::from(Span::styled(
            format!("  > {}", app.input_buf.as_str()),
            Style::default().fg(Color::Cyan),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  Esc: cancel",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::bordered()
                .title(" Reset device ")
                .title_alignment(Alignment::Center)
                .border_type(BorderType::Double)
                .style(red),
        ),
        popup,
    );
}

pub(super) fn render_security_warning_popup(frame: &mut Frame, area: Rect, idx: usize, app: &App) {
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
