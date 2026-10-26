#![forbid(unsafe_code)]

fn main() -> std::io::Result<()> {
    let mut terminal = ratatui::init();
    let mut app = cesa_conn_tui::App::new();
    let result = cesa_conn_tui::run(&mut terminal, &mut app);
    ratatui::restore();
    result
}
