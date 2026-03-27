mod action;
mod app;
mod event;
mod ui;

use std::io;

use crossterm::{
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::Terminal;
use ratatui::prelude::CrosstermBackend;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> io::Result<()> {
    // Parse optional CLI args for server URLs
    let args: Vec<String> = std::env::args().collect();
    let identity_url =
        std::env::var("PULSE_IDENTITY_URL").unwrap_or_else(|_| "http://127.0.0.1:8001".to_string());
    let signal_url =
        std::env::var("PULSE_SIGNAL_URL").unwrap_or_else(|_| "http://127.0.0.1:8002".to_string());

    // Check for --help
    if args.iter().any(|a| a == "--help" || a == "-h") {
        eprintln!("pulse-tui: Interactive terminal client for Pulse anonymous polling");
        eprintln!();
        eprintln!("Usage: pulse-tui [OPTIONS]");
        eprintln!();
        eprintln!("Environment variables:");
        eprintln!("  PULSE_IDENTITY_URL  Identity zone URL (default: http://127.0.0.1:8001)");
        eprintln!("  PULSE_SIGNAL_URL    Signal zone URL (default: http://127.0.0.1:8002)");
        eprintln!();
        eprintln!("Run the dev server first: cargo run -p pulse-server");
        return Ok(());
    }

    // Set up terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Channels for async protocol results
    let (protocol_tx, protocol_rx) = mpsc::unbounded_channel();
    let (action_tx, mut action_rx) = mpsc::unbounded_channel();

    // Create app with configured URLs
    let mut app = app::App::new(protocol_tx);
    app.identity_url = identity_url;
    app.signal_url = signal_url;

    // Spawn event loop
    let event_action_tx = action_tx.clone();
    tokio::spawn(async move {
        event::event_loop(event_action_tx, protocol_rx).await;
    });

    // Main render + update loop
    loop {
        terminal.draw(|frame| ui::render(frame, &app))?;

        if let Some(action) = action_rx.recv().await {
            app.update(action);
        }

        if app.should_quit {
            break;
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
