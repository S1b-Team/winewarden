//! TUI (Terminal User Interface) for WineWarden
//!
//! Provides a real-time monitoring dashboard with:
//! - Live session statistics
//! - Trust score visualization
//! - Network monitoring
//! - Process tracking
//! - Event log with filtering

#![allow(dead_code)] // API methods for future integration

use std::io;
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    Terminal,
};

mod app;
mod events;
mod ui;

pub use app::App;
pub use events::EventHandler;

/// Runs the TUI application
pub fn run_tui() -> Result<()> {
    // Setup terminal
    terminal::enable_raw_mode().context("enable raw mode")?;
    let mut stdout = io::stdout();
    crossterm::execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
        .context("enter alternate screen")?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("create terminal")?;

    // Create app state
    let mut app = App::new();

    // Create event handler with 250ms tick rate
    let mut event_handler = EventHandler::new(Duration::from_millis(250));

    // Main event loop
    let result = run_event_loop(&mut terminal, &mut app, &mut event_handler);

    // Restore terminal
    terminal::disable_raw_mode().context("disable raw mode")?;
    crossterm::execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )
    .context("leave alternate screen")?;
    terminal.show_cursor().context("show cursor")?;

    result
}

/// Main event loop
fn run_event_loop<B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    event_handler: &mut EventHandler,
) -> Result<()> {
    let mut last_draw = std::time::Instant::now();
    let draw_interval = Duration::from_millis(50); // 20 FPS max

    while app.running {
        // Handle events
        if let Some(event) = event_handler.next_event()? {
            events::handle_event(app, event)?;
        }

        // Draw UI (throttled to ~20 FPS)
        if last_draw.elapsed() >= draw_interval {
            terminal.draw(|f| ui::render(f, app))?;
            last_draw = std::time::Instant::now();
        }
    }

    Ok(())
}

/// Checks if the TUI is available (terminal supports it)
pub fn available() -> bool {
    // Check if we're in a terminal
    terminal::is_raw_mode_enabled().ok().is_some() || atty::is(atty::Stream::Stdout)
}

/// Initializes the TUI and returns the terminal instance
pub fn init_tui() -> Result<Terminal<impl Backend>> {
    terminal::enable_raw_mode().context("enable raw mode")?;
    let stdout = io::stdout();
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend).context("create terminal")?;
    Ok(terminal)
}

/// Restores the terminal to normal state
pub fn restore_tui() -> Result<()> {
    terminal::disable_raw_mode().context("disable raw mode")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_creation() {
        let app = App::new();
        assert!(app.running);
    }

    #[test]
    fn test_available() {
        // This will vary depending on test environment
        // Just verify it doesn't panic
        let _ = available();
    }
}
