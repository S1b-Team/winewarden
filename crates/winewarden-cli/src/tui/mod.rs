//! TUI (Terminal User Interface) for WineWarden
//!
//! Provides a real-time monitoring dashboard with:
//! - Live session statistics
//! - Trust score visualization
//! - Network monitoring
//! - Process tracking
//! - Event log with filtering

use std::io;
use std::path::Path;
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
mod feed;
mod tail;
mod ui;

pub use app::App;
pub use events::EventHandler;
use events::TuiEvent;
use winewarden_core::config::ConfigPaths;

/// Runs the TUI on a finished session report, or follows a live session log
/// (the newest one when `session` is not given).
pub fn run_tui(report: Option<&Path>, session: Option<&str>) -> Result<()> {
    let mut app = App::new();
    let mut live = None;
    if let Some(path) = report {
        feed::load_report(&mut app, feed::read_report(path)?);
    } else {
        let dir = reporting::live::default_live_dir(&ConfigPaths::resolve()?);
        let mut tail = tail::LiveTail::open(&tail::session_log(&dir, session)?)?;
        tail.poll(&mut app)?;
        live = Some(tail);
    }

    // Setup terminal
    terminal::enable_raw_mode().context("enable raw mode")?;
    let mut stdout = io::stdout();
    crossterm::execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
        .context("enter alternate screen")?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("create terminal")?;

    // Create event handler with 250ms tick rate
    let mut event_handler = EventHandler::new(Duration::from_millis(250));

    // Main event loop
    let result = run_event_loop(&mut terminal, &mut app, &mut event_handler, live);

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
    mut live: Option<tail::LiveTail>,
) -> Result<()> {
    let mut last_draw = std::time::Instant::now();
    let draw_interval = Duration::from_millis(50); // 20 FPS max

    while app.running {
        // Handle events
        match event_handler.next_event()? {
            Some(TuiEvent::Tick) => {
                if let Some(tail) = live.as_mut().filter(|_| !app.paused) {
                    tail.poll(app)?;
                }
            }
            Some(TuiEvent::Key(key)) => events::handle_key_event(app, key)?,
            None => {}
        }

        // Draw UI (throttled to ~20 FPS)
        if last_draw.elapsed() >= draw_interval {
            terminal.draw(|f| ui::render(f, app))?;
            last_draw = std::time::Instant::now();
        }
    }

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
}
