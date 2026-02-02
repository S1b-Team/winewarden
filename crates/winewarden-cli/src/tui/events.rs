//! TUI Event Handling
//!
//! Handles keyboard input and other events for the TUI.

#![allow(dead_code)] // API for future integration

use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};

use crate::tui::app::{App, Screen};

/// TUI event types
#[derive(Debug, Clone)]
pub enum TuiEvent {
    /// Terminal tick (for updates)
    Tick,
    /// Keyboard input
    Key(KeyEvent),
    /// Window resize
    Resize(u16, u16),
}

/// Event handler for the TUI
pub struct EventHandler {
    /// Tick rate for updates
    tick_rate: Duration,
    /// Last tick time
    last_tick: Instant,
}

impl EventHandler {
    pub fn new(tick_rate: Duration) -> Self {
        Self {
            tick_rate,
            last_tick: Instant::now(),
        }
    }

    /// Polls for the next event
    pub fn next_event(&mut self) -> anyhow::Result<Option<TuiEvent>> {
        let timeout = self.tick_rate.saturating_sub(self.last_tick.elapsed());

        if event::poll(timeout)? {
            match event::read()? {
                Event::Key(key) => Ok(Some(TuiEvent::Key(key))),
                Event::Resize(w, h) => Ok(Some(TuiEvent::Resize(w, h))),
                _ => Ok(None),
            }
        } else {
            self.last_tick = Instant::now();
            Ok(Some(TuiEvent::Tick))
        }
    }
}

/// Handles a TUI event and updates the app state
pub fn handle_event(app: &mut App, event: TuiEvent) -> anyhow::Result<()> {
    match event {
        TuiEvent::Tick => {
            // Update logic for tick events
            // In a real implementation, this would poll for new data
        }
        TuiEvent::Key(key) => handle_key_event(app, key)?,
        TuiEvent::Resize(_, _) => {
            // Terminal will automatically handle resize
        }
    }
    Ok(())
}

/// Handles keyboard input
fn handle_key_event(app: &mut App, key: KeyEvent) -> anyhow::Result<()> {
    match app.current_screen {
        Screen::Events => handle_events_screen_keys(app, key),
        _ => handle_normal_keys(app, key),
    }
}

/// Handles keys for the events screen (with filter input)
fn handle_events_screen_keys(app: &mut App, key: KeyEvent) -> anyhow::Result<()> {
    match key.code {
        KeyCode::Esc => {
            // Clear filter and exit filter mode
            app.clear_filter();
        }
        KeyCode::Backspace => {
            // Remove last character from filter
            app.event_filter.pop();
        }
        KeyCode::Char(c) => {
            // Add character to filter
            app.event_filter.push(c);
        }
        _ => {
            // Pass to normal key handling
            handle_normal_keys(app, key)?;
        }
    }
    Ok(())
}

/// Handles normal keys (non-filtering mode)
fn handle_normal_keys(app: &mut App, key: KeyEvent) -> anyhow::Result<()> {
    match key.code {
        // Navigation
        KeyCode::Tab | KeyCode::Right => {
            if key.modifiers.contains(KeyModifiers::SHIFT) {
                app.prev_screen();
            } else {
                app.next_screen();
            }
        }
        KeyCode::BackTab | KeyCode::Left => {
            app.prev_screen();
        }

        // Quit
        KeyCode::Char('q') | KeyCode::Char('Q') => {
            app.quit();
        }

        // Pause/Resume
        KeyCode::Char('p') | KeyCode::Char('P') => {
            app.toggle_pause();
        }

        // Screen-specific keys
        KeyCode::Char('/') => {
            // Switch to events screen for filtering
            app.current_screen = Screen::Events;
        }

        // Scrolling (for events screen)
        KeyCode::Up => {
            if app.current_screen == Screen::Events {
                app.auto_scroll = false;
                app.selected_event = app.selected_event.saturating_sub(1);
            }
        }
        KeyCode::Down => {
            if app.current_screen == Screen::Events {
                let max = app.filtered_events().len().saturating_sub(1);
                app.selected_event = (app.selected_event + 1).min(max);
                if app.selected_event == max {
                    app.auto_scroll = true;
                }
            }
        }
        KeyCode::Home => {
            if app.current_screen == Screen::Events {
                app.auto_scroll = false;
                app.selected_event = 0;
            }
        }
        KeyCode::End => {
            if app.current_screen == Screen::Events {
                app.selected_event = app.filtered_events().len().saturating_sub(1);
                app.auto_scroll = true;
            }
        }

        // Number keys for direct screen navigation
        KeyCode::Char('1') => app.current_screen = Screen::Dashboard,
        KeyCode::Char('2') => app.current_screen = Screen::Trust,
        KeyCode::Char('3') => app.current_screen = Screen::Network,
        KeyCode::Char('4') => app.current_screen = Screen::Processes,
        KeyCode::Char('5') => app.current_screen = Screen::Events,

        _ => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_quit() {
        let mut app = App::new();
        assert!(app.running);

        handle_key_event(&mut app, KeyEvent::from(KeyCode::Char('q'))).unwrap();

        assert!(!app.running);
    }

    #[test]
    fn test_handle_screen_navigation() {
        let mut app = App::new();
        assert_eq!(app.current_screen, Screen::Dashboard);

        handle_key_event(&mut app, KeyEvent::from(KeyCode::Tab)).unwrap();
        assert_eq!(app.current_screen, Screen::Trust);

        handle_key_event(&mut app, KeyEvent::from(KeyCode::Left)).unwrap();
        assert_eq!(app.current_screen, Screen::Dashboard);
    }

    #[test]
    fn test_handle_number_keys() {
        let mut app = App::new();

        handle_key_event(&mut app, KeyEvent::from(KeyCode::Char('3'))).unwrap();
        assert_eq!(app.current_screen, Screen::Network);

        handle_key_event(&mut app, KeyEvent::from(KeyCode::Char('5'))).unwrap();
        assert_eq!(app.current_screen, Screen::Events);
    }
}
