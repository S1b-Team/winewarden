//! TUI Application State Management
//!
//! Manages the state for the real-time monitoring dashboard.

#![allow(dead_code)] // Many methods are for future integration

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use policy_engine::trust::scoring::TrustScore;
use winewarden_core::trust::TrustTier;
use winewarden_core::types::AccessAttempt;

/// Maximum number of events to keep in history
const MAX_EVENTS: usize = 1000;
/// Maximum number of trust scores to keep for graphing
const MAX_TRUST_HISTORY: usize = 60;

/// Current screen/tab in the TUI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Dashboard,
    Trust,
    Network,
    Processes,
    Events,
}

impl Screen {
    pub fn title(&self) -> &'static str {
        match self {
            Screen::Dashboard => "Dashboard",
            Screen::Trust => "Trust Score",
            Screen::Network => "Network",
            Screen::Processes => "Processes",
            Screen::Events => "Events",
        }
    }

    pub fn next(&self) -> Self {
        match self {
            Screen::Dashboard => Screen::Trust,
            Screen::Trust => Screen::Network,
            Screen::Network => Screen::Processes,
            Screen::Processes => Screen::Events,
            Screen::Events => Screen::Dashboard,
        }
    }

    pub fn prev(&self) -> Self {
        match self {
            Screen::Dashboard => Screen::Events,
            Screen::Trust => Screen::Dashboard,
            Screen::Network => Screen::Trust,
            Screen::Processes => Screen::Network,
            Screen::Events => Screen::Processes,
        }
    }
}

/// Process information for display
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub name: String,
    pub pid: u32,
    pub status: ProcessStatus,
    pub started_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessStatus {
    Running,
    Suspended,
    Terminated,
}

impl ProcessStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProcessStatus::Running => "●",
            ProcessStatus::Suspended => "⏸",
            ProcessStatus::Terminated => "✗",
        }
    }
}

/// Network connection info
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub first_seen: Instant,
    pub connection_count: u32,
}

/// DNS query info
#[derive(Debug, Clone)]
pub struct DnsInfo {
    pub domain: String,
    pub resolved_ips: Vec<String>,
    pub query_count: u32,
    pub last_query: Instant,
}

/// Main application state
#[derive(Debug)]
pub struct App {
    /// Current screen
    pub current_screen: Screen,
    /// Whether the TUI is running
    pub running: bool,
    /// Current trust tier
    pub trust_tier: TrustTier,
    /// Current trust score
    pub trust_score: Option<TrustScore>,
    /// Trust score history for graphing
    pub trust_history: VecDeque<(u64, u32)>, // (timestamp_secs, score)
    /// Event log
    pub events: VecDeque<AccessAttempt>,
    /// Active processes
    pub processes: Vec<ProcessInfo>,
    /// Active connections
    pub connections: Vec<ConnectionInfo>,
    /// DNS queries
    pub dns_queries: Vec<DnsInfo>,
    /// Session start time
    pub session_start: Instant,
    /// Total events processed
    pub total_events: u64,
    /// Denied events count
    pub denied_events: u64,
    /// Event filter string
    pub event_filter: String,
    /// Selected event index
    pub selected_event: usize,
    /// Auto-scroll events
    pub auto_scroll: bool,
    /// Last update time
    pub last_update: Instant,
    /// Update interval
    pub update_interval: Duration,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        Self {
            current_screen: Screen::Dashboard,
            running: true,
            trust_tier: TrustTier::Yellow,
            trust_score: None,
            trust_history: VecDeque::with_capacity(MAX_TRUST_HISTORY),
            events: VecDeque::with_capacity(MAX_EVENTS),
            processes: Vec::new(),
            connections: Vec::new(),
            dns_queries: Vec::new(),
            session_start: Instant::now(),
            total_events: 0,
            denied_events: 0,
            event_filter: String::new(),
            selected_event: 0,
            auto_scroll: true,
            last_update: Instant::now(),
            update_interval: Duration::from_millis(250),
        }
    }

    /// Returns session duration as string
    pub fn session_duration(&self) -> String {
        let duration = self.session_start.elapsed();
        let hours = duration.as_secs() / 3600;
        let minutes = (duration.as_secs() % 3600) / 60;
        let seconds = duration.as_secs() % 60;
        format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
    }

    /// Updates trust score and history
    pub fn update_trust_score(&mut self, score: TrustScore) {
        let now = Instant::now().elapsed().as_secs();
        self.trust_history.push_back((now, score.score));
        if self.trust_history.len() > MAX_TRUST_HISTORY {
            self.trust_history.pop_front();
        }
        self.trust_score = Some(score);
    }

    /// Adds an event to the log
    pub fn add_event(&mut self, event: AccessAttempt, denied: bool) {
        if self.events.len() >= MAX_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(event);
        self.total_events += 1;
        if denied {
            self.denied_events += 1;
        }

        if self.auto_scroll {
            self.selected_event = self.events.len().saturating_sub(1);
        }
    }

    /// Returns filtered events
    pub fn filtered_events(&self) -> Vec<&AccessAttempt> {
        if self.event_filter.is_empty() {
            return self.events.iter().collect();
        }

        let filter_lower = self.event_filter.to_lowercase();
        self.events
            .iter()
            .filter(|e| {
                let note = e.note.as_deref().unwrap_or("").to_lowercase();
                let target = format!("{:?}", e.target).to_lowercase();
                note.contains(&filter_lower) || target.contains(&filter_lower)
            })
            .collect()
    }

    /// Adds or updates a connection
    pub fn add_connection(&mut self, host: String, port: u16, protocol: String) {
        if let Some(conn) = self
            .connections
            .iter_mut()
            .find(|c| c.host == host && c.port == port && c.protocol == protocol)
        {
            conn.connection_count += 1;
        } else {
            self.connections.push(ConnectionInfo {
                host,
                port,
                protocol,
                first_seen: Instant::now(),
                connection_count: 1,
            });
        }
    }

    /// Adds or updates a DNS query
    pub fn add_dns_query(&mut self, domain: String, resolved: Vec<String>) {
        if let Some(query) = self.dns_queries.iter_mut().find(|q| q.domain == domain) {
            query.query_count += 1;
            query.last_query = Instant::now();
            for ip in resolved {
                if !query.resolved_ips.contains(&ip) {
                    query.resolved_ips.push(ip);
                }
            }
        } else {
            self.dns_queries.push(DnsInfo {
                domain,
                resolved_ips: resolved,
                query_count: 1,
                last_query: Instant::now(),
            });
        }
    }

    /// Adds a process
    pub fn add_process(&mut self, name: String, pid: u32) {
        self.processes.push(ProcessInfo {
            name,
            pid,
            status: ProcessStatus::Running,
            started_at: Instant::now(),
        });
    }

    /// Updates process status
    pub fn update_process_status(&mut self, pid: u32, status: ProcessStatus) {
        if let Some(proc) = self.processes.iter_mut().find(|p| p.pid == pid) {
            proc.status = status;
        }
    }

    /// Returns events per second
    pub fn events_per_second(&self) -> f64 {
        let duration_secs = self.session_start.elapsed().as_secs_f64();
        if duration_secs > 0.0 {
            self.total_events as f64 / duration_secs
        } else {
            0.0
        }
    }

    /// Returns denial rate (0.0 - 1.0)
    pub fn denial_rate(&self) -> f64 {
        if self.total_events > 0 {
            self.denied_events as f64 / self.total_events as f64
        } else {
            0.0
        }
    }

    /// Moves to next screen
    pub fn next_screen(&mut self) {
        self.current_screen = self.current_screen.next();
    }

    /// Moves to previous screen
    pub fn prev_screen(&mut self) {
        self.current_screen = self.current_screen.prev();
    }

    /// Toggles pause
    pub fn toggle_pause(&mut self) {
        // In a real implementation, this would pause/resume monitoring
    }

    /// Clears event filter
    pub fn clear_filter(&mut self) {
        self.event_filter.clear();
    }

    /// Quits the application
    pub fn quit(&mut self) {
        self.running = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_new() {
        let app = App::new();
        assert!(app.running);
        assert_eq!(app.current_screen, Screen::Dashboard);
        assert!(app.events.is_empty());
    }

    #[test]
    fn test_screen_navigation() {
        let mut app = App::new();
        assert_eq!(app.current_screen, Screen::Dashboard);

        app.next_screen();
        assert_eq!(app.current_screen, Screen::Trust);

        app.prev_screen();
        assert_eq!(app.current_screen, Screen::Dashboard);
    }

    #[test]
    fn test_trust_history() {
        let mut app = App::new();
        let score = TrustScore::new(75, vec![]);
        app.update_trust_score(score);

        assert!(app.trust_score.is_some());
        assert_eq!(app.trust_score.unwrap().score, 75);
        assert_eq!(app.trust_history.len(), 1);
    }

    #[test]
    fn test_session_duration() {
        let app = App::new();
        let duration = app.session_duration();
        assert!(duration.contains(':'));
    }
}
