//! Network telemetry for monitoring connection patterns.
//!
//! Provides aggregate statistics and timing information about network activity.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Network telemetry data collected during a session
#[derive(Debug, Clone)]
pub struct NetworkTelemetry {
    /// When telemetry collection started
    pub started_at: Instant,
    /// Total bytes sent (if tracked)
    pub bytes_sent: u64,
    /// Total bytes received (if tracked)
    pub bytes_received: u64,
    /// Total connections made
    pub total_connections: u32,
    /// Failed connection attempts
    pub failed_connections: u32,
    /// Protocol usage counts
    pub protocol_counts: HashMap<String, u32>,
    /// Port usage counts
    pub port_counts: HashMap<u16, u32>,
    /// Connection durations (if tracked)
    pub connection_durations: Vec<Duration>,
}

impl Default for NetworkTelemetry {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkTelemetry {
    /// Creates new telemetry tracking
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            total_connections: 0,
            failed_connections: 0,
            protocol_counts: HashMap::new(),
            port_counts: HashMap::new(),
            connection_durations: Vec::new(),
        }
    }

    /// Records a successful connection
    pub fn record_connection(&mut self, protocol: &str, port: u16) {
        self.total_connections += 1;
        *self
            .protocol_counts
            .entry(protocol.to_string())
            .or_insert(0) += 1;
        *self.port_counts.entry(port).or_insert(0) += 1;
    }

    /// Records a failed connection attempt
    pub fn record_failed_connection(&mut self, _protocol: &str, _port: u16) {
        self.failed_connections += 1;
    }

    /// Records data transfer
    pub fn record_transfer(&mut self, sent: u64, received: u64) {
        self.bytes_sent += sent;
        self.bytes_received += received;
    }

    /// Records connection duration
    pub fn record_duration(&mut self, duration: Duration) {
        self.connection_durations.push(duration);
    }

    /// Returns the total duration of telemetry collection
    pub fn duration(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// Returns the average connection duration
    pub fn avg_connection_duration(&self) -> Option<Duration> {
        if self.connection_durations.is_empty() {
            return None;
        }

        let total: Duration = self.connection_durations.iter().sum();
        Some(total / self.connection_durations.len() as u32)
    }

    /// Returns the most used protocol
    pub fn top_protocol(&self) -> Option<(&str, u32)> {
        self.protocol_counts
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(proto, count)| (proto.as_str(), *count))
    }

    /// Returns the most used port
    pub fn top_port(&self) -> Option<(u16, u32)> {
        self.port_counts
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(port, count)| (*port, *count))
    }

    /// Returns connection success rate (0.0 - 1.0)
    pub fn success_rate(&self) -> f64 {
        let total = self.total_connections + self.failed_connections;
        if total == 0 {
            return 0.0;
        }
        self.total_connections as f64 / total as f64
    }

    /// Returns a summary of telemetry
    pub fn summary(&self) -> String {
        let duration = self.duration();
        let mins = duration.as_secs() / 60;
        let secs = duration.as_secs() % 60;

        format!(
            "Network Telemetry: {} connections over {}m {}s, {:.1}% success rate",
            self.total_connections,
            mins,
            secs,
            self.success_rate() * 100.0
        )
    }

    /// Resets all telemetry data
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry() {
        let mut telemetry = NetworkTelemetry::new();

        telemetry.record_connection("tcp", 443);
        telemetry.record_connection("tcp", 443);
        telemetry.record_connection("udp", 53);
        telemetry.record_failed_connection("tcp", 443);

        assert_eq!(telemetry.total_connections, 3);
        assert_eq!(telemetry.failed_connections, 1);
        assert_eq!(telemetry.top_protocol(), Some(("tcp", 2)));
        assert_eq!(telemetry.top_port(), Some((443, 2))); // Failed connections don't count toward port usage
    }

    #[test]
    fn test_success_rate() {
        let mut telemetry = NetworkTelemetry::new();

        assert_eq!(telemetry.success_rate(), 0.0);

        telemetry.record_connection("tcp", 80);
        telemetry.record_connection("tcp", 80);
        telemetry.record_failed_connection("tcp", 443);

        assert!((telemetry.success_rate() - 0.666).abs() < 0.001);
    }
}
