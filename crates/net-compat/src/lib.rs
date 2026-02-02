pub mod destinations;
pub mod dns;
pub mod dns_parser;
pub mod telemetry;

use std::collections::HashMap;

pub use destinations::DestinationTracker;
pub use dns::DnsCapture;
pub use telemetry::NetworkTelemetry;

/// Network compatibility layer for WineWarden.
/// Provides DNS awareness, destination monitoring, and connection tracking.
#[derive(Debug, Default)]
pub struct NetCompat {
    /// Tracks DNS queries and their responses
    pub dns: DnsCapture,
    /// Tracks unique destination hosts/IPs
    pub destinations: DestinationTracker,
    /// Network telemetry data
    pub telemetry: NetworkTelemetry,
}

impl NetCompat {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a DNS observation from intercepted traffic
    pub fn record_dns_query(&mut self, query: &str) {
        self.dns.record_query(query);
    }

    /// Records a DNS response with resolved IPs
    pub fn record_dns_response(&mut self, query: &str, resolved: Vec<String>) {
        self.dns.record_response(query, resolved);
    }

    /// Records a connection to a destination
    pub fn record_destination(&mut self, host: String) {
        self.destinations.record(host);
    }

    /// Returns all observed DNS queries
    pub fn dns_queries(&self) -> &HashMap<String, dns::DnsObservation> {
        &self.dns.queries
    }

    /// Returns all tracked destinations
    pub fn destinations(&self) -> &std::collections::HashSet<String> {
        &self.destinations.hosts
    }
}
