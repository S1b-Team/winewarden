//! Destination tracking for network connections.
//!
//! Tracks unique destination hosts and IPs for analysis and policy decisions.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Tracks network destinations observed during a session
#[derive(Debug, Clone)]
pub struct DestinationTracker {
    /// Set of unique destination hosts (domains or IPs as strings)
    pub hosts: HashSet<String>,
    /// Set of unique destination IPs
    pub ips: HashSet<IpAddr>,
    /// When each destination was first seen
    pub first_seen: HashMap<String, Instant>,
    /// Connection counts per destination
    pub connection_counts: HashMap<String, u32>,
    /// First observation time
    pub started_at: Instant,
}

impl Default for DestinationTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl DestinationTracker {
    /// Creates a new destination tracker
    pub fn new() -> Self {
        Self {
            hosts: HashSet::new(),
            ips: HashSet::new(),
            first_seen: HashMap::new(),
            connection_counts: HashMap::new(),
            started_at: Instant::now(),
        }
    }

    /// Records a connection to a host (domain name or IP string)
    pub fn record(&mut self, host: String) {
        if self.hosts.insert(host.clone()) {
            self.first_seen.insert(host.clone(), Instant::now());
            self.connection_counts.insert(host.clone(), 1);
        } else {
            *self.connection_counts.entry(host).or_insert(0) += 1;
        }
    }

    /// Records a connection to an IP address
    pub fn record_ip(&mut self, ip: IpAddr) {
        self.ips.insert(ip);
        self.record(ip.to_string());
    }

    /// Records a destination with metadata
    pub fn record_with_metadata(&mut self, host: String, port: u16, protocol: &str) {
        let key = format!("{}:{} ({})", host, port, protocol);
        self.record(key);
        self.record(host);
    }

    /// Returns true if the given host has been observed
    pub fn contains(&self, host: &str) -> bool {
        self.hosts.contains(host)
    }

    /// Returns true if the given IP has been observed
    pub fn contains_ip(&self, ip: IpAddr) -> bool {
        self.ips.contains(&ip)
    }

    /// Returns the number of unique destinations
    pub fn len(&self) -> usize {
        self.hosts.len()
    }

    /// Returns true if no destinations have been tracked
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }

    /// Returns all unique hosts
    pub fn hosts(&self) -> &HashSet<String> {
        &self.hosts
    }

    /// Returns all unique IPs
    pub fn ips(&self) -> &HashSet<IpAddr> {
        &self.ips
    }

    /// Returns only the domain names (not IPs)
    pub fn domains(&self) -> Vec<&str> {
        self.hosts
            .iter()
            .filter(|h| !is_ip_address(h))
            .map(|h| h.as_str())
            .collect()
    }

    /// Returns only the IP addresses as strings
    pub fn ip_addresses(&self) -> Vec<&str> {
        self.hosts
            .iter()
            .filter(|h| is_ip_address(h))
            .map(|h| h.as_str())
            .collect()
    }

    /// Returns the most frequently contacted destinations (top N)
    pub fn top_destinations(&self, n: usize) -> Vec<(&String, u32)> {
        let mut counts: Vec<(&String, u32)> = self
            .connection_counts
            .iter()
            .map(|(k, v)| (k, *v))
            .collect();
        counts.sort_by(|a, b| b.1.cmp(&a.1));
        counts.truncate(n);
        counts
    }

    /// Returns the duration since tracking started
    pub fn duration(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// Returns how long ago a destination was first seen
    pub fn age(&self, host: &str) -> Option<Duration> {
        self.first_seen.get(host).map(|t| t.elapsed())
    }

    /// Merges another tracker into this one
    pub fn merge(&mut self, other: &DestinationTracker) {
        for host in &other.hosts {
            self.record(host.clone());
        }
        for ip in &other.ips {
            self.ips.insert(*ip);
        }
    }

    /// Returns a summary report of destinations
    pub fn summary(&self) -> String {
        let domains = self.domains().len();
        let ips = self.ip_addresses().len();
        let unique = self.len();

        format!(
            "Destination Summary: {} unique ({} domains, {} IPs)",
            unique, domains, ips
        )
    }

    /// Clears all tracked destinations
    pub fn clear(&mut self) {
        self.hosts.clear();
        self.ips.clear();
        self.first_seen.clear();
        self.connection_counts.clear();
        self.started_at = Instant::now();
    }
}

/// Checks if a string looks like an IP address
fn is_ip_address(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok()
}

/// Categorizes a destination by type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationType {
    /// IPv4 address
    Ipv4,
    /// IPv6 address
    Ipv6,
    /// Domain name
    Domain,
    /// Private/local IP
    Private,
    /// Multicast address
    Multicast,
    /// Broadcast address
    Broadcast,
}

impl DestinationType {
    /// Categorizes an IP address
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ipv4) => {
                if ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local() {
                    DestinationType::Private
                } else if ipv4.is_multicast() {
                    DestinationType::Multicast
                } else if ipv4.is_broadcast() {
                    DestinationType::Broadcast
                } else {
                    DestinationType::Ipv4
                }
            }
            IpAddr::V6(ipv6) => {
                if ipv6.is_loopback()
                    || ipv6.is_unique_local()
                    || (ipv6.segments()[0] & 0xFE00) == 0xFC00
                {
                    DestinationType::Private
                } else if ipv6.is_multicast() {
                    DestinationType::Multicast
                } else {
                    DestinationType::Ipv6
                }
            }
        }
    }

    /// Returns true if this is a public internet destination
    pub fn is_public_internet(&self) -> bool {
        matches!(
            self,
            DestinationType::Ipv4 | DestinationType::Ipv6 | DestinationType::Domain
        )
    }

    /// Returns true if this is a private/local destination
    pub fn is_private(&self) -> bool {
        matches!(self, DestinationType::Private)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_track_destinations() {
        let mut tracker = DestinationTracker::new();

        tracker.record("example.com".to_string());
        tracker.record("93.184.216.34".to_string());
        tracker.record("example.com".to_string()); // Duplicate

        assert_eq!(tracker.len(), 2);
        assert!(tracker.contains("example.com"));
        assert!(tracker.contains("93.184.216.34"));
    }

    #[test]
    fn test_record_ip() {
        let mut tracker = DestinationTracker::new();

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        tracker.record_ip(ip);

        assert!(tracker.contains_ip(ip));
        assert!(tracker.contains("192.168.1.1"));
    }

    #[test]
    fn test_top_destinations() {
        let mut tracker = DestinationTracker::new();

        // Add multiple connections
        for _ in 0..5 {
            tracker.record("popular.com".to_string());
        }
        for _ in 0..3 {
            tracker.record("medium.com".to_string());
        }
        tracker.record("rare.com".to_string());

        let top = tracker.top_destinations(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].0, "popular.com");
        assert_eq!(top[0].1, 5);
    }

    #[test]
    fn test_destination_type() {
        assert!(DestinationType::from_ip("8.8.8.8".parse().unwrap()).is_public_internet());
        assert!(DestinationType::from_ip("192.168.1.1".parse().unwrap()).is_private());
        assert!(DestinationType::from_ip("127.0.0.1".parse().unwrap()).is_private());
    }

    #[test]
    fn test_summary() {
        let mut tracker = DestinationTracker::new();
        tracker.record("example.com".to_string());
        tracker.record("1.2.3.4".to_string());

        let summary = tracker.summary();
        assert!(summary.contains("2 unique"));
        assert!(summary.contains("1 domain"));
        assert!(summary.contains("1 IP"));
    }
}
