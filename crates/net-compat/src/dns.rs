//! DNS capture and observation tracking.
//!
//! This module tracks DNS queries and their responses to provide
//! domain-level awareness for the policy engine.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Observed DNS query and its resolution
#[derive(Debug, Clone)]
pub struct DnsObservation {
    /// The domain name queried
    pub query: String,
    /// Resolved IP addresses
    pub resolved: Vec<String>,
    /// When the query was first observed
    pub first_seen: Instant,
    /// When the query was last observed
    pub last_seen: Instant,
    /// Number of times this query was made
    pub query_count: u32,
}

impl DnsObservation {
    /// Creates a new DNS observation
    pub fn new(query: String) -> Self {
        let now = Instant::now();
        Self {
            query,
            resolved: Vec::new(),
            first_seen: now,
            last_seen: now,
            query_count: 1,
        }
    }

    /// Records a repeated query
    pub fn record_query(&mut self) {
        self.last_seen = Instant::now();
        self.query_count = self.query_count.saturating_add(1);
    }

    /// Records resolved IPs
    pub fn record_resolved(&mut self, ips: Vec<String>) {
        for ip in ips {
            if !self.resolved.contains(&ip) {
                self.resolved.push(ip);
            }
        }
        self.last_seen = Instant::now();
    }

    /// Returns true if this observation has resolved IPs
    pub fn is_resolved(&self) -> bool {
        !self.resolved.is_empty()
    }

    /// Returns how long ago this query was last seen
    pub fn age(&self) -> Duration {
        self.last_seen.elapsed()
    }
}

/// Captures and tracks DNS activity
#[derive(Debug, Default)]
pub struct DnsCapture {
    /// Map of domain name to observation
    pub queries: HashMap<String, DnsObservation>,
    /// Maximum number of queries to track (LRU eviction)
    max_entries: usize,
}

impl DnsCapture {
    /// Creates a new DNS capture with default settings
    pub fn new() -> Self {
        Self {
            queries: HashMap::new(),
            max_entries: 1000,
        }
    }

    /// Creates a new DNS capture with custom max entries
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            queries: HashMap::with_capacity(max_entries),
            max_entries,
        }
    }

    /// Records a DNS query
    pub fn record_query(&mut self, query: &str) {
        let query = normalize_domain(query);

        if let Some(obs) = self.queries.get_mut(&query) {
            obs.record_query();
        } else {
            // Check if we need to evict old entries
            if self.queries.len() >= self.max_entries {
                self.evict_oldest();
            }

            self.queries
                .insert(query.clone(), DnsObservation::new(query));
        }
    }

    /// Records a DNS response with resolved IPs
    pub fn record_response(&mut self, query: &str, resolved: Vec<String>) {
        let query = normalize_domain(query);

        if let Some(obs) = self.queries.get_mut(&query) {
            obs.record_resolved(resolved);
        } else {
            // Response without seeing query first - create entry
            let mut obs = DnsObservation::new(query.clone());
            obs.record_resolved(resolved);
            self.queries.insert(query, obs);
        }
    }

    /// Looks up a domain's observation
    pub fn lookup(&self, domain: &str) -> Option<&DnsObservation> {
        self.queries.get(&normalize_domain(domain))
    }

    /// Returns true if the given IP was resolved from a DNS query
    pub fn is_known_ip(&self, ip: &str) -> bool {
        self.queries
            .values()
            .any(|obs| obs.resolved.contains(&ip.to_string()))
    }

    /// Returns domains that resolved to the given IP
    pub fn domains_for_ip(&self, ip: &str) -> Vec<&str> {
        self.queries
            .iter()
            .filter(|(_, obs)| obs.resolved.contains(&ip.to_string()))
            .map(|(domain, _)| domain.as_str())
            .collect()
    }

    /// Returns all resolved domains
    pub fn resolved_domains(&self) -> Vec<&str> {
        self.queries
            .iter()
            .filter(|(_, obs)| obs.is_resolved())
            .map(|(domain, _)| domain.as_str())
            .collect()
    }

    /// Returns all unresolved domains (queries without responses)
    pub fn pending_queries(&self) -> Vec<&str> {
        self.queries
            .iter()
            .filter(|(_, obs)| !obs.is_resolved())
            .map(|(domain, _)| domain.as_str())
            .collect()
    }

    /// Clears old entries older than the given duration
    pub fn clear_old(&mut self, max_age: Duration) {
        self.queries.retain(|_, obs| obs.age() < max_age);
    }

    /// Returns the number of tracked queries
    pub fn len(&self) -> usize {
        self.queries.len()
    }

    /// Returns true if no queries are tracked
    pub fn is_empty(&self) -> bool {
        self.queries.is_empty()
    }

    /// Evicts the oldest entry (simple LRU)
    fn evict_oldest(&mut self) {
        if let Some(oldest) = self
            .queries
            .iter()
            .min_by_key(|(_, obs)| obs.last_seen)
            .map(|(k, _)| k.clone())
        {
            self.queries.remove(&oldest);
        }
    }
}

/// Normalizes a domain name (lowercase, trim trailing dot)
fn normalize_domain(domain: &str) -> String {
    domain.trim_end_matches('.').to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_capture() {
        let mut capture = DnsCapture::new();

        // Record a query
        capture.record_query("example.com");
        assert_eq!(capture.len(), 1);

        // Record response
        capture.record_response("example.com", vec!["93.184.216.34".to_string()]);

        let obs = capture.lookup("example.com").unwrap();
        assert_eq!(obs.query, "example.com");
        assert_eq!(obs.resolved, vec!["93.184.216.34"]);
        assert!(obs.is_resolved());
    }

    #[test]
    fn test_duplicate_queries() {
        let mut capture = DnsCapture::new();

        capture.record_query("test.com");
        capture.record_query("test.com");
        capture.record_query("test.com");

        let obs = capture.lookup("test.com").unwrap();
        assert_eq!(obs.query_count, 3);
    }

    #[test]
    fn test_domain_normalization() {
        let mut capture = DnsCapture::new();

        capture.record_query("Example.COM");
        capture.record_query("example.com.");

        // Should be treated as same domain
        assert_eq!(capture.len(), 1);

        let obs = capture.lookup("EXAMPLE.COM").unwrap();
        assert_eq!(obs.query_count, 2);
    }

    #[test]
    fn test_ip_to_domain_lookup() {
        let mut capture = DnsCapture::new();

        capture.record_response(
            "api.example.com",
            vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()],
        );
        capture.record_response("cdn.example.com", vec!["5.6.7.8".to_string()]);

        assert!(capture.is_known_ip("1.2.3.4"));
        assert!(capture.is_known_ip("5.6.7.8"));
        assert!(!capture.is_known_ip("9.9.9.9"));

        let domains = capture.domains_for_ip("5.6.7.8");
        assert!(domains.contains(&"api.example.com"));
        assert!(domains.contains(&"cdn.example.com"));
    }

    #[test]
    fn test_capacity_limit() {
        let mut capture = DnsCapture::with_capacity(3);

        capture.record_query("a.com");
        capture.record_query("b.com");
        capture.record_query("c.com");
        capture.record_query("d.com"); // Should evict oldest

        assert_eq!(capture.len(), 3);
    }
}
