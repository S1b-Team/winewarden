#[derive(Debug, Clone)]
pub struct DnsObservation {
    pub query: String,
    pub resolved: Vec<String>,
}
