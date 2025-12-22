use std::collections::HashSet;

#[derive(Debug, Default, Clone)]
pub struct DestinationSet {
    pub hosts: HashSet<String>,
}

impl DestinationSet {
    pub fn remember(&mut self, host: String) {
        self.hosts.insert(host);
    }
}
