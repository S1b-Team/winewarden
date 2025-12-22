pub mod destinations;
pub mod dns;
pub mod telemetry;

use destinations::DestinationSet;

#[derive(Debug, Default)]
pub struct NetCompat {
    pub destinations: DestinationSet,
}

impl NetCompat {
    pub fn new() -> Self {
        Self::default()
    }
}
