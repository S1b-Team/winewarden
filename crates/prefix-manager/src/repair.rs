#[derive(Debug, Clone)]
pub struct RepairAction {
    pub description: String,
}

impl RepairAction {
    pub fn new(description: String) -> Self {
        Self { description }
    }
}
