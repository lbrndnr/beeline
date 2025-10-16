mod dfa;
mod parser;
pub use parser::Parser;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Starts capturing a range
    /// The start index is identified by the cid
    StartCapture(u8),

    /// Ends capturing a range with a given cid (1st argument)
    /// The range is identified by the rid (2nd argument)
    EndCapture(u8, u8),

    /// Terminates parsing
    Done,

    // No action
    None,
}

impl Action {
    pub fn is_some(&self) -> bool {
        !self.is_none()
    }

    pub fn is_none(&self) -> bool {
        matches!(self, Action::None)
    }
}
