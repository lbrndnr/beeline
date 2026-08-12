mod dfa;
mod parser;
use anyhow::{Result, bail};
use std::mem::discriminant;

pub use parser::AttachedParser;
pub use parser::Parser;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct StateId(u16);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct CaptureId(u16);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct MatchId(u16);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    /// Starts capturing a range
    /// The start index is identified by the cid
    StartCapture(CaptureId),

    /// Ends capturing a range with a given cid (1st argument)
    /// The range is identified by the rid (2nd argument)
    EndCapture(CaptureId, MatchId),

    /// Terminates parsing
    Done,
}

trait Actions: Sized {
    /// Tries to push an action. Fails if the resulting vector
    /// contains conflicting actions.
    fn try_push(&mut self, action: Action) -> Result<()>;
}

impl Actions for Vec<Action> {
    fn try_push(&mut self, action: Action) -> Result<()> {
        if self.contains(&Action::Done) || action == Action::Done {
            self.clear();
            self.push(action);
            return Ok(());
        }

        for a in self.iter() {
            if discriminant(a) == discriminant(&action) && a != &action {
                bail!(
                    "conflicting actions: duplicate {:?} action with different payload",
                    action
                );
            }
        }

        self.push(action);
        Ok(())
    }
}
