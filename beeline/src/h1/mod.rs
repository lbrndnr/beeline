mod dfa;
mod parser;

pub use parser::AttachedParser;
pub use parser::Parser;

use anyhow::{Result, bail};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct StateId(u16);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct CaptureId(u16);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct MatchId(u16);

/// The action a single state carries. A state either starts or ends a capture,
/// and optionally terminates parsing.
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

    /// Starts capturing a range and terminates parsing
    StartCaptureAndDone(CaptureId),

    /// Ends capturing a range and terminates parsing
    EndCaptureAndDone(CaptureId, MatchId),
}

impl Action {
    /// Combines `self` with `action`. Since a state carries a single capture,
    /// this fails if the two capture different ranges. Pushing the very same
    /// action twice is a no-op, states are shared between patterns after all.
    pub(crate) fn push(self, action: Action) -> Result<Action> {
        let action = match (self, action) {
            (action, other) if action == other => action,

            // [`Action::Done`] combines with any capture
            (Action::Done, Action::StartCapture(cid))
            | (Action::StartCapture(cid), Action::Done)
            | (Action::Done, Action::StartCaptureAndDone(cid))
            | (Action::StartCaptureAndDone(cid), Action::Done) => Action::StartCaptureAndDone(cid),

            (Action::Done, Action::EndCapture(cid, mid))
            | (Action::EndCapture(cid, mid), Action::Done)
            | (Action::Done, Action::EndCaptureAndDone(cid, mid))
            | (Action::EndCaptureAndDone(cid, mid), Action::Done) => {
                Action::EndCaptureAndDone(cid, mid)
            }

            // a capture combines with the very same capture that is also done
            (Action::StartCapture(cid), Action::StartCaptureAndDone(other))
            | (Action::StartCaptureAndDone(other), Action::StartCapture(cid))
                if cid == other =>
            {
                Action::StartCaptureAndDone(cid)
            }

            (Action::EndCapture(cid, mid), Action::EndCaptureAndDone(other_cid, other_mid))
            | (Action::EndCaptureAndDone(other_cid, other_mid), Action::EndCapture(cid, mid))
                if (cid, mid) == (other_cid, other_mid) =>
            {
                Action::EndCaptureAndDone(cid, mid)
            }

            (action, other) => bail!("Cannot {action:?} and {other:?} with the same state"),
        };

        Ok(action)
    }
}
