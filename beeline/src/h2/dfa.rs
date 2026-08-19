use crate::h2::Action;
use std::collections::{HashMap, HashSet};
use tracing::trace;

/// Builds a single pattern into a [`Dfa`].
///
/// A pattern is the Huffman encoded name of a header field; the value that
/// follows it is captured by the action of the last transition, which is why
/// the builder keeps track of that transition.
pub struct DfaBuilder<'a> {
    dfa: &'a mut Dfa,

    /// The current state id
    sid: u16,

    /// the last input
    prev_trans: Option<(u16, u8)>,
}

impl DfaBuilder<'_> {
    /// Appends `input` to the pattern, one transition per byte.
    pub fn push(&mut self, input: &[u8]) -> &mut Self {
        self.sid = self.push_from(self.sid, input);

        self
    }

    /// Appends `input` starting at `sid` and returns the state it ends in,
    /// reusing the transitions another pattern already inserted.
    ///
    /// # Panics
    ///
    /// Panics if `sid` is not a state of the DFA.
    fn push_from(&mut self, mut sid: u16, input: &[u8]) -> u16 {
        assert!(self.dfa.states.contains(&sid));

        for c in input.iter() {
            self.prev_trans = Some((sid, *c));

            if let Some((to, _)) = self
                .dfa
                .transitions
                .get(&(sid, *c))
                .map(|(to, action)| (*to, *action))
            {
                trace!(target: "dfa", "push_optional: reusing transition");
                sid = to;
            } else {
                trace!(target: "dfa", "push_optional: inserting new transition");
                let next = self.dfa.insert_state();
                self.dfa.insert_transition(sid, next, *c, Action::None);
                sid = next;
            }
        }

        sid
    }

    /// Captures the value of the field the pattern matches.
    ///
    /// # Panics
    ///
    /// Panics if the pattern is still empty.
    pub fn capture_field_value(&mut self) -> &mut Self {
        assert!(self.prev_trans.is_some());

        let cid = self.dfa.insert_new_capture_start();

        if let Some((_, act)) = self.dfa.transitions.get_mut(&self.prev_trans.unwrap()) {
            *act = Action::CaptureFieldValue(cid);
        }
        self
    }
}

/// The DFA the patterns of a [`Parser`](super::Parser) are compiled into.
///
/// It is injected into the BPF parser program as a table of transitions,
/// indexed by state and input byte.
pub(crate) struct Dfa {
    /// The next free state id
    sid: u16,

    /// The next free capture id
    cid: u8,

    /// The states of the DFA, including the reserved ones.
    states: HashSet<u16>,

    /// The transitions of the DFA, keyed by state and input.
    transitions: HashMap<(u16, u8), (u16, Action)>,
}

impl Dfa {
    /// Creates a DFA that holds nothing but `reserved_states`, the states the
    /// BPF parser refers to by a fixed id.
    pub fn new(reserved_states: impl Iterator<Item = u16>) -> Dfa {
        Dfa {
            sid: 0,
            cid: 0,
            states: reserved_states.collect(),
            transitions: HashMap::new(),
        }
    }

    /// Inserts an unused state and returns its id.
    fn insert_state(&mut self) -> u16 {
        while self.states.contains(&self.sid) {
            self.sid += 1;
        }

        self.states.insert(self.sid);
        self.sid
    }

    /// Returns an unused capture id.
    fn insert_new_capture_start(&mut self) -> u8 {
        let cid = self.cid;
        self.cid += 1;
        cid
    }

    /// Inserts a transition from `from` to `to`, matching `input` and carrying
    /// `action`. Returns the transition it replaced, if there was one.
    pub fn insert_transition(
        &mut self,
        from: u16,
        to: u16,
        input: u8,
        action: Action,
    ) -> Option<(u16, Action)> {
        // let lc_input = input.to_ascii_lowercase();
        // let uc_input = input.to_ascii_uppercase();

        if let Some(transition) = self.transitions.insert((from, input), (to, action)) {
            return Some(transition);
        }

        trace!(target: "dfa", "insert_transition: {} --({})--> {} {:?}", from, input, to, action);

        // if lc_input != uc_input {
        //     if let Some(transition) = self.transitions.insert((from, uc_input), (to, action)) {
        //         return Some(transition);
        //     }
        // }

        None
    }

    /// Starts a new pattern, anchored at the state `from`.
    pub fn start_pattern<'a>(&'a mut self, from: u16) -> DfaBuilder<'a> {
        trace!(target: "dfa", "start_pattern: {} --> ", from);
        DfaBuilder {
            dfa: self,
            sid: from,
            prev_trans: None,
        }
    }

    /// Returns an iterator over the transitions of the DFA.
    pub fn iter_transitions<'a>(
        &'a self,
    ) -> impl Iterator<Item = (&'a u16, &'a u16, &'a u8, &'a Action)> {
        self.transitions
            .iter()
            .map(|((from, input), (to, action))| (from, to, input, action))
    }
}
