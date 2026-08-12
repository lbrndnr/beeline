use crate::h1::{Action, Actions, CaptureId, MatchId, StateId};
use std::{collections::HashMap, ops::RangeBounds};
use tracing::trace;

const INIT_STATE: StateId = StateId(0);
const ANY_STATE: StateId = StateId(1);

const ANY_INPUT: char = '*';

pub struct DfaBuilder<'a> {
    dfa: &'a mut Dfa,
    state: StateId,
    optional_prefixes: Vec<String>,
    start_capture: Option<CaptureId>,
    end_capture: Option<CaptureId>,
}

impl DfaBuilder<'_> {
    fn new(dfa: &mut Dfa, state: StateId) -> DfaBuilder<'_> {
        DfaBuilder {
            dfa,
            state,
            optional_prefixes: Vec::new(),
            start_capture: None,
            end_capture: None,
        }
    }

    fn push_edge_case_insensitive(
        &mut self,
        from: StateId,
        input: char,
        to: Option<StateId>,
    ) -> StateId {
        let to = to.unwrap_or(self.dfa.next_state(&from, &input));
        let lc = input.to_ascii_lowercase();
        self.dfa.insert_edge(from, lc, to);

        let uc = input.to_ascii_uppercase();
        if uc != lc {
            self.dfa.insert_edge(from, uc, to);
        }

        to
    }

    fn push_edge(&mut self, input: char, to: Option<StateId>) {
        let start = self.state;
        while let Some(optional) = self.optional_prefixes.pop() {
            let mut from = start;
            for (i, c) in optional.char_indices() {
                let to = if i == optional.len() - 1 {
                    Some(start)
                } else {
                    None
                };
                from = self.push_edge_case_insensitive(from, c, to);
            }
        }

        if let Some(id) = self.start_capture.take() {
            trace!("start_capturing; state={:?}, cid={:?} ", self.state, id);

            self.dfa.add_action(self.state, Action::StartCapture(id));
            self.end_capture = Some(id);
        }

        trace!(
            "push_edge; state={:?}, input={:?}, to={:?}",
            self.state, input, to
        );

        self.state = self.push_edge_case_insensitive(start, input, to);
    }

    pub fn push(&mut self, input: &str) -> &mut Self {
        for c in input.chars() {
            self.push_edge(c, None);
        }
        self
    }

    /// Pushes the [`ANY_INPUT`] character onto the [`Dfa`]. `range`
    /// specifies the min and max amount of times any character may
    /// appear in the matched string.
    pub fn push_any<R: RangeBounds<usize>>(&mut self, range: R) -> &mut Self {
        let min_len = match range.start_bound() {
            std::ops::Bound::Excluded(n) => *&n.saturating_sub(1),
            std::ops::Bound::Included(n) => *n,
            std::ops::Bound::Unbounded => 0,
        };

        let max_len = match range.end_bound() {
            std::ops::Bound::Excluded(n) => *&n.saturating_sub(1),
            std::ops::Bound::Included(n) => *n,
            std::ops::Bound::Unbounded => min_len,
        };

        trace!(
            "push_any; state={:?}, min_len={:?}, max_len={:?}",
            self.state, min_len, max_len
        );

        for _ in 0..min_len {
            self.push_edge(ANY_INPUT, None);
        }

        // the following transitions are optional and must point to `self.state`
        for i in 1..max_len - min_len {
            let prefix = ANY_INPUT.to_string().repeat(i);
            self.optional_prefixes.push(prefix);
        }

        if matches!(range.end_bound(), std::ops::Bound::Unbounded) {
            self.push_edge_case_insensitive(self.state, ANY_INPUT, Some(self.state));
        }

        self
    }

    pub fn push_optional(&mut self, input: &str) -> &mut Self {
        self.optional_prefixes.push(input.to_string());
        self
    }

    pub fn start_capturing(&mut self) -> &mut Self {
        assert!(self.start_capture.is_none());
        let cid = self.dfa.new_capture();

        self.start_capture = Some(cid);

        self
    }

    pub fn end_capturing(&mut self) -> &mut Self {
        let cid = self.end_capture.take().expect("No capture started");
        let mid = self.dfa.new_match();
        trace!(
            "end_capturing; state={:?}, cid={:?} mid={:?}",
            self.state, cid, mid
        );

        self.dfa
            .add_action(self.state, Action::EndCapture(cid, mid));

        self
    }

    /// Matches the given input string but sets the final state
    /// to the state the DFA would be in if it started from [`ANY_STATE`].
    pub fn restart_with(&mut self, input: &str) {
        let final_state = input
            .chars()
            .fold(ANY_STATE, |state, c| self.dfa.next_state(&state, &c));

        for (i, c) in input.char_indices() {
            let to = if i == input.len() - 1 {
                Some(final_state)
            } else {
                None
            };
            self.push_edge(c, to);
        }
    }

    pub fn done(&mut self) {
        self.dfa.add_action(self.state, Action::Done);
    }
}

type EdgeMap = HashMap<StateId, HashMap<char, StateId>>;
type ActionMap = HashMap<StateId, Vec<Action>>;

pub(crate) struct Dfa {
    num_captures: u16,
    num_matches: u16,
    num_states: u16,
    edges: EdgeMap,
    actions: ActionMap,
}

impl Dfa {
    pub fn new() -> Dfa {
        Dfa {
            num_captures: 0,
            num_matches: 0,
            num_states: 2,
            edges: HashMap::new(),
            actions: HashMap::new(),
        }
    }

    pub fn start_pattern<'a>(&'a mut self, status_line: bool) -> DfaBuilder<'a> {
        trace!(target: "dfa", "start_pattern; status_line={:?}", status_line);
        let state = if status_line { INIT_STATE } else { ANY_STATE };
        DfaBuilder::new(self, state)
    }

    fn new_state(&mut self) -> StateId {
        let id = StateId(self.num_states);
        self.num_states += 1;
        id
    }

    fn new_capture(&mut self) -> CaptureId {
        let id = CaptureId(self.num_captures);
        self.num_captures += 1;
        id
    }

    fn new_match(&mut self) -> MatchId {
        let id = MatchId(self.num_matches);
        self.num_matches += 1;
        id
    }

    /// Queries the edges to retrieve the next state from given state and
    /// input character. Creates a new state if none exists.
    fn next_state(&mut self, from: &StateId, input: &char) -> StateId {
        self.edges
            .get(from)
            .and_then(|es| es.get(input).map(|to| *to))
            .unwrap_or_else(|| self.new_state())
    }

    fn insert_edge(&mut self, from: StateId, input: char, to: StateId) {
        if let Some(to_old) = self.edges.entry(from).or_default().insert(input, to) {
            assert!(
                to_old == to,
                "Cannot create transition from {from:?} to {to_old:?} and {to:?}"
            );
        }
    }

    fn add_action(&mut self, state: StateId, action: Action) {
        self.actions
            .entry(state)
            .or_default()
            .try_push(action)
            .expect("Conflicting actions");
    }

    pub fn iter_transitions<'a>(
        &'a self,
    ) -> impl Iterator<Item = (&'a StateId, &'a StateId, &'a char, &'a [Action])> {
        self.edges.iter().flat_map(move |(from, edges)| {
            edges.iter().map(move |(input, to)| {
                let actions = self
                    .actions
                    .get(to)
                    .map(|actions| actions.as_slice())
                    .unwrap_or(&[]);
                (from, to, input, actions)
            })
        })
    }
}
