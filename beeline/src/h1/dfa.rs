use crate::h1::{Action, Actions};
use anyhow::{Result, bail};
use std::collections::{HashMap, HashSet};
use tracing::trace;

pub struct DfaBuilder<'a> {
    dfa: &'a mut Dfa,
    start: u16,

    /// The current capture id
    cid: Option<u8>,

    /// The current state id
    sid: u16,

    /// `true` if the current pattern captures a range
    capturing: bool,
}

impl DfaBuilder<'_> {
    pub fn push(&mut self, input: &str) -> Result<&mut Self> {
        self.sid = self.push_from(self.sid, input)?;

        Ok(self)
    }

    fn push_from(&mut self, mut sid: u16, input: &str) -> Result<u16> {
        trace!(target: "dfa", "push_from; input={}, from={}", input.escape_debug(), sid);
        assert!(self.dfa.states.contains(&sid));

        for c in input.chars() {
            let start_capture = self.capturing && self.cid.is_none();
            let action = if start_capture {
                self.cid = Some(self.dfa.insert_new_capture_start());
                Some(Action::StartCapture(self.cid.unwrap()))
            } else {
                None
            };

            if let Some((to, actions)) = self.dfa.transitions.get_mut(&(sid, c)) {
                trace!(target: "dfa", "push_from; reusing transition");

                if let Some(action) = action {
                    actions.try_push(action)?;
                }

                sid = *to;
            } else {
                trace!(target: "dfa", "push_from; inserting new transition");

                let actions = action.map(|a| vec![a]).unwrap_or_default();
                let next = self.dfa.insert_state();
                self.dfa.insert_transition(sid, next, c, actions);
                sid = next;
            }
        }

        Ok(sid)
    }

    pub fn push_optional(&mut self, input: char) -> Result<&mut Self> {
        trace!(target: "dfa", "push_optional; input={}", input.escape_debug());
        assert!(self.dfa.states.contains(&self.sid));

        // if we start capturing, we have to create a new state
        let start_capture = self.capturing && self.cid.is_none();
        if start_capture {
            self.push(&input.to_string())?;
        }

        // we can keep in the current state as long as we want
        if let Some((to, actions)) =
            self.dfa
                .insert_transition(self.sid, self.sid, input, Vec::new())
        {
            // TODO: refine this condition
            if to != self.sid || actions.len() > 0 {
                bail!("Conflicting transition for optional input.");
            }
        }

        Ok(self)
    }

    pub fn start_capturing(&mut self) -> &mut Self {
        self.capturing = true;
        self
    }

    pub fn end_capturing(&mut self, input: &str) -> Result<&mut Self> {
        trace!(target: "dfa", "end_capturing; input={}", input.escape_debug());
        if !self.capturing || self.cid.is_none() {
            bail!("No capture ID set.");
        }

        let rid = self.dfa.insert_new_range();
        let to = self.dfa.insert_state();
        self.end_pattern(input, Action::EndCapture(self.cid.unwrap(), rid), Some(to))?;
        self.cid = None;
        self.capturing = false;

        Ok(self)
    }

    pub fn end_caputuring_and_restart_with(
        &mut self,
        input: &str,
        restart_from: u16,
    ) -> Result<&mut Self> {
        trace!(target: "dfa", "end_capturing_and_restart_with; input={}", input.escape_debug());
        if !self.capturing || self.cid.is_none() {
            bail!("No capture ID set.");
        }

        let rid = self.dfa.insert_new_range();
        let to = match self.get_sid(input) {
            Some(sid) => sid,
            None => self.push_from(restart_from, input)?,
        };

        self.end_pattern(input, Action::EndCapture(self.cid.unwrap(), rid), Some(to))
    }

    pub fn done_on(&mut self, input: &str) -> Result<&mut Self> {
        if self.capturing || self.cid.is_some() {
            bail!("Capturing range will always fail.");
        }

        self.end_pattern(input, Action::Done, None)
    }

    fn end_pattern(&mut self, input: &str, action: Action, to: Option<u16>) -> Result<&mut Self> {
        let all_but_last: String = input.chars().take(input.len() - 1).collect();

        if all_but_last.len() > 0 {
            self.push(&all_but_last)?;
        }

        let last_char = input.chars().last().unwrap();
        let to = to
            .or_else(|| {
                if let Some((state, _)) = self.dfa.transitions.get(&(self.sid, last_char)) {
                    return Some(*state);
                }

                None
            })
            .unwrap_or_else(|| self.dfa.insert_state());

        if let Some((to_old, actions)) = self.dfa.transitions.get_mut(&(self.sid, last_char)) {
            if to != *to_old {
                bail!(
                    "Conflicting transition from state {} with input {}",
                    self.sid,
                    last_char,
                );
            }
            actions.try_push(action)?;
        } else {
            _ = self
                .dfa
                .insert_transition(self.sid, to, last_char, vec![action]);
        }

        self.sid = to;

        Ok(self)
    }

    fn get_sid(&self, input: &str) -> Option<u16> {
        let mut sid = self.start;
        for c in input.chars() {
            if let Some((to, _)) = self.dfa.transitions.get(&(sid, c)) {
                sid = *to;
            } else {
                return None;
            }
        }

        Some(sid)
    }
}

pub(crate) struct Dfa {
    /// The next free state id
    sid: u16,

    /// The next free capture id
    cid: u8,

    /// The next free range id
    rid: u8,

    states: HashSet<u16>,
    transitions: HashMap<(u16, char), (u16, Vec<Action>)>,
}

impl Dfa {
    pub fn new(reserved_states: impl Iterator<Item = u16>) -> Dfa {
        Dfa {
            sid: 0,
            cid: 0,
            rid: 0,
            states: reserved_states.collect(),
            transitions: HashMap::new(),
        }
    }

    fn insert_state(&mut self) -> u16 {
        while self.states.contains(&self.sid) {
            self.sid += 1;
        }

        self.states.insert(self.sid);
        self.sid
    }

    fn insert_new_capture_start(&mut self) -> u8 {
        let cid = self.cid;
        self.cid += 1;
        cid
    }

    fn insert_new_range(&mut self) -> u8 {
        let rid = self.rid;
        self.rid += 1;
        rid
    }

    pub fn insert_transition(
        &mut self,
        from: u16,
        to: u16,
        input: char,
        actions: Vec<Action>,
    ) -> Option<(u16, Vec<Action>)> {
        trace!(target: "dfa", "insert_transition; {} --({})--> {} {:?}", from, input.escape_debug(), to, actions);

        let lc_input = input.to_ascii_lowercase();
        let uc_input = input.to_ascii_uppercase();

        if let Some(transition) = self
            .transitions
            .insert((from, lc_input), (to, actions.clone()))
        {
            return Some(transition);
        }

        if lc_input != uc_input {
            if let Some(transition) = self.transitions.insert((from, uc_input), (to, actions)) {
                return Some(transition);
            }
        }

        None
    }

    pub fn start_pattern<'a>(&'a mut self, from: u16) -> DfaBuilder<'a> {
        trace!(target: "dfa", "start_pattern; from={}", from);
        DfaBuilder {
            dfa: self,
            start: from,
            sid: from,
            cid: None,
            capturing: false,
        }
    }

    pub fn iter_transitions<'a>(
        &'a self,
    ) -> impl Iterator<Item = (&'a u16, &'a u16, &'a char, &'a [Action])> {
        self.transitions
            .iter()
            .map(|((from, input), (to, actions))| (from, to, input, actions.as_slice()))
    }
}
