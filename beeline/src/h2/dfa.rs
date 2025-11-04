use crate::h2::Action;
use anyhow::Result;
use log::trace;
use std::collections::{HashMap, HashSet};

pub struct DfaBuilder<'a> {
    dfa: &'a mut Dfa,
    start: u16,

    /// The current state id
    sid: u16,

    /// the last input
    prev_trans: Option<(u16, u8)>,

    /// The current capture id
    cid: Option<u8>,
}

impl DfaBuilder<'_> {
    pub fn push(&mut self, input: &[u8]) -> Result<&mut Self> {
        self.sid = self.push_from(self.sid, input)?;

        Ok(self)
    }

    fn push_from(&mut self, mut sid: u16, input: &[u8]) -> Result<u16> {
        // trace!(target: "dfa", "push: {}, from {}", input.escape_debug(), sid);
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

        Ok(sid)
    }

    pub fn capture_field_value(&mut self) -> &mut Self {
        assert!(self.prev_trans.is_some());
        println!("capture_field_value {:?}", self.prev_trans);

        let cid = self.dfa.insert_new_capture_start();

        if let Some((_, act)) = self.dfa.transitions.get_mut(&self.prev_trans.unwrap()) {
            *act = Action::CaptureFieldValue(cid);
        }
        self
    }

    fn get_sid(&self, input: &[u8]) -> Option<u16> {
        let mut sid = self.start;
        for c in input.iter() {
            if let Some((to, _)) = self.dfa.transitions.get(&(sid, *c)) {
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
    transitions: HashMap<(u16, u8), (u16, Action)>,
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

    pub fn start_pattern<'a>(&'a mut self, from: u16) -> DfaBuilder<'a> {
        trace!(target: "dfa", "start_pattern: {} --> ", from);
        DfaBuilder {
            dfa: self,
            start: from,
            sid: from,
            cid: None,
            prev_trans: None,
        }
    }

    pub fn iter_states<'a>(&'a self) -> impl Iterator<Item = &'a u16> {
        self.states.iter()
    }

    pub fn iter_transitions<'a>(
        &'a self,
    ) -> impl Iterator<Item = (&'a u16, &'a u16, &'a u8, &'a Action)> {
        self.transitions
            .iter()
            .map(|((from, input), (to, action))| (from, to, input, action))
    }
}
