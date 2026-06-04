use crate::h1::Action;
use anyhow::{Result, bail};
use regex_automata::{
    Anchored, Input,
    dfa::{Automaton, dense},
    util::syntax,
};
use std::collections::{HashMap, HashSet};
use tracing::trace;

/// Builds the literal `text` (ASCII case-insensitive) into a `regex_automata`
/// dense DFA, then iterates that DFA's states and transitions to recover the
/// chain of byte-classes that make up the literal.
///
/// Each element of the returned vector corresponds to one position in the
/// literal and lists every byte that advances the DFA at that position (e.g. a
/// letter yields both its upper- and lower-case byte).
fn build_literal_chain(text: &str) -> Result<Vec<Vec<u8>>> {
    let mut pattern = String::new();
    for c in text.chars() {
        if c.is_ascii_alphabetic() {
            pattern.push('[');
            pattern.push(c.to_ascii_uppercase());
            pattern.push(c.to_ascii_lowercase());
            pattern.push(']');
        } else {
            pattern.push_str(&format!("\\x{:02x}", c as u32));
        }
    }

    let dfa = dense::DFA::builder()
        .syntax(syntax::Config::new().unicode(false).utf8(false))
        .build(&pattern)?;

    let start = dfa.start_state_forward(&Input::new("").anchored(Anchored::Yes))?;

    let mut chain = Vec::new();
    let mut s = start;
    loop {
        // the end of the literal is the state whose end-of-input transition is a
        // match; transitions out of it only exist to report longer matches and
        // must not be followed
        if dfa.is_match_state(dfa.next_eoi_state(s)) {
            break;
        }

        let mut target = None;
        let mut bytes = Vec::new();

        for b in 0u16..=255 {
            let b = b as u8;
            let next = dfa.next_state(s, b);
            if dfa.is_dead_state(next) {
                continue;
            }

            match target {
                None => {
                    target = Some(next);
                    bytes.push(b);
                }
                Some(t) if t == next => bytes.push(b),
                Some(_) => bail!("ambiguous literal DFA for {}", text.escape_debug()),
            }
        }

        match target {
            None => break,
            Some(t) => {
                chain.push(bytes);
                s = t;
            }
        }
    }

    Ok(chain)
}

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
        let entry = self.capturing && self.cid.is_none();
        let (end, cid) = self.dfa.splice(self.sid, input, entry)?;
        if let Some(c) = cid {
            self.cid = Some(c);
        }
        self.sid = end;

        Ok(self)
    }

    pub fn push_optional(&mut self, input: char) -> Result<&mut Self> {
        trace!(target: "dfa", "push_optional: {}", input.escape_debug());
        assert!(self.dfa.states.contains(&self.sid));

        // if we start capturing, we have to advance into a new state first so the
        // entry transition carries the StartCapture action
        let start_capture = self.capturing && self.cid.is_none();
        if start_capture {
            self.push(&input.to_string())?;
        }

        // we can keep in the current state as long as we want
        self.dfa
            .insert_transition(self.sid, self.sid, input, Action::None)?;

        Ok(self)
    }

    pub fn start_capturing(&mut self) -> &mut Self {
        self.capturing = true;
        self.cid = None;
        self
    }

    pub fn end_capturing(&mut self, input: &str) -> Result<&mut Self> {
        trace!(target: "dfa", "end_capturing: {}", input.escape_debug());
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
        trace!(target: "dfa", "end_capturing_and_restart_with: {}", input.escape_debug());
        if !self.capturing || self.cid.is_none() {
            bail!("No capture ID set.");
        }

        let rid = self.dfa.insert_new_range();
        let to = match self.walk(self.start, input) {
            Some(sid) => sid,
            None => self.dfa.splice(restart_from, input, false)?.0,
        };

        self.end_pattern(input, Action::EndCapture(self.cid.unwrap(), rid), Some(to))?;
        self.cid = None;
        self.capturing = false;

        Ok(self)
    }

    pub fn done_on(&mut self, input: &str) -> Result<&mut Self> {
        if self.capturing || self.cid.is_some() {
            bail!("Capturing range will always fail.");
        }

        self.end_pattern(input, Action::Done, None)
    }

    fn end_pattern(&mut self, input: &str, action: Action, to: Option<u16>) -> Result<&mut Self> {
        let chars: Vec<char> = input.chars().collect();
        assert!(!chars.is_empty());

        let (last, all_but_last) = chars.split_last().unwrap();
        let last = *last;

        if !all_but_last.is_empty() {
            let prefix: String = all_but_last.iter().collect();
            self.sid = self.dfa.splice(self.sid, &prefix, false)?.0;
        }

        let to = to
            .or_else(|| {
                if let Some((state, old_action)) = self.dfa.transitions.get(&(self.sid, last)) {
                    if *state == self.sid && (old_action.is_none() || *old_action == action) {
                        return Some(*state);
                    }
                }

                None
            })
            .unwrap_or_else(|| self.dfa.insert_state());

        self.dfa.insert_transition(self.sid, to, last, action)?;
        self.sid = to;

        Ok(self)
    }

    /// Walks existing transitions for `input` starting at `from`, returning the
    /// reached state if the whole input is already present in the graph.
    fn walk(&self, from: u16, input: &str) -> Option<u16> {
        let mut sid = from;
        for c in input.chars() {
            let next = self
                .dfa
                .transitions
                .get(&(sid, c))
                .or_else(|| self.dfa.transitions.get(&(sid, c.to_ascii_lowercase())))
                .or_else(|| self.dfa.transitions.get(&(sid, c.to_ascii_uppercase())))?;
            sid = next.0;
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
    transitions: HashMap<(u16, char), (u16, Action)>,
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

    /// Inserts a single transition, reconciling it with any transition that
    /// already exists for `(from, input)`.
    ///
    /// Reusing a transition is allowed as long as the target matches and the
    /// action is compatible (the existing action is `None`, identical, or the
    /// new action is `None`). Anything else is a construction conflict.
    fn insert_transition(
        &mut self,
        from: u16,
        to: u16,
        input: char,
        action: Action,
    ) -> Result<()> {
        if let Some((old_to, old_action)) = self.transitions.get(&(from, input)).copied() {
            if old_to != to {
                bail!(
                    "Conflicting transition target (old: {}, new: {}) on input {}",
                    old_to,
                    to,
                    input.escape_debug()
                );
            }

            // a None action never overwrites an existing one
            if action.is_none() {
                return Ok(());
            }

            if old_action.is_some() && old_action != action {
                bail!(
                    "Conflicting action (old: {:?}, new: {:?}) on input {}",
                    old_action,
                    action,
                    input.escape_debug()
                );
            }
        }

        trace!(target: "dfa", "insert_transition: {} --({})--> {} {:?}", from, input.escape_debug(), to, action);
        self.transitions.insert((from, input), (to, action));

        Ok(())
    }

    /// Materializes the literal `text` starting at state `from` by building a
    /// dense DFA for it and splicing its transitions into the graph, reusing
    /// any shared prefix already present.
    ///
    /// When `entry` is set the first transition of the literal carries a
    /// `StartCapture` action; the allocated (or reused) capture id is returned
    /// alongside the end state.
    fn splice(&mut self, from: u16, text: &str, entry: bool) -> Result<(u16, Option<u8>)> {
        let chain = build_literal_chain(text)?;
        let mut cur = from;
        let mut applied_cid = None;

        for (i, bytes) in chain.iter().enumerate() {
            // reuse an existing target if any byte of this position is already wired up
            let mut target = None;
            for &b in bytes {
                if let Some((to, _)) = self.transitions.get(&(cur, b as char)) {
                    target = Some(*to);
                    break;
                }
            }
            let target = target.unwrap_or_else(|| self.insert_state());

            let action = if i == 0 && entry {
                let existing = bytes
                    .iter()
                    .find_map(|&b| self.transitions.get(&(cur, b as char)).map(|(_, a)| *a));
                let cid = match existing {
                    Some(Action::StartCapture(c)) => c,
                    Some(Action::None) => {
                        bail!("Conflicting action: cannot start capturing on a shared transition")
                    }
                    Some(other) => bail!("Conflicting action {:?} when starting capture", other),
                    None => self.insert_new_capture_start(),
                };
                applied_cid = Some(cid);
                Action::StartCapture(cid)
            } else {
                Action::None
            };

            for &b in bytes {
                self.insert_transition(cur, target, b as char, action)?;
            }
            cur = target;
        }

        Ok((cur, applied_cid))
    }

    pub fn start_pattern<'a>(&'a mut self, from: u16) -> DfaBuilder<'a> {
        trace!(target: "dfa", "start_pattern: {} --> ", from);
        DfaBuilder {
            dfa: self,
            start: from,
            sid: from,
            cid: None,
            capturing: false,
        }
    }

    pub fn iter_states<'a>(&'a self) -> impl Iterator<Item = &'a u16> {
        self.states.iter()
    }

    pub fn iter_transitions<'a>(
        &'a self,
    ) -> impl Iterator<Item = (&'a u16, &'a u16, &'a char, &'a Action)> {
        self.transitions
            .iter()
            .map(|((from, input), (to, action))| (from, to, input, action))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S_ANY: u16 = 1;

    /// Mirrors the eBPF `_next` helper in `parser.bpf.c`.
    fn next(dfa: &Dfa, state: u16, byte: u8) -> (u16, Action) {
        if let Some(&(to, act)) = dfa.transitions.get(&(state, byte as char)) {
            return (to, act);
        }
        if let Some(&(to, act)) = dfa.transitions.get(&(state, '*')) {
            return (to, act);
        }
        (S_ANY, Action::None)
    }

    /// Mirrors the eBPF `_parse_from` capture bookkeeping and returns the
    /// captured ranges keyed by range id.
    fn run(dfa: &Dfa, input: &[u8]) -> HashMap<u8, (usize, usize)> {
        let mut cidx: HashMap<u8, usize> = HashMap::new();
        let mut ms: HashMap<u8, (usize, usize)> = HashMap::new();
        let mut s = 0u16;

        for (i, &c) in input.iter().enumerate() {
            let (mut ns, mut a) = next(dfa, s, c);
            if ns == S_ANY {
                let (ns2, a2) = next(dfa, S_ANY, c);
                ns = ns2;
                a = a2;
            }
            s = ns;

            match a {
                Action::StartCapture(cid) => {
                    cidx.insert(cid, i);
                }
                Action::EndCapture(cid, rid) => {
                    let start = cidx[&cid];
                    ms.insert(rid, (start, i - start - 1));
                    cidx.insert(cid, i);
                }
                _ => {}
            }
        }

        ms
    }

    fn captured<'a>(input: &'a [u8], range: (usize, usize)) -> &'a str {
        std::str::from_utf8(&input[range.0..range.0 + range.1]).unwrap()
    }

    #[test]
    fn literal_chain_is_case_insensitive() {
        let chain = build_literal_chain("user-agent").unwrap();
        assert_eq!(chain.len(), 10);
        assert_eq!(chain[0], vec![b'U', b'u']);
        assert_eq!(chain[4], vec![b'-']);
    }

    #[test]
    fn captures_header_value() {
        let mut dfa = Dfa::new(vec![0, 1].into_iter());
        dfa.start_pattern(S_ANY)
            .push("\r\n")
            .unwrap()
            .push("user-agent")
            .unwrap()
            .push_optional('\t')
            .unwrap()
            .push_optional(' ')
            .unwrap()
            .push(":")
            .unwrap()
            .push_optional('\t')
            .unwrap()
            .push_optional(' ')
            .unwrap()
            .start_capturing()
            .push_optional('*')
            .unwrap()
            .end_caputuring_and_restart_with("\r\n", S_ANY)
            .unwrap();

        let input = b"\r\nUser-Agent: beeline\r\n\r\n";
        let ms = run(&dfa, input);
        assert_eq!(captured(input, ms[&0]), "beeline");
    }

    #[test]
    fn captures_two_headers() {
        let mut dfa = Dfa::new(vec![0, 1].into_iter());
        for key in ["user-agent", "accept-language"] {
            dfa.start_pattern(S_ANY)
                .push("\r\n")
                .unwrap()
                .push(key)
                .unwrap()
                .push_optional('\t')
                .unwrap()
                .push_optional(' ')
                .unwrap()
                .push(":")
                .unwrap()
                .push_optional('\t')
                .unwrap()
                .push_optional(' ')
                .unwrap()
                .start_capturing()
                .push_optional('*')
                .unwrap()
                .end_caputuring_and_restart_with("\r\n", S_ANY)
                .unwrap();
        }

        let input = b"\r\nUser-Agent: beeline\r\nAccept-Language: sumsum\r\n\r\n";
        let ms = run(&dfa, input);
        assert_eq!(captured(input, ms[&0]), "beeline");
        assert_eq!(captured(input, ms[&1]), "sumsum");
    }

    #[test]
    fn realistic_parser_fits_state_byte() {
        let mut dfa = Dfa::new(vec![0, 1].into_iter());

        // preface
        dfa.start_pattern(0)
            .start_capturing()
            .push("PRI * HTTP/2.0")
            .unwrap()
            .push("\r\n")
            .unwrap()
            .push("\r\n")
            .unwrap()
            .end_capturing("SM")
            .unwrap()
            .push("\r\n")
            .unwrap()
            .done_on("\r\n")
            .unwrap();

        // request status line
        dfa.start_pattern(0)
            .start_capturing()
            .push_optional('*')
            .unwrap()
            .end_capturing(" ")
            .unwrap()
            .start_capturing()
            .push_optional('*')
            .unwrap()
            .push(" HTTP/1.1")
            .unwrap()
            .end_caputuring_and_restart_with("\r\n", S_ANY)
            .unwrap();

        // status code
        dfa.start_pattern(0)
            .push("HTTP/1.1 ")
            .unwrap()
            .start_capturing()
            .push_optional('*')
            .unwrap()
            .end_caputuring_and_restart_with("\r\n", S_ANY)
            .unwrap();

        for key in ["user-agent", "accept-language"] {
            dfa.start_pattern(S_ANY)
                .push("\r\n")
                .unwrap()
                .push(key)
                .unwrap()
                .push_optional('\t')
                .unwrap()
                .push_optional(' ')
                .unwrap()
                .push(":")
                .unwrap()
                .push_optional('\t')
                .unwrap()
                .push_optional(' ')
                .unwrap()
                .start_capturing()
                .push_optional('*')
                .unwrap()
                .end_caputuring_and_restart_with("\r\n", S_ANY)
                .unwrap();
        }

        // header end
        dfa.start_pattern(S_ANY)
            .push("\r\n")
            .unwrap()
            .done_on("\r\n")
            .unwrap();

        let max = dfa.iter_states().max().copied().unwrap();
        assert!(max < 256, "state id {} exceeds eBPF byte mask", max);
    }

    #[test]
    fn header_lookup_is_case_insensitive_on_key() {
        let mut dfa = Dfa::new(vec![0, 1].into_iter());
        dfa.start_pattern(S_ANY)
            .push("\r\n")
            .unwrap()
            .push("user-agent")
            .unwrap()
            .push(":")
            .unwrap()
            .push_optional(' ')
            .unwrap()
            .start_capturing()
            .push_optional('*')
            .unwrap()
            .end_caputuring_and_restart_with("\r\n", S_ANY)
            .unwrap();

        let input = b"\r\nUSER-AGENT: beeline\r\n\r\n";
        let ms = run(&dfa, input);
        assert_eq!(captured(input, ms[&0]), "beeline");
    }
}
