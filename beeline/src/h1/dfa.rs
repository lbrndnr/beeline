use crate::h1::Action;
use anyhow::{Result, bail};
use regex_automata::{
    Anchored, Input,
    dfa::{Automaton, dense},
    util::{primitives::StateID, syntax},
};
use regex_syntax::{
    ParserBuilder,
    hir::{Class, Hir, HirKind},
};
use std::collections::{HashMap, HashSet};
use tracing::trace;

pub(crate) const S_INIT: u16 = 0;
pub(crate) const S_ANY: u16 = 1;

/// A capture group of a pattern that should be exported as a range. `group` is
/// the regex capture-group index.
///
/// Capture groups within one pattern share a single scratch register (`cid`)
/// and chain: a `StartCapture` fires on the first byte of the first group, and
/// an `EndCapture(cid, rid)` fires one byte past each group's last captured
/// byte. The eBPF `EndCapture` both records the range and resets the register
/// to that boundary, so the next group's content is measured from there. This
/// assumes consecutive groups are separated by exactly one delimiter byte
/// (which holds for the HTTP grammar: `METHOD URI HTTP/1.1`).
pub(crate) struct Capture {
    pub group: usize,
}

/// A single pattern to splice into the parser DFA.
pub(crate) struct Pattern<'a> {
    /// State the pattern is anchored at (`S_INIT` or `S_ANY`).
    pub start: u16,
    /// The regex describing the pattern, including capture groups.
    pub regex: &'a str,
    pub captures: &'a [Capture],
    /// Where the terminating match transitions to (e.g. the shared post-CRLF
    /// state so subsequent headers keep matching). `None` for terminal patterns.
    pub restart_to: Option<u16>,
    /// Whether reaching the end of the pattern emits the `Done` action.
    pub done: bool,
}

/// The number of bytes that must share a target before that target is exported
/// through the wildcard `'*'` slot rather than as explicit per-byte
/// transitions. Capture bodies fan out to hundreds of bytes; literal states
/// only ever have a handful, so this cleanly separates the two.
const WILDCARD_THRESHOLD: usize = 8;

pub(crate) struct Dfa {
    /// The next free state id
    sid: u16,

    /// The next free scratch-register id (`cid`), one per pattern
    cid: u8,

    /// The next free result-slot id (`rid`), one per capture group
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

    fn new_cid(&mut self) -> u8 {
        let id = self.cid;
        self.cid += 1;
        id
    }

    fn new_rid(&mut self) -> u8 {
        let id = self.rid;
        self.rid += 1;
        id
    }

    /// Inserts a single transition, reconciling it with any transition that
    /// already exists for `(from, input)` (shared prefixes across patterns).
    fn insert_transition(&mut self, from: u16, to: u16, input: char, action: Action) -> Result<()> {
        if let Some((old_to, old_action)) = self.transitions.get(&(from, input)).copied() {
            if old_to != to {
                bail!(
                    "Conflicting transition target (old: {}, new: {}) on input {}",
                    old_to,
                    to,
                    input.escape_debug()
                );
            }

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

    /// Returns the state reached by following `input` from `from`, creating the
    /// path if it does not yet exist. Used to wire restart targets onto the
    /// shared post-CRLF state.
    pub fn ensure_path(&mut self, from: u16, input: &str) -> Result<u16> {
        let mut sid = from;
        for c in input.chars() {
            sid = match self.transitions.get(&(sid, c)) {
                Some((to, _)) => *to,
                None => {
                    let next = self.insert_state();
                    self.insert_transition(sid, next, c, Action::None)?;
                    next
                }
            };
        }

        Ok(sid)
    }

    /// Builds a dense DFA for `pattern.regex`, locates its capture boundary
    /// states, and splices the whole automaton into the parser graph (reusing
    /// shared prefixes).
    ///
    /// To map regex capture groups onto dense DFA states we need a concrete
    /// matching byte string and the group offsets within it. Both are derived
    /// structurally from the regex's HIR (`synthesize`): a representative match
    /// is generated while tracking where each capture group opens and closes.
    pub fn add_pattern(&mut self, pattern: Pattern) -> Result<()> {
        let dfa = dense::DFA::builder()
            .syntax(syntax::Config::new().unicode(false).utf8(false))
            .build(pattern.regex)?;
        let start = dfa.start_state_forward(&Input::new("").anchored(Anchored::Yes))?;

        let (path, group_spans) = Self::synthesize(pattern.regex)?;

        // replay the synthesized match to get the DFA state before every byte
        let mut walk = Vec::with_capacity(path.len() + 1);
        let mut s = start;
        walk.push(s);
        for &b in &path {
            s = dfa.next_state(s, b);
            walk.push(s);
        }

        // Locate capture boundaries and turn them into actions. A capture
        // "region entry" action (placed when first entering a group's content)
        // lives in `entry_actions`, keyed by the dense state it is entered from.
        // Final/terminal actions that fire on a specific (state, byte) literal
        // transition live in `explicit_actions`.
        let mut entry_actions: HashMap<usize, (StateID, Action)> = HashMap::new();
        let mut explicit_actions: HashMap<(usize, u8), Action> = HashMap::new();

        if !pattern.captures.is_empty() {
            let spans = pattern
                .captures
                .iter()
                .map(|cap| {
                    group_spans
                        .get(&cap.group)
                        .copied()
                        .ok_or_else(|| anyhow::anyhow!("missing capture group {}", cap.group))
                })
                .collect::<Result<Vec<_>>>()?;

            // one scratch register for the whole pattern
            let cid = self.new_cid();

            // StartCapture fires on the first content byte of the first group
            let entry = |actions: &mut HashMap<usize, (StateID, Action)>, idx: usize, a: Action| {
                let d = walk[idx];
                let tgt = dfa.next_state(d, path[idx]);
                actions.insert(d.as_usize(), (tgt, a));
            };
            entry(&mut entry_actions, spans[0].0, Action::StartCapture(cid));

            // EndCapture for group k fires one byte past its content. For all but
            // the last group this coincides with the next group's first content
            // byte, where it also serves to (re)start the register.
            for (k, &(_, span_end)) in spans.iter().enumerate() {
                let rid = self.new_rid();
                let action = Action::EndCapture(cid, rid);
                if let Some(&(next_start, _)) = spans.get(k + 1) {
                    entry(&mut entry_actions, next_start, action);
                } else {
                    let end = span_end + 1;
                    explicit_actions.insert((walk[end].as_usize(), path[end]), action);
                }
            }
        }

        if pattern.done {
            let last = path.len() - 1;
            explicit_actions.insert((walk[last].as_usize(), path[last]), Action::Done);
        }

        self.splice(&dfa, start, &pattern, &entry_actions, &explicit_actions)
    }

    /// Generates a representative byte string that matches `regex` together with
    /// the byte span of every capture group, derived structurally from the
    /// regex's HIR. Repetitions emit a single iteration (so capture bodies are
    /// non-empty), character classes emit one representative byte, and
    /// alternations take their first branch.
    fn synthesize(regex: &str) -> Result<(Vec<u8>, HashMap<usize, (usize, usize)>)> {
        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(regex)?;

        let mut path = Vec::new();
        let mut spans = HashMap::new();
        Self::emit(&hir, &mut path, &mut spans);

        Ok((path, spans))
    }

    fn emit(hir: &Hir, path: &mut Vec<u8>, spans: &mut HashMap<usize, (usize, usize)>) {
        match hir.kind() {
            HirKind::Empty | HirKind::Look(_) => {}
            HirKind::Literal(lit) => path.extend_from_slice(&lit.0),
            HirKind::Class(class) => path.push(Self::rep_byte(class)),
            HirKind::Repetition(rep) => {
                for _ in 0..rep.min.max(1) {
                    Self::emit(&rep.sub, path, spans);
                }
            }
            HirKind::Capture(cap) => {
                let start = path.len();
                Self::emit(&cap.sub, path, spans);
                spans.insert(cap.index as usize, (start, path.len()));
            }
            HirKind::Concat(subs) => {
                for sub in subs {
                    Self::emit(sub, path, spans);
                }
            }
            HirKind::Alternation(subs) => {
                if let Some(first) = subs.first() {
                    Self::emit(first, path, spans);
                }
            }
        }
    }

    /// Picks a representative byte from a character class, preferring a readable
    /// ASCII byte over control characters.
    fn rep_byte(class: &Class) -> u8 {
        let ranges: Vec<(u8, u8)> = match class {
            Class::Bytes(b) => b.ranges().iter().map(|r| (r.start(), r.end())).collect(),
            Class::Unicode(u) => u
                .ranges()
                .iter()
                .map(|r| (r.start() as u8, r.end().min('\u{ff}') as u8))
                .collect(),
        };
        let contains = |c: u8| ranges.iter().any(|&(s, e)| s <= c && c <= e);

        if contains(b'a') {
            return b'a';
        }
        for c in 0x21u8..=0x7e {
            if contains(c) {
                return c;
            }
        }
        ranges.first().map(|&(s, _)| s).unwrap_or(b'a')
    }

    /// BFS over the dense DFA, mapping its states onto parser states and
    /// emitting transitions. Bytes that share a high-fanout target are folded
    /// into the `'*'` wildcard slot the eBPF falls back to.
    fn splice(
        &mut self,
        dfa: &dense::DFA<Vec<u32>>,
        start: StateID,
        pattern: &Pattern,
        entry_actions: &HashMap<usize, (StateID, Action)>,
        explicit_actions: &HashMap<(usize, u8), Action>,
    ) -> Result<()> {
        let mut map: HashMap<usize, u16> = HashMap::new();
        map.insert(start.as_usize(), pattern.start);
        let mut seen: HashSet<usize> = HashSet::from([start.as_usize()]);
        let mut queue = vec![start];

        // A capture region whose first content byte loops back to its own state
        // (e.g. `(.*?)` or `([^ ]*)` with no preceding structure) is its own
        // body. We cannot mark "first entry" on a self loop, so we clone such
        // states into a distinct, non-capturing body state. The original state
        // becomes the entry: its content bytes carry the region's entry action
        // (`StartCapture`, or an `EndCapture` that also restarts the register)
        // and target the body.
        let mut body_of: HashMap<usize, (Action, u16)> = HashMap::new();
        for (&d0, &(tgt, action)) in entry_actions.iter() {
            if tgt.as_usize() == d0 {
                let body = self.insert_state();
                body_of.insert(d0, (action, body));
            }
        }

        while let Some(d) = queue.pop() {
            // a match state ends the pattern; its outgoing transitions only
            // exist to report longer matches and must not be followed
            if dfa.is_match_state(dfa.next_eoi_state(d)) {
                continue;
            }

            let g = map[&d.as_usize()];

            // self-loop capture start: emit a separate entry/body pair
            if let Some(&(entry_action, body)) = body_of.get(&d.as_usize()) {
                for bb in 0u16..=255 {
                    let b = bb as u8;
                    let n = dfa.next_state(d, b);
                    if dfa.is_dead_state(n) || n == d {
                        // content bytes (self loop) are folded into '*' below
                        continue;
                    }
                    let action = explicit_actions
                        .get(&(d.as_usize(), b))
                        .copied()
                        .unwrap_or(Action::None);
                    let gn = self.resolve(dfa, g, b as char, n, pattern.restart_to, &mut map);
                    self.insert_transition(g, gn, b as char, action)?;
                    self.insert_transition(body, gn, b as char, action)?;
                    if seen.insert(n.as_usize()) {
                        queue.push(n);
                    }
                }
                self.insert_transition(g, body, '*', entry_action)?;
                self.insert_transition(body, body, '*', Action::None)?;
                continue;
            }

            let dominant = Self::dominant(dfa, d);
            let cap_start = entry_actions.get(&d.as_usize()).copied();

            // the action the wildcard slot will carry, so per-byte transitions
            // that match it can be folded away
            let star_action = match (dominant, cap_start) {
                (Some(dom), Some((tgt, entry_action))) if tgt == dom => entry_action,
                _ => Action::None,
            };

            for bb in 0u16..=255 {
                let b = bb as u8;
                let n = dfa.next_state(d, b);
                if dfa.is_dead_state(n) {
                    continue;
                }

                let action = if let Some(&a) = explicit_actions.get(&(d.as_usize(), b)) {
                    a
                } else if let Some((tgt, entry_action)) = cap_start {
                    if n == tgt {
                        entry_action
                    } else {
                        Action::None
                    }
                } else {
                    Action::None
                };

                // fold into the wildcard slot if it goes to the dominant target
                // and carries the same action the wildcard slot will
                if Some(n) == dominant && action == star_action {
                    continue;
                }

                let gn = self.resolve(dfa, g, b as char, n, pattern.restart_to, &mut map);
                self.insert_transition(g, gn, b as char, action)?;
                if seen.insert(n.as_usize()) {
                    queue.push(n);
                }
            }

            if let Some(dom) = dominant {
                let gdom = if dom == d {
                    g
                } else {
                    self.resolve(dfa, g, '*', dom, pattern.restart_to, &mut map)
                };
                self.insert_transition(g, gdom, '*', star_action)?;
                if seen.insert(dom.as_usize()) {
                    queue.push(dom);
                }
            }
        }

        Ok(())
    }

    /// Maps a dense DFA target state onto a parser state, reusing an existing
    /// parser transition (prefix sharing), routing terminal matches to the
    /// restart target, or allocating a fresh state.
    fn resolve(
        &mut self,
        dfa: &dense::DFA<Vec<u32>>,
        g: u16,
        c: char,
        n: StateID,
        restart_to: Option<u16>,
        map: &mut HashMap<usize, u16>,
    ) -> u16 {
        if let Some(&gn) = map.get(&n.as_usize()) {
            return gn;
        }

        if dfa.is_match_state(dfa.next_eoi_state(n)) {
            if let Some(r) = restart_to {
                map.insert(n.as_usize(), r);
                return r;
            }
        }

        if let Some(&(to, _)) = self.transitions.get(&(g, c)) {
            map.insert(n.as_usize(), to);
            return to;
        }

        let ns = self.insert_state();
        map.insert(n.as_usize(), ns);
        ns
    }

    /// Returns the highest-fanout non-dead target of `d`, if it carries at least
    /// `WILDCARD_THRESHOLD` bytes (i.e. a capture-body-style self loop).
    fn dominant(dfa: &dense::DFA<Vec<u32>>, d: StateID) -> Option<StateID> {
        let mut counts: HashMap<usize, (StateID, usize)> = HashMap::new();
        for b in 0u16..=255 {
            let n = dfa.next_state(d, b as u8);
            if dfa.is_dead_state(n) {
                continue;
            }
            let e = counts.entry(n.as_usize()).or_insert((n, 0));
            e.1 += 1;
        }

        counts
            .values()
            .filter(|(_, c)| *c >= WILDCARD_THRESHOLD)
            .max_by_key(|(_, c)| *c)
            .map(|(s, _)| *s)
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

    /// Mirrors the eBPF `_parse_from` capture bookkeeping.
    fn run(dfa: &Dfa, input: &[u8]) -> HashMap<u8, (usize, usize)> {
        let mut cidx: HashMap<u8, usize> = HashMap::new();
        let mut ms: HashMap<u8, (usize, usize)> = HashMap::new();
        let mut s = S_INIT;

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

    fn add_header(dfa: &mut Dfa, key: &str) {
        let restart = dfa.ensure_path(S_ANY, "\r\n").unwrap();
        let regex = format!(r"(?is)\r\n{}[ \t]*:[ \t]*(.*?)\r\n", key);
        dfa.add_pattern(Pattern {
            start: S_ANY,
            regex: &regex,
            captures: &[Capture { group: 1 }],
            restart_to: Some(restart),
            done: false,
        })
        .unwrap();
    }

    #[test]
    fn captures_header_value() {
        let mut dfa = Dfa::new(vec![S_INIT, S_ANY].into_iter());
        add_header(&mut dfa, "user-agent");

        let input = b"\r\nUser-Agent: beeline\r\n\r\n";
        let ms = run(&dfa, input);
        assert_eq!(captured(input, ms[&0]), "beeline");
    }

    #[test]
    fn captures_two_headers() {
        let mut dfa = Dfa::new(vec![S_INIT, S_ANY].into_iter());
        add_header(&mut dfa, "user-agent");
        add_header(&mut dfa, "accept-language");

        let input = b"\r\nUser-Agent: beeline\r\nAccept-Language: sumsum\r\n\r\n";
        let ms = run(&dfa, input);
        assert_eq!(captured(input, ms[&0]), "beeline");
        assert_eq!(captured(input, ms[&1]), "sumsum");
    }

    #[test]
    fn header_lookup_is_case_insensitive_on_key() {
        let mut dfa = Dfa::new(vec![S_INIT, S_ANY].into_iter());
        add_header(&mut dfa, "user-agent");

        let input = b"\r\nUSER-AGENT: beeline\r\n\r\n";
        let ms = run(&dfa, input);
        assert_eq!(captured(input, ms[&0]), "beeline");
    }

    #[test]
    fn captures_request_line_method_and_uri() {
        let mut dfa = Dfa::new(vec![S_INIT, S_ANY].into_iter());
        let restart = dfa.ensure_path(S_ANY, "\r\n").unwrap();
        dfa.add_pattern(Pattern {
            start: S_INIT,
            regex: r"([^ ]*) ([^ ]*) HTTP/1\.1\r\n",
            captures: &[
                Capture { group: 1 },
                Capture { group: 2 },
            ],
            restart_to: Some(restart),
            done: false,
        })
        .unwrap();

        let input = b"POST /index.html HTTP/1.1\r\n\r\n";
        let ms = run(&dfa, input);
        assert_eq!(captured(input, ms[&0]), "POST");
        assert_eq!(captured(input, ms[&1]), "/index.html");
    }

    #[test]
    fn status_code_capture_fits_state_byte() {
        let mut dfa = Dfa::new(vec![S_INIT, S_ANY].into_iter());
        let restart = dfa.ensure_path(S_ANY, "\r\n").unwrap();
        dfa.add_pattern(Pattern {
            start: S_INIT,
            regex: r"(?is)HTTP/1\.1 (.*?)\r\n",
            captures: &[Capture { group: 1 }],
            restart_to: Some(restart),
            done: false,
        })
        .unwrap();
        add_header(&mut dfa, "user-agent");

        let input = b"HTTP/1.1 200 OK\r\nUser-Agent: beeline\r\n\r\n";
        let ms = run(&dfa, input);
        assert_eq!(captured(input, ms[&0]), "200 OK");
        assert_eq!(captured(input, ms[&1]), "beeline");

        let max = dfa.iter_states().max().copied().unwrap();
        assert!(max < 256, "state id {} exceeds eBPF byte mask", max);
    }
}
