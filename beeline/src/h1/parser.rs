#![allow(unused_imports)]
use crate::{
    autoload_and_attach,
    h1::{Action, dfa::Dfa},
    header::{METHOD, PATH, STATUS},
};
use anyhow::{Result, bail};
use http::HeaderName;
use libbpf_rs::{
    Link, MapCore, OpenObject, PrintLevel, set_print,
    skel::{OpenSkel, Skel, SkelBuilder},
};
use std::{collections::HashMap, mem::MaybeUninit};
use tracing::{Level, debug, warn};
use types::*;

const CRLF: &str = "\r\n";

pub struct Parser {
    s_init: u16,
    s_any: u16,

    dfa: Dfa,

    parse_msg_fn: Option<String>,
    parse_buf_fn: Option<String>,
    parse_skb_fn: Option<String>,
    extract_fn: Option<String>,
    matched_fn: Option<String>,
}

include!(concat!(env!("OUT_DIR"), "/h1/parser.skel.rs"));

fn new_transition(state: u16, action: Action, rodata: &rodata) -> trans {
    let action = match action {
        Action::StartCapture(mid) => rodata.a_start_capture | (mid as u16) & rodata.a_id_mask,
        Action::EndCapture(cid, mid) => {
            let id = (cid as u16) << 6 | (mid as u16);
            rodata.a_end_capture | id & rodata.a_id_mask
        }
        Action::Done => rodata.a_done,
        Action::None => 0,
    };

    trans { state, action }
}

#[allow(dead_code)]
impl Parser {
    /// Creates a new HTTP/1.1 parser.
    ///
    /// Additional configuration must be done through the builder methods before calling `attach`.
    pub fn new() -> Parser {
        let states = vec![0, 1];

        Parser {
            s_init: 0,
            s_any: 1,
            dfa: Dfa::new(states.into_iter()),
            parse_msg_fn: None,
            parse_buf_fn: None,
            parse_skb_fn: None,
            extract_fn: None,
            matched_fn: None,
        }
    }

    /// Specifies the function template in the target program to be replaced with an HTTP/1.1
    /// parser. The function will not be replaced until `attach` is called.
    ///
    /// # Arguments
    ///
    /// * `parse_fn` - The name of the function to replace in the target program
    pub fn replace_parse_msg<S: ToString>(mut self, parse_fn: S) -> Parser {
        self.parse_msg_fn = Some(parse_fn.to_string());
        self
    }

    pub fn replace_parse_skb<S: ToString>(mut self, parse_fn: S) -> Parser {
        self.parse_skb_fn = Some(parse_fn.to_string());
        self
    }

    pub fn replace_parse_buf<S: ToString>(mut self, parse_fn: S) -> Parser {
        self.parse_buf_fn = Some(parse_fn.to_string());
        self
    }

    /// Specifies the function template in the target program to be called when a pattern match
    /// is completed. The function will not be replaced until `attach` is called.
    ///
    /// # Arguments
    ///
    /// * `matched_fn` - The name of the matched callback function in the target program
    pub fn replace_matched<S: ToString>(mut self, matched_fn: S) -> Parser {
        self.matched_fn = Some(matched_fn.to_string());
        self
    }

    /// Specifies the function template in the target program to be called when extracting
    /// matched content. The function will not be replaced until `attach` is called.
    ///
    /// # Arguments
    ///
    /// * `extract_fn` - The name of the extract callback function in the target program
    pub fn replace_extract<S: ToString>(mut self, extract_fn: S) -> Parser {
        self.extract_fn = Some(extract_fn.to_string());
        self
    }

    /// Configures the parser to capture an HTTP/2 header field value.
    ///
    /// # Arguments
    ///
    /// * `name` - The HTTP/2 header name to capture
    ///
    /// # Errors
    ///
    /// Returns an error if the pattern configuration fails.
    pub fn capture_hdr(mut self, name: &HeaderName) -> Result<Parser> {
        if name == &METHOD || name == &PATH {
            return self.capture_status_line_hdr(name);
        } else if name == &STATUS {
            return self.capture_status_code();
        }

        self.dfa
            .start_pattern(self.s_any)
            .push(CRLF)?
            .push(name.as_str())?
            .push_optional('\t')?
            .push_optional(' ')?
            .push(":")?
            .push_optional('\t')?
            .push_optional(' ')?
            .start_capturing()
            .push_optional('*')?
            .end_caputuring_and_restart_with(CRLF, self.s_any)?;

        Ok(self)
    }

    /// Configures the parser to match an HTTP/2 preface in an HTTP/1.1 connection.
    ///
    /// This method sets up pattern matching for the HTTP/2 connection preface
    /// (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`), which is used to upgrade from HTTP/1.1 to HTTP/2.
    ///
    /// # Errors
    ///
    /// Returns an error if the pattern configuration fails.
    pub fn match_h2_preface(mut self) -> Result<Parser> {
        self.dfa
            .start_pattern(self.s_init)
            .start_capturing()
            .push("PRI * HTTP/2.0")?
            .push(CRLF)?
            .push(CRLF)?
            .end_capturing("SM")?
            .push(CRLF)?
            .done_on(CRLF)?;

        Ok(self)
    }

    fn done_on_hdr_end(mut self) -> Result<Parser> {
        self.dfa
            .start_pattern(self.s_any)
            .push(CRLF)?
            .done_on(CRLF)?;

        Ok(self)
    }

    /// Configures the parser to match and capture HTTP request status line components.
    fn capture_status_line_hdr(mut self, name: &HeaderName) -> Result<Parser> {
        if name == &METHOD {
            self.dfa
                .start_pattern(self.s_init)
                .start_capturing()
                .push_optional('*')?
                .end_capturing(" ")?
                .push_optional('*')?
                .push(" HTTP/1.1")?;
        } else if name == &STATUS {
            self.dfa
                .start_pattern(self.s_init)
                .push_optional('*')?
                .push(" ")?
                .start_capturing()
                .push_optional('*')?
                .push(" HTTP/1.1")?
                .end_caputuring_and_restart_with(CRLF, self.s_any)?;
        }

        Ok(self)
    }

    /// Configures the parser to match and capture HTTP response status code.
    fn capture_status_code(mut self) -> Result<Parser> {
        self.dfa
            .start_pattern(self.s_init)
            .start_capturing()
            .push_optional('*')?
            .end_capturing(" ")?
            .start_capturing()
            .push_optional('*')?
            .push(" HTTP/1.1")?
            .end_caputuring_and_restart_with(CRLF, self.s_any)?;

        Ok(self)
    }

    /// Configures the parser to match and capture the HTTP response status code.
    ///
    /// This method captures the status code from an HTTP response status line.
    /// It expects the format: `HTTP/1.1 STATUS_CODE\r\n`.
    ///
    /// # Errors
    ///
    /// Returns an error if the pattern configuration fails.
    // pub fn capture_status_code(mut self) -> Result<Parser> {
    //     self.dfa
    //         .start_pattern(self.s_init)
    //         .push("HTTP/1.1 ")?
    //         .start_capturing()
    //         .push_optional('*')?
    //         .end_caputuring_and_restart_with(CRLF, self.s_any)?;

    //     Ok(self)
    // }

    /// Returns an iterator over all states in the parser's DFA.
    ///
    /// # Returns
    ///
    /// An iterator yielding references to state identifiers.
    pub fn iter_states<'a>(&'a self) -> impl Iterator<Item = &'a u16> {
        self.dfa.iter_states()
    }

    /// Returns an iterator over all transitions in the parser's DFA.
    ///
    /// # Returns
    ///
    /// An iterator yielding tuples of (from_state, to_state, input_char, action).
    pub fn iter_transitions<'a>(
        &'a self,
    ) -> impl Iterator<Item = (&'a u16, &'a u16, &'a char, &'a Action)> {
        self.dfa.iter_transitions()
    }

    /// Attaches the configured parser to the target program.
    ///
    /// # Arguments
    ///
    /// * `target` - The file descriptor of the target program to attach to
    ///
    /// # Returns
    ///
    /// A tuple of optional Links for (parse, matched, extract) functions. Each Link is
    /// `Some` if the corresponding function was configured via `replace_*` methods,
    /// or `None` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if attachment to the target program fails.
    pub fn attach<'obj>(self, target: i32) -> Result<AttachedParser> {
        set_print(Some((PrintLevel::Debug, crate::print)));

        let parser = self.done_on_hdr_end()?;

        let skel_builder = ParserSkelBuilder::default();
        let mut open_obj: MaybeUninit<OpenObject> = MaybeUninit::uninit();
        let mut open_skel = skel_builder.open(&mut open_obj)?;
        if tracing::event_enabled!(Level::TRACE) {
            open_skel.progs.parse_msg.set_log_level(1);
            open_skel.progs.parse_buf.set_log_level(1);
            open_skel.progs.parse_buf.set_log_level(1);
        }

        let progs = vec![
            (&mut open_skel.progs.parse_msg, parser.parse_msg_fn.clone()),
            (&mut open_skel.progs.parse_skb, parser.parse_skb_fn.clone()),
            (&mut open_skel.progs.parse_buf, parser.parse_buf_fn.clone()),
            (&mut open_skel.progs.matched, parser.matched_fn.clone()),
            (
                &mut open_skel.progs.extract_match,
                parser.extract_fn.clone(),
            ),
        ];

        for (prog, func) in progs {
            autoload_and_attach(prog, target, func)?;
        }

        parser.inject(&mut open_skel)?;

        let skel = open_skel.load()?;
        bpf_tracing::try_init(skel.object())?;

        let mut links = Vec::new();
        if parser.parse_msg_fn.is_some() {
            links.push(skel.progs.parse_msg.attach()?);
        }
        if parser.parse_skb_fn.is_some() {
            links.push(skel.progs.parse_skb.attach()?);
        }
        if parser.parse_buf_fn.is_some() {
            links.push(skel.progs.parse_buf.attach()?);
        }

        if parser.matched_fn.is_some() {
            links.push(skel.progs.matched.attach()?);
        }

        if parser.extract_fn.is_some() {
            links.push(skel.progs.extract_match.attach()?);
        }

        debug!("Beeline http/1 attached");

        anyhow::Ok(AttachedParser { links })
    }

    fn inject(&self, skel: &mut OpenParserSkel) -> Result<()> {
        for (from, to, input, action) in self.iter_transitions() {
            let s = *from as usize;
            let data = skel.maps.rodata_data.as_mut().unwrap();
            let t = new_transition(*to, *action, data);
            data.s2ts[s][*input as usize] = t;
        }

        Ok(())
    }
}

pub struct AttachedParser {
    #[allow(dead_code)]
    links: Vec<Link>,
}
