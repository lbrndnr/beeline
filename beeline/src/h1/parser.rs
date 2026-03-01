use crate::h1::{Action, dfa::Dfa};
use anyhow::{Result, bail};
use libbpf_rs::{
    Link, MapCore, OpenObject, PrintLevel, set_print,
    skel::{OpenSkel, SkelBuilder},
};
use log::{debug, log_enabled, warn};
use std::mem::MaybeUninit;
use types::*;

const CRLF: &str = "\r\n";

#[derive(Debug, Clone)]
enum ParseFn {
    Buf(String),
    Msg(String),
}

impl ToString for ParseFn {
    fn to_string(&self) -> String {
        match self {
            ParseFn::Buf(name) => name.clone(),
            ParseFn::Msg(name) => name.clone(),
        }
    }
}

pub struct Parser {
    s_init: u16,
    s_any: u16,

    dfa: Dfa,

    parse_fn: Option<ParseFn>,
    extract_fn: Option<String>,
    matched_fn: Option<String>,
    parse_h1_egress: Option<String>,
    extract_h1_egress: Option<String>,
}

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/h1/parser.skel.rs"
));

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
            parse_fn: None,
            extract_fn: None,
            matched_fn: None,
            extract_h1_egress: None,
            parse_h1_egress: None,
        }
    }

    /// Specifies the function template in the target program to be replaced with an HTTP/1.1
    /// parser. The function will not be replaced until `attach` is called.
    ///
    /// # Arguments
    ///
    /// * `parse_fn` - The name of the function to replace in the target program
    pub fn replace_parse_msg<S: ToString>(mut self, parse_fn: S) -> Parser {
        self.parse_fn = Some(ParseFn::Msg(parse_fn.to_string()));
        self
    }

    pub fn replace_parse_buf<S: ToString>(mut self, parse_fn: S) -> Parser {
        self.parse_fn = Some(ParseFn::Buf(parse_fn.to_string()));
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

    pub fn replace_h1_extract_egress<S: ToString>(mut self, extract_fn: S) -> Parser {
        self.extract_h1_egress = Some(extract_fn.to_string());
        self
    }

    pub fn replace_parse_h1_egress<S: ToString>(mut self, parse_fn: S) -> Parser {
        self.parse_h1_egress = Some(parse_fn.to_string());
        self
    }

    /// Configures the parser to match an HTTP/2 preface in an HTTP/1.1 connection.
    ///
    /// This method sets up pattern matching for the HTTP/2 connection preface
    /// (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`), which is used to upgrade from HTTP/1.1 to HTTP/2.
    ///
    /// # Errors
    ///
    /// Returns an error if the pattern configuration fails.
    pub fn match_preface(mut self) -> Result<Parser> {
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

    fn done_on_http_hdr_end(mut self) -> Result<Parser> {
        self.dfa
            .start_pattern(self.s_any)
            .push(CRLF)?
            .done_on(CRLF)?;

        Ok(self)
    }

    /// Configures the parser to match and capture HTTP request status line components.
    ///
    /// This method captures the HTTP method and request URI from the request status line.
    /// It expects the format: `METHOD URI HTTP/1.1\r\n`.
    ///
    /// # Errors
    ///
    /// Returns an error if the pattern configuration fails.
    pub fn match_http_req_status_line(mut self) -> Result<Parser> {
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
    pub fn match_http_status_code(mut self) -> Result<Parser> {
        self.dfa
            .start_pattern(self.s_init)
            .push("HTTP/1.1 ")?
            .start_capturing()
            .push_optional('*')?
            .end_caputuring_and_restart_with(CRLF, self.s_any)?;

        Ok(self)
    }

    /// Configures the parser to match and capture a specific HTTP header value.
    ///
    /// # Arguments
    ///
    /// * `key` - The HTTP header name to match (case-insensitive)
    ///
    /// # Errors
    ///
    /// Returns an error if the pattern configuration fails.
    pub fn match_http_hdr(mut self, key: &str) -> Result<Parser> {
        self.dfa
            .start_pattern(self.s_any)
            .push(CRLF)?
            .push(key)?
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
    pub fn attach_ingress_egress<'obj>(
        self,
        target_ingress: i32,
        target_egress: Option<(i32, i32)>,
    ) -> Result<(
        Option<Link>,
        Option<Link>,
        Option<Link>,
        Option<Link>,
        Option<Link>,
        Option<Link>,
        Option<Link>,
    )> {
        set_print(Some((PrintLevel::Debug, crate::print)));

        let parser = self.done_on_http_hdr_end()?;

        let skel_builder = ParserSkelBuilder::default();
        let mut open_obj: MaybeUninit<OpenObject> = MaybeUninit::uninit();
        let mut open_skel = skel_builder.open(&mut open_obj)?;
        if log_enabled!(log::Level::Debug) {
            open_skel.progs.parse_msg.set_log_level(1);
            open_skel.progs.parse_buf.set_log_level(1);
        }

        match &parser.parse_fn {
            &Some(ParseFn::Msg(ref name)) => {
                open_skel.progs.parse_msg.set_autoload(true);
                open_skel.progs.parse_buf.set_autoload(false);
                open_skel
                    .progs
                    .parse_msg
                    .set_attach_target(target_ingress, Some(name.clone()))?;
            }
            &Some(ParseFn::Buf(ref name)) => {
                open_skel.progs.parse_msg.set_autoload(false);
                open_skel.progs.parse_buf.set_autoload(true);
                open_skel
                    .progs
                    .parse_buf
                    .set_attach_target(target_ingress, Some(name.clone()))?;
            }
            None => bail!("No parse function specified"),
        }

        open_skel
            .progs
            .matched
            .set_autoload(parser.matched_fn.is_some());
        open_skel
            .progs
            .matched
            .set_attach_target(target_ingress, parser.matched_fn.clone())?;

        open_skel
            .progs
            .extract_match
            .set_autoload(parser.extract_fn.is_some());
        open_skel
            .progs
            .extract_match
            .set_attach_target(target_ingress, parser.extract_fn.clone())?;

        open_skel
            .progs
            .replaceable_extract_h1_match_egress_stream_parser
            .set_autoload(parser.parse_h1_egress.is_some());
        open_skel
            .progs
            .replaceable_parse_h1_egress_stream_parser
            .set_autoload(parser.extract_h1_egress.is_some());

        open_skel
            .progs
            .replaceable_extract_h1_match_egress_stream_verdict
            .set_autoload(parser.parse_h1_egress.is_some());
        open_skel
            .progs
            .replaceable_parse_h1_egress_stream_verdict
            .set_autoload(parser.extract_h1_egress.is_some());

        if let Some((stream_verdict_egress_fd, stream_parser_egress_fd)) = target_egress {
            open_skel
                .progs
                .replaceable_parse_h1_egress_stream_parser
                .set_attach_target(stream_parser_egress_fd, parser.parse_h1_egress.clone())?;

            open_skel
                .progs
                .replaceable_extract_h1_match_egress_stream_parser
                .set_attach_target(stream_parser_egress_fd, parser.extract_h1_egress.clone())?;

            open_skel
                .progs
                .replaceable_parse_h1_egress_stream_verdict
                .set_attach_target(stream_verdict_egress_fd, parser.parse_h1_egress.clone())?;

            open_skel
                .progs
                .replaceable_extract_h1_match_egress_stream_verdict
                .set_attach_target(stream_verdict_egress_fd, parser.extract_h1_egress.clone())?;
        }

        parser.inject(&mut open_skel)?;

        let skel = open_skel.load()?;

        let parse = match &parser.parse_fn {
            &Some(ParseFn::Msg(_)) => Some(skel.progs.parse_msg.attach()?),
            &Some(ParseFn::Buf(_)) => Some(skel.progs.parse_buf.attach()?),
            None => bail!("No parse function specified"),
        };
        let matched = if parser.matched_fn.is_some() {
            Some(skel.progs.matched.attach()?)
        } else {
            None
        };
        let extract = if parser.extract_fn.is_some() {
            Some(skel.progs.extract_match.attach()?)
        } else {
            None
        };

        let parse_h1_egress_stream_parser = if parser.parse_h1_egress.is_some() {
            Some(skel.progs.replaceable_parse_h1_egress_stream_parser.attach()?)
        } else {
            None
        };

        let extract_h1_egress_stream_parser = if parser.extract_h1_egress.is_some() {
            Some(skel.progs.replaceable_extract_h1_match_egress_stream_parser.attach()?)
        } else {
            None
        };

        let parse_h1_egress_stream_verdict = if parser.parse_h1_egress.is_some() {
            Some(skel.progs.replaceable_parse_h1_egress_stream_verdict.attach()?)
        } else {
            None
        };

        let extract_h1_egress_stream_verdict = if parser.extract_h1_egress.is_some() {
            Some(skel.progs.replaceable_extract_h1_match_egress_stream_verdict.attach()?)
        } else {
            None
        };

        debug!("Beeline http/1 attached");

        anyhow::Ok((parse, matched, extract, parse_h1_egress_stream_parser, extract_h1_egress_stream_parser, parse_h1_egress_stream_verdict, extract_h1_egress_stream_verdict))
    }

    pub fn attach<'obj>(
        self,
        target: i32,
    ) -> Result<(
        Option<Link>,
        Option<Link>,
        Option<Link>,
        Option<Link>,
        Option<Link>,
        Option<Link>,
        Option<Link>,
    )> {
        return self.attach_ingress_egress(target, None);
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
