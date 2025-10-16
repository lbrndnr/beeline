use crate::h1::{Action, dfa::Dfa};
use anyhow::Result;
use libbpf_rs::{
    Link, MapCore, OpenObject, PrintLevel, set_print,
    skel::{OpenSkel, SkelBuilder},
};
use log::{debug, info, log_enabled, warn};
use std::mem::MaybeUninit;
use types::*;

const CRLF: &str = "\r\n";

pub struct Parser {
    s_init: u16,
    s_any: u16,

    dfa: Dfa,
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

fn print(level: PrintLevel, msg: String) {
    let msg = msg.trim_start_matches("libbpf:").trim();

    match level {
        PrintLevel::Debug => debug!(target: "libbpf", "{}", msg),
        PrintLevel::Info => info!(target: "libbpf", "{}", msg),
        PrintLevel::Warn => warn!(target: "libbpf", "{}", msg),
    }
}

#[allow(dead_code)]
impl Parser {
    pub fn new() -> Parser {
        let states = vec![0, 1];

        Parser {
            s_init: 0,
            s_any: 1,
            dfa: Dfa::new(states.into_iter()),
        }
    }

    pub fn match_preface(&mut self) -> Result<()> {
        self.dfa
            .start_pattern(self.s_init)
            .start_capturing()
            .push("PRI * HTTP/2.0")?
            .push(CRLF)?
            .push(CRLF)?
            .end_capturing("SM")?
            .push(CRLF)?
            .done_on(CRLF)?;

        Ok(())
    }

    pub fn done_on_http_hdr_end(&mut self) -> Result<()> {
        self.dfa
            .start_pattern(self.s_any)
            .push(CRLF)?
            .done_on(CRLF)?;

        Ok(())
    }

    pub fn match_http_req_status_line(&mut self) -> Result<()> {
        self.dfa
            .start_pattern(self.s_init)
            .start_capturing()
            .push_optional('*')?
            .end_capturing(" ")?
            .start_capturing()
            .push_optional('*')?
            .push(" HTTP/1.1")?
            .end_caputuring_and_restart_with(CRLF, self.s_any)?;

        Ok(())
    }

    pub fn match_http_status_code(&mut self) -> Result<()> {
        self.dfa
            .start_pattern(self.s_init)
            .push("HTTP/1.1 ")?
            .start_capturing()
            .push_optional('*')?
            .end_caputuring_and_restart_with(CRLF, self.s_any)?;

        Ok(())
    }

    pub fn match_http_hdr(&mut self, key: &str) -> Result<()> {
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

        Ok(())
    }

    pub fn iter_states<'a>(&'a self) -> impl Iterator<Item = &'a u16> {
        self.dfa.iter_states()
    }

    pub fn iter_transitions<'a>(
        &'a self,
    ) -> impl Iterator<Item = (&'a u16, &'a u16, &'a char, &'a Action)> {
        self.dfa.iter_transitions()
    }

    pub fn attach<'obj>(&self, target: i32) -> Result<(Link, Link)> {
        set_print(Some((PrintLevel::Debug, print)));

        let skel_builder = ParserSkelBuilder::default();
        let mut open_obj: MaybeUninit<OpenObject> = MaybeUninit::uninit();
        let mut open_skel = skel_builder.open(&mut open_obj)?;
        if log_enabled!(log::Level::Debug) {
            open_skel.progs.parse_h1.set_log_level(1);
        }

        open_skel
            .progs
            .parse_h1
            .set_attach_target(target, Some("parse_h1".to_string()))?;

        open_skel
            .progs
            .extract_match
            .set_attach_target(target, Some("extract_match".to_string()))?;

        self.inject(&mut open_skel)?;

        let skel = open_skel.load()?;
        let h1 = skel.progs.parse_h1.attach()?;
        let ms = skel.progs.extract_match.attach()?;

        debug!("Beeline http/1 attached");

        anyhow::Ok((h1, ms))
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
