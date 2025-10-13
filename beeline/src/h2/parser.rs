use crate::h2::dfa::{Action, Dfa};
use anyhow::Result;
use as_bytes::AsBytes;
use libbpf_rs::{
    Link, MapCore, MapFlags, MapHandle, PrintLevel, set_print,
    skel::{OpenSkel, SkelBuilder},
};
use log::{debug, info, log_enabled, warn};
use std::mem::MaybeUninit;
use types::*;

const CRLF: &str = "\r\n";

pub struct Parser {
    pub s_init: u16,
    pub s_any: u16,

    dfa: Dfa,
}

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/beeline.skel.rs"));

fn new_transition(state: u16, action: Action, rodata: &rodata) -> trans {
    let action = match action {
        Action::CaptureFieldValue(cid) => rodata.a_start_capture | (cid as u16) & rodata.a_id_mask,
        // Action::EndCapturing(rid) => rodata.a_end_capture | (rid as u16) & rodata.a_id_mask,
        Action::Done => rodata.a_done,
        Action::None => 0,
    };

    trans { state, action }
}

fn inject_parser(parser: &Parser, skel: &mut OpenBeelineSkel) -> Result<()> {
    for (from, to, input, action) in parser.iter_transitions() {
        let s = *from as usize;
        let data = skel.maps.rodata_data.as_mut().unwrap();
        let t = new_transition(*to, *action, data);
        println!(
            "Transition from state {} to state {} on input {} with action {:?}",
            from, to, input, action
        );
        data.s2ts[s][*input as usize] = t;
    }

    Ok(())
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
    pub fn new(s_init: u16, s_any: u16) -> Parser {
        let states = vec![s_init, s_any];

        Parser {
            s_init,
            s_any,
            dfa: Dfa::new(states.into_iter()),
        }
    }

    // pub fn match_preface(&mut self) -> Result<()> {
    //     self.dfa
    //         .start_pattern(self.s_init)
    //         .start_capturing()
    //         .push("PRI * HTTP/2.0")?
    //         .push(CRLF)?
    //         .push(CRLF)?
    //         .end_capturing("SM")?
    //         .push(CRLF)?
    //         .done_on(CRLF)?;

    //     Ok(())
    // }

    pub fn match_http_hdr(&mut self, key: &str) -> Result<()> {
        // if let Some(idx) = st.get(key) {
        // let mut idx_encoded = hpack::encoder::encode_integer(*idx, 6);

        // println!("Header index: {:?}", idx_encoded);

        // idx_encoded[0] |= 64;

        // println!("Header index: {:?}", idx_encoded);

        let key_encoded = b"\xa4\xa9\x9c\xf2\x7f";

        self.dfa
            .start_pattern(self.s_any)
            .push(key_encoded)?
            .capture_field_value();
        // .push_optional('*')?
        // .end_caputuring_and_restart_with("a", self.s_any)?;
        // }

        // self.dfa
        //     .start_pattern(self.s_any)
        //     .push(CRLF)?
        //     .push(key)?
        //     .push_optional('\t')?
        //     .push_optional(' ')?
        //     .push(":")?
        //     .push_optional('\t')?
        //     .push_optional(' ')?
        //     .start_capturing()
        //     .push_optional('*')?
        //     .end_caputuring_and_restart_with(CRLF, self.s_any)?;

        Ok(())
    }

    pub fn iter_states<'a>(&'a self) -> impl Iterator<Item = &'a u16> {
        self.dfa.iter_states()
    }

    pub fn iter_transitions<'a>(
        &'a self,
    ) -> impl Iterator<Item = (&'a u16, &'a u16, &'a u8, &'a Action)> {
        self.dfa.iter_transitions()
    }

    pub fn attach<'obj>(
        &self,
        target: i32,
        open_obj: &'obj mut MaybeUninit<libbpf_rs::OpenObject>,
    ) -> Result<(Link, Link, Link)> {
        set_print(Some((PrintLevel::Debug, print)));

        let skel_builder = BeelineSkelBuilder::default();
        // let mut open_obj: MaybeUninit<OpenObject> = MaybeUninit::uninit();
        let mut open_skel = skel_builder.open(open_obj)?;
        if log_enabled!(log::Level::Debug) {
            open_skel.progs.parse_h2.set_log_level(1);
        }

        open_skel
            .progs
            .parse_h2
            .set_attach_target(target, Some("parse_h2".to_string()))?;

        open_skel
            .progs
            .parse_h1
            .set_attach_target(target, Some("parse_h1".to_string()))?;

        open_skel
            .progs
            .extract_match
            .set_attach_target(target, Some("extract_match".to_string()))?;

        inject_parser(self, &mut open_skel)?;

        debug!("Loading");
        let skel = open_skel.load()?;
        debug!("Loading done");
        let h1 = skel.progs.parse_h1.attach()?;
        let h2 = skel.progs.parse_h2.attach()?;
        let ms = skel.progs.extract_match.attach()?;

        let id = skel.maps.static_table.info()?.info.id;
        let static_table = MapHandle::from_map_id(id)?;
        let key = unsafe { 2.as_bytes() };

        let mut val = vec![0u8; 64];
        val[0] = 0xa4;
        val[1] = 0xa9;
        val[2] = 0x9c;
        val[3] = 0xf2;
        val[4] = 0x7f;
        val[5] = 0xc5;
        val[6] = 0x83;
        val[7] = 0x7f;

        static_table.update(&key, &val, MapFlags::ANY)?;

        debug!("Beeline http/2 attached");

        anyhow::Ok((h1, h2, ms))
    }
}
