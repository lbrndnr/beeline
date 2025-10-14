use crate::h2::{
    create_header_maps,
    dfa::{Action, Dfa},
    huffman,
};
use anyhow::{Result, bail};
use as_bytes::AsBytes;
use bytes::BytesMut;
use libbpf_rs::{
    Link, MapCore, MapFlags, MapHandle, OpenObject, PrintLevel, set_print,
    skel::{OpenSkel, SkelBuilder},
};
use log::{debug, info, log_enabled, warn};
use std::mem::MaybeUninit;
use types::*;

pub struct Parser {
    s_init: u16,
    s_any: u16,

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
    pub fn new() -> Parser {
        let states = vec![0, 1];

        Parser {
            s_init: 0,
            s_any: 1,
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

        let mut key_encoded = BytesMut::with_capacity(key.len());
        huffman::encode(key.as_bytes(), &mut key_encoded);

        self.dfa
            .start_pattern(self.s_any)
            .push(&key_encoded)?
            .capture_field_value();

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

    fn populate_static_table(&self, static_table: &MapHandle) -> Result<()> {
        let (st_keys, st_hfs) = create_header_maps();

        for (key, vals) in st_hfs.iter() {
            for (val, idx) in vals.iter() {
                let mut hf = BytesMut::with_capacity(key.len() + val.len());
                huffman::encode(key.as_bytes(), &mut hf);
                huffman::encode(val.as_bytes(), &mut hf);

                let mut hf = hf.to_vec();
                if hf.len() > 64 {
                    bail!("Header field too long.");
                }
                hf.resize(64, 0);

                let idx = *idx as u32;
                let idx = unsafe { idx.as_bytes() };

                static_table.update(&idx, &hf, MapFlags::ANY)?;
            }
        }

        Ok(())
    }

    pub fn attach<'obj>(&self, target: i32) -> Result<(Link, Link, Link)> {
        set_print(Some((PrintLevel::Debug, print)));

        let skel_builder = BeelineSkelBuilder::default();
        let mut open_obj: MaybeUninit<OpenObject> = MaybeUninit::uninit();
        let mut open_skel = skel_builder.open(&mut open_obj)?;
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

        let skel = open_skel.load()?;
        let h1 = skel.progs.parse_h1.attach()?;
        let h2 = skel.progs.parse_h2.attach()?;
        let ms = skel.progs.extract_match.attach()?;

        let id = skel.maps.static_table.info()?.info.id;
        let static_table = MapHandle::from_map_id(id)?;
        self.populate_static_table(&static_table)?;

        debug!("Beeline http/2 attached");

        anyhow::Ok((h1, h2, ms))
    }
}
