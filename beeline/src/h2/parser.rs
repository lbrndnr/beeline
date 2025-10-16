use crate::h2::{Action, create_header_maps, dfa::Dfa, huffman};
use anyhow::Result;
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

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/h2/parser.skel.rs"
));

fn new_transition(state: u16, action: Action, rodata: &rodata) -> trans {
    let action = match action {
        Action::CaptureFieldValue(cid) => rodata.a_start_capture | (cid as u16) & rodata.a_id_mask,
        // Action::EndCapturing(rid) => rodata.a_end_capture | (rid as u16) & rodata.a_id_mask,
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
        let mut key_encoded = BytesMut::with_capacity(key.len());
        huffman::encode(key.as_bytes(), &mut key_encoded);

        self.dfa
            .start_pattern(self.s_any)
            .push(&key_encoded)?
            .capture_field_value();

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
        let insert = |idx: u32, key: &str, val: Option<&str>| {
            let mut hf_key = BytesMut::with_capacity(key.len());
            huffman::encode(key.as_bytes(), &mut hf_key);

            let val_len = val.map(|v| v.len()).unwrap_or(0);
            let mut hf_val = BytesMut::with_capacity(val_len);
            if let Some(val) = val {
                huffman::encode(val.as_bytes(), &mut hf_val);
            }

            let mut hf_key = hf_key.to_vec();
            let mut hf_val = hf_val.to_vec();

            hf_key.resize(32, 0);
            hf_val.resize(32, 0);

            let hf = header_field {
                key: hf_key.try_into().unwrap(),
                val: hf_val.try_into().unwrap(),
            };

            let idx = unsafe { idx.as_bytes() };
            let hf = unsafe { hf.as_bytes() };

            static_table.update(&idx, &hf, MapFlags::ANY)?;

            anyhow::Ok(())
        };

        let (st_keys, st_hfs) = create_header_maps();
        for (key, vals) in st_hfs.iter() {
            for (val, idx) in vals.iter() {
                insert(*idx as u32, key, Some(val))?;
            }
        }

        for (key, idx) in st_keys.iter() {
            insert(*idx as u32, key, None)?;
        }

        static_table.freeze()?;

        Ok(())
    }

    pub fn attach<'obj>(&self, target: i32) -> Result<(Link, Link)> {
        set_print(Some((PrintLevel::Debug, print)));

        let skel_builder = ParserSkelBuilder::default();
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
            .extract_match
            .set_attach_target(target, Some("extract_match".to_string()))?;

        self.inject(&mut open_skel)?;

        let skel = open_skel.load()?;
        let h2 = skel.progs.parse_h2.attach()?;
        let ms = skel.progs.extract_match.attach()?;

        let id = skel.maps.static_table.info()?.info.id;
        let static_table = MapHandle::from_map_id(id)?;
        self.populate_static_table(&static_table)?;

        debug!("Beeline http/2 attached");

        anyhow::Ok((h2, ms))
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
