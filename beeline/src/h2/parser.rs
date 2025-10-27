use crate::h2::{Action, create_header_maps, dfa::Dfa};
use anyhow::Result;
use as_bytes::AsBytes;
use httlib_huffman as huffman;
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

    parse_fn: Option<String>,
    extract_fn: Option<String>,
    matched_fn: Option<String>,
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
            parse_fn: None,
            extract_fn: None,
            matched_fn: None,
        }
    }

    pub fn replace_parse<S: ToString>(mut self, parse_fn: S) -> Parser {
        self.parse_fn = Some(parse_fn.to_string());
        self
    }

    pub fn replace_matched<S: ToString>(mut self, matched_fn: S) -> Parser {
        self.matched_fn = Some(matched_fn.to_string());
        self
    }

    pub fn replace_extract<S: ToString>(mut self, extract_fn: S) -> Parser {
        self.extract_fn = Some(extract_fn.to_string());
        self
    }

    pub fn capture_http_hdr(mut self, key: &str) -> Result<Parser> {
        let mut key_encoded = Vec::new();
        huffman::encode(key.as_bytes(), &mut key_encoded)?;

        self.dfa
            .start_pattern(self.s_any)
            .push(&key_encoded)?
            .capture_field_value();

        Ok(self)
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
            let mut hf_key = Vec::new();
            huffman::encode(key.as_bytes(), &mut hf_key)?;

            let mut hf_val = Vec::new();
            if let Some(val) = val {
                huffman::encode(val.as_bytes(), &mut hf_val)?;
            }

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

    pub fn attach<'obj>(self, target: i32) -> Result<(Option<Link>, Option<Link>, Option<Link>)> {
        set_print(Some((PrintLevel::Debug, print)));

        let skel_builder = ParserSkelBuilder::default();
        let mut open_obj: MaybeUninit<OpenObject> = MaybeUninit::uninit();
        let mut open_skel = skel_builder.open(&mut open_obj)?;
        if log_enabled!(log::Level::Debug) {
            open_skel.progs.parse.set_log_level(1);
        }

        open_skel.progs.parse.set_autoload(self.parse_fn.is_some());
        open_skel
            .progs
            .parse
            .set_autoattach(self.parse_fn.is_some());
        open_skel
            .progs
            .parse
            .set_attach_target(target, self.parse_fn.clone())?;

        open_skel
            .progs
            .matched
            .set_autoload(self.matched_fn.is_some());
        open_skel
            .progs
            .matched
            .set_autoattach(self.matched_fn.is_some());
        open_skel
            .progs
            .matched
            .set_attach_target(target, self.matched_fn.clone())?;

        open_skel
            .progs
            .extract_match
            .set_autoload(self.extract_fn.is_some());
        open_skel
            .progs
            .extract_match
            .set_autoattach(self.extract_fn.is_some());
        open_skel
            .progs
            .extract_match
            .set_attach_target(target, self.extract_fn.clone())?;

        self.inject(&mut open_skel)?;

        let skel = open_skel.load()?;
        let parse = if self.parse_fn.is_some() {
            Some(skel.progs.parse.attach()?)
        } else {
            None
        };
        let matched = if self.matched_fn.is_some() {
            Some(skel.progs.matched.attach()?)
        } else {
            None
        };
        let extract = if self.extract_fn.is_some() {
            Some(skel.progs.extract_match.attach()?)
        } else {
            None
        };

        let id = skel.maps.static_table.info()?.info.id;
        let static_table = MapHandle::from_map_id(id)?;
        self.populate_static_table(&static_table)?;

        debug!("Beeline http/2 attached");

        anyhow::Ok((parse, matched, extract))
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
