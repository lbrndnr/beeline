#![allow(unused_imports)]
use crate::{
    autoload_and_attach,
    h2::{Action, create_header_maps, dfa::Dfa},
};
use anyhow::{Result, bail};
use as_bytes::AsBytes;
use httlib_huffman as huffman;
use http::HeaderName;
use libbpf_rs::{
    Link, MapCore, MapFlags, MapHandle, OpenObject, PrintLevel, set_print,
    skel::{OpenSkel, Skel, SkelBuilder},
};
use plain::Plain;
use std::mem::MaybeUninit;
use std::net::SocketAddr;
use tracing::{Level, debug, warn};
use types::*;
pub use types::{ip4_addr, ip4_conn};

extern crate plain;

pub struct Parser {
    s_any: u16,

    dfa: Dfa,

    parse_msg_fn: Option<String>,
    parse_buf_fn: Option<String>,
    parse_skb_fn: Option<String>,
    extract_fn: Option<String>,
    matched_fn: Option<String>,
}

include!(concat!(env!("OUT_DIR"), "/h2/parser.skel.rs"));

fn new_transition(state: u16, action: Action, rodata: &rodata) -> trans {
    let action = match action {
        Action::CaptureFieldValue(cid) => rodata.a_start_capture | (cid as u16) & rodata.a_id_mask,
        // Action::EndCapturing(rid) => rodata.a_end_capture | (rid as u16) & rodata.a_id_mask,
        Action::Done => rodata.a_done,
        Action::None => 0,
    };

    trans { state, action }
}

#[allow(dead_code)]
impl Parser {
    /// Creates a new HTTP/2 parser.
    ///
    /// Additional configuration must be done through the builder methods before calling `attach`.
    pub fn new() -> Parser {
        let states = vec![0, 1];

        Parser {
            s_any: 0,
            dfa: Dfa::new(states.into_iter()),
            parse_msg_fn: None,
            parse_buf_fn: None,
            parse_skb_fn: None,
            extract_fn: None,
            matched_fn: None,
        }
    }

    /// Specifies the function template in the target program to be replaced with an HTTP/2
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
        let mut name_encoded = Vec::new();
        huffman::encode(name.as_str().as_bytes(), &mut name_encoded)?;

        self.dfa
            .start_pattern(self.s_any)
            .push(&name_encoded)
            .capture_field_value();

        Ok(self)
    }

    fn populate_static_table(&self, static_table: &MapHandle) -> Result<()> {
        let insert = |idx: u32, key: &str, val: Option<&str>| {
            let mut hf_key = Vec::new();
            huffman::encode(key.as_bytes(), &mut hf_key)?;

            let mut hf_val = Vec::new();
            if let Some(val) = val {
                huffman::encode(val.as_bytes(), &mut hf_val)?;
            }

            let key_len = hf_key.len() as u8;
            let val_len = hf_val.len() as u8;
            hf_key.resize(128, 0);
            hf_val.resize(128, 0);

            let hf = header_field {
                key: hf_key.try_into().unwrap(),
                key_len,
                val: hf_val.try_into().unwrap(),
                val_len,
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

        let skel_builder = ParserSkelBuilder::default();
        let mut open_obj: MaybeUninit<OpenObject> = MaybeUninit::uninit();
        let mut open_skel = skel_builder.open(&mut open_obj)?;
        if tracing::event_enabled!(Level::TRACE) {
            open_skel.progs.parse_msg.set_log_level(1);
            open_skel.progs.parse_skb.set_log_level(1);
            open_skel.progs.parse_buf.set_log_level(1);
        }

        let progs = vec![
            (&mut open_skel.progs.parse_msg, self.parse_msg_fn.clone()),
            (&mut open_skel.progs.parse_skb, self.parse_skb_fn.clone()),
            (&mut open_skel.progs.parse_buf, self.parse_buf_fn.clone()),
            (&mut open_skel.progs.matched, self.matched_fn.clone()),
            (&mut open_skel.progs.extract_match, self.extract_fn.clone()),
        ];

        for (prog, func) in progs {
            autoload_and_attach(prog, target, func)?;
        }

        self.inject(&mut open_skel)?;

        let skel = open_skel.load()?;
        bpf_tracing::try_init(skel.object())?;

        let mut links = Vec::new();
        if self.parse_msg_fn.is_some() {
            links.push(skel.progs.parse_msg.attach()?);
        }
        if self.parse_skb_fn.is_some() {
            links.push(skel.progs.parse_skb.attach()?);
        }
        if self.parse_buf_fn.is_some() {
            links.push(skel.progs.parse_buf.attach()?);
        }
        if self.matched_fn.is_some() {
            links.push(skel.progs.matched.attach()?);
        }
        if self.extract_fn.is_some() {
            links.push(skel.progs.extract_match.attach()?);
        }

        let id = skel.maps.static_table.info()?.info.id;
        let static_table = MapHandle::from_map_id(id)?;
        self.populate_static_table(&static_table)?;

        debug!("Beeline http/2 attached");

        let id = skel.maps.dynamic_table_info.info()?.info.id;
        Ok(AttachedParser {
            dynamic_table_info: MapHandle::from_map_id(id)?,
            links,
        })
    }

    fn inject(&self, skel: &mut OpenParserSkel) -> Result<()> {
        for (from, to, input, action) in self.dfa.iter_transitions() {
            let s = *from as usize;
            let data = skel.maps.rodata_data.as_mut().unwrap();
            let t = new_transition(*to, *action, data);
            data.s2ts[s][*input as usize] = t;
        }

        Ok(())
    }
}

pub struct AttachedParser {
    dynamic_table_info: MapHandle,

    #[allow(dead_code)]
    links: Vec<Link>,
}

#[repr(C)]
#[derive(Default, Clone)]
pub struct DynamicTableInfo {
    pub count: u32,
    pub size: u32,
    pub max_size: u32,
    pub deleted: u32,
}

unsafe impl Plain for DynamicTableInfo {}

impl AttachedParser {
    pub fn dynamic_table_info(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Result<DynamicTableInfo> {
        let conn = ip4_conn {
            local: local.into(),
            remote: remote.into(),
        };

        let key = unsafe { conn.as_bytes() };
        let val = self.dynamic_table_info.lookup(key, MapFlags::empty())?;
        let Some(val) = val else {
            bail!("no dynamic table info for connection");
        };

        let info: Result<&DynamicTableInfo, _> = plain::from_bytes(&val);
        match info {
            Ok(info) => Ok(info.clone()),
            Err(e) => bail!("failed to parse dynamic table info: {:?}", e),
        }
    }
}
