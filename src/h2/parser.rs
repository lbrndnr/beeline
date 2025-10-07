use crate::{
    h2,
    h2::dfa::{Action, Dfa},
};
use anyhow::{Ok, Result};

const CRLF: &str = "\r\n";

pub struct Parser {
    pub s_init: u16,
    pub s_any: u16,

    dfa: Dfa,
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
        // // Usage example
        // let (headers_without_values, headers_with_values) = create_header_maps();

        // // Look up a header without value
        // if let Some(index) = headers_without_values.get("host") {
        //     println!("Host header is at index: {}", index);
        // }

        // // Look up a header with value
        // if let Some(method_values) = headers_with_values.get(":method") {
        //     if let Some(index) = method_values.get("GET") {
        //         println!(":method GET is at index: {}", index);
        //     }
        // }

        let (st, st_) = h2::create_header_maps();

        if let Some(idx) = st.get(key) {
            let mut idx_encoded = hpack::encoder::encode_integer(*idx, 6);

            // println!("Header index: {:?}", idx_encoded);

            idx_encoded[0] |= 64;

            // println!("Header index: {:?}", idx_encoded);

            self.dfa
                .start_pattern(self.s_any)
                .push(&idx_encoded)?
                .capture_field_value();
            // .push_optional('*')?
            // .end_caputuring_and_restart_with("a", self.s_any)?;
        }

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
}
