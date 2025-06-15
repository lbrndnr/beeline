use crate::dfa::{Action, Dfa};
use anyhow::{Ok, Result};

const CRLF: &str = "\r\n";

pub struct H2Dfa {
    pub s_init: u16,
    pub s_any: u16,

    dfa: Dfa,
}

#[allow(dead_code)]
impl H2Dfa {
    pub fn new(s_init: u16, s_any: u16) -> H2Dfa {
        let states = vec![s_init, s_any];

        H2Dfa {
            s_init,
            s_any,
            dfa: Dfa::new(states.into_iter()),
        }
    }

    pub fn iter_states<'a>(&'a self) -> impl Iterator<Item = &'a u16> {
        self.dfa.iter_states()
    }

    pub fn iter_transitions<'a>(
        &'a self,
    ) -> impl Iterator<Item = (&'a u16, &'a u16, &'a char, &'a Action)> {
        self.dfa.iter_transitions()
    }
}
