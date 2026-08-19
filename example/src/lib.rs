//! The parts of the example server that do not need the fast path attached.
//!
//! These live in a library so that they can be tested on their own: the
//! connection loop and the listener wrapper are what implement the dynamic
//! table handover on the user space side, and none of it requires eBPF to
//! exercise.

pub mod h2serve;
pub mod listener;
