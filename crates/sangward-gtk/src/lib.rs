//! sangward-gtk: a thin Relm4 rendering layer over `sangward-client`.
//!
//! Split into a library so `tests/ui.rs` can launch the real component
//! in-process, drive its widgets and measure main-loop stalls.

mod app;
pub mod clipboard;

pub use app::{APP_ID, App, Msg, names};
