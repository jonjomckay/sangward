//! `gdk::Clipboard` implementation of the platform `Clipboard` trait.
//!
//! Lives in the GTK crate because it needs GTK types; the trait itself is
//! toolkit-agnostic (`sangward-platform`).

use relm4::gtk::gdk;
use relm4::gtk::glib;
use relm4::gtk::prelude::*;

use sangward_platform::{Clipboard, ClipboardError, CopyToken};

pub struct GdkClipboard {
    clipboard: gdk::Clipboard,
    next: u64,
    /// The provider we installed, to check ownership without reading contents back.
    current: Option<(CopyToken, gdk::ContentProvider)>,
}

impl GdkClipboard {
    pub fn for_display(display: &gdk::Display) -> Self {
        Self {
            clipboard: display.clipboard(),
            next: 1,
            current: None,
        }
    }

    pub fn default_display() -> Option<Self> {
        gdk::Display::default().map(|d| Self::for_display(&d))
    }
}

impl Clipboard for GdkClipboard {
    fn set_secret(&mut self, value: &str) -> Result<CopyToken, ClipboardError> {
        let text = gdk::ContentProvider::for_bytes(
            "text/plain;charset=utf-8",
            &glib::Bytes::from(value.as_bytes()),
        );
        let plain =
            gdk::ContentProvider::for_bytes("text/plain", &glib::Bytes::from(value.as_bytes()));
        let utf8 =
            gdk::ContentProvider::for_bytes("UTF8_STRING", &glib::Bytes::from(value.as_bytes()));
        // KDE/Klipper and most clipboard managers skip entries carrying this hint.
        let hint = gdk::ContentProvider::for_bytes(
            "x-kde-passwordManagerHint",
            &glib::Bytes::from_static(b"secret"),
        );
        let provider = gdk::ContentProvider::new_union(&[text, plain, utf8, hint]);
        self.clipboard
            .set_content(Some(&provider))
            .map_err(|e| ClipboardError::Unavailable(e.to_string()))?;
        let token = CopyToken(self.next);
        self.next += 1;
        self.current = Some((token, provider));
        Ok(token)
    }

    fn clear_if_owned(&mut self, token: CopyToken) -> Result<bool, ClipboardError> {
        let Some((cur, provider)) = self.current.take() else {
            return Ok(false);
        };
        if cur != token {
            self.current = Some((cur, provider));
            return Ok(false);
        }
        // Still ours only if the clipboard is local and serving our exact provider.
        let ours =
            self.clipboard.is_local() && self.clipboard.content().as_ref() == Some(&provider);
        if ours {
            self.clipboard
                .set_content(None::<&gdk::ContentProvider>)
                .map_err(|e| ClipboardError::Unavailable(e.to_string()))?;
        }
        Ok(ours)
    }
}
