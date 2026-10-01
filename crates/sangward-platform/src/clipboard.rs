//! Clipboard abstraction with "clear only if it's still ours" semantics.
//!
//! The GTK frontend implements this with `gdk::Clipboard` (in `sangward-gtk`,
//! since it needs GTK types). [`ArboardClipboard`] is the toolkit-free
//! implementation used by the CLI and any non-GTK frontend.

#[derive(Debug, thiserror::Error)]
pub enum ClipboardError {
    #[error("clipboard unavailable: {0}")]
    Unavailable(String),
}

/// Identifies one `set_secret` call, so a later `clear_if_owned` can tell
/// whether the clipboard still holds that value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CopyToken(pub u64);

pub trait Clipboard {
    /// Put a secret on the clipboard, marked with `x-kde-passwordManagerHint: secret`
    /// where the backend supports it so clipboard managers skip it.
    fn set_secret(&mut self, value: &str) -> Result<CopyToken, ClipboardError>;

    /// Clear the clipboard if it still holds the value from `token`.
    /// Returns whether it cleared anything.
    fn clear_if_owned(&mut self, token: CopyToken) -> Result<bool, ClipboardError>;
}

/// `arboard`-backed clipboard (X11 + Wayland data-control).
///
/// On Linux the clipboard is owned by the process that set it, so the CLI keeps
/// the process alive until the clear deadline (`hold_until`).
#[cfg(target_os = "linux")]
pub struct ArboardClipboard {
    inner: arboard::Clipboard,
    next: u64,
    current: Option<(CopyToken, zeroize::Zeroizing<String>)>,
}

#[cfg(target_os = "linux")]
impl ArboardClipboard {
    pub fn new() -> Result<Self, ClipboardError> {
        let inner =
            arboard::Clipboard::new().map_err(|e| ClipboardError::Unavailable(e.to_string()))?;
        Ok(Self {
            inner,
            next: 1,
            current: None,
        })
    }

    /// Set the secret and serve it until `deadline` (or until someone else takes
    /// the clipboard), then clear it if still ours. Blocks the calling thread.
    pub fn copy_and_hold(
        &mut self,
        value: &str,
        deadline: std::time::Instant,
    ) -> Result<bool, ClipboardError> {
        use arboard::SetExtLinux;
        self.inner
            .set()
            .exclude_from_history()
            .wait_until(deadline)
            .text(value.to_owned())
            .map_err(|e| ClipboardError::Unavailable(e.to_string()))?;
        let token = self.mark(value);
        self.clear_if_owned(token)
    }

    fn mark(&mut self, value: &str) -> CopyToken {
        let token = CopyToken(self.next);
        self.next += 1;
        self.current = Some((token, zeroize::Zeroizing::new(value.to_owned())));
        token
    }
}

#[cfg(target_os = "linux")]
impl Clipboard for ArboardClipboard {
    fn set_secret(&mut self, value: &str) -> Result<CopyToken, ClipboardError> {
        use arboard::SetExtLinux;
        self.inner
            .set()
            .exclude_from_history()
            .text(value.to_owned())
            .map_err(|e| ClipboardError::Unavailable(e.to_string()))?;
        Ok(self.mark(value))
    }

    fn clear_if_owned(&mut self, token: CopyToken) -> Result<bool, ClipboardError> {
        let Some((cur, value)) = self.current.take() else {
            return Ok(false);
        };
        if cur != token {
            self.current = Some((cur, value));
            return Ok(false);
        }
        // Compare against the live clipboard: if the user copied something else, leave it.
        match self.inner.get_text() {
            Ok(text) if text == *value => {
                self.inner
                    .clear()
                    .map_err(|e| ClipboardError::Unavailable(e.to_string()))?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}
