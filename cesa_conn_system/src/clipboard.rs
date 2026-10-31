//! OS clipboard access for clipboard sync (text only).
//!
//! The daemon polls [`Clipboard::change_count`] (cheap, reads no content)
//! and reads the text only after the count changed. Content marked by a
//! password manager as concealed or transient is never read into memory
//! ([`ClipRead::Concealed`]); see <http://nspasteboard.org>.
//!
//! macOS: the general `NSPasteboard`, through objc2's safe bindings (this
//! crate keeps `forbid(unsafe_code)`). Other platforms: not supported yet,
//! [`platform_clipboard`] returns `None` and the daemon says so.
//!
//! What can't be wiped: the OS keeps its own copy of whatever is on the
//! clipboard (that is what a clipboard is), and the `NSString` objects are
//! released by the OS. Our copies are `Zeroizing`.

use zeroize::Zeroizing;

/// What reading the clipboard found.
pub enum ClipRead {
    /// Text, at most the asked-for length (UTF-8 bytes), wiped on drop.
    Text(Zeroizing<String>),
    /// A password manager marked it concealed / transient: not read.
    Concealed,
    /// Text longer than allowed: not read.
    TooLarge,
    /// No text on the clipboard (empty, an image, files, ...).
    NoText,
}

/// The OS clipboard. A trait so tests can use memory.
pub trait Clipboard: Send + Sync {
    /// The clipboard's change counter: it changes whenever anyone puts
    /// something new on the clipboard. Reads no content.
    fn change_count(&self) -> i64;
    /// The text on the clipboard if it is at most `max_len` bytes of UTF-8
    /// and not marked concealed / transient.
    fn read_text(&self, max_len: usize) -> ClipRead;
    /// Replaces the clipboard with `text`; returns the change count that
    /// belongs to this write (so the daemon doesn't send it back), or
    /// `None` if the OS refused.
    fn write_text(&self, text: &str) -> Option<i64>;
}

/// Pasteboard types a password manager sets on content that must not be
/// recorded or synced (nspasteboard.org). Content carrying any of them is
/// never read.
pub const CONCEALED_MARKERS: [&str; 2] = [
    "org.nspasteboard.ConcealedType",
    "org.nspasteboard.TransientType",
];

/// The UTI of plain UTF-8 text (`NSPasteboardTypeString`), spelled out: the
/// framework constant is an extern static, which needs `unsafe` to read.
#[cfg(target_os = "macos")]
const TEXT_TYPE: &str = "public.utf8-plain-text";

/// The OS clipboard of this platform, `None` where it isn't supported yet.
pub fn platform_clipboard() -> Option<std::sync::Arc<dyn Clipboard>> {
    #[cfg(target_os = "macos")]
    {
        Some(std::sync::Arc::new(macos::MacClipboard))
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::{CONCEALED_MARKERS, ClipRead, Clipboard, TEXT_TYPE};
    use objc2::rc::autoreleasepool;
    use objc2_app_kit::NSPasteboard;
    use objc2_foundation::NSString;
    use zeroize::Zeroizing;

    /// The general pasteboard. Every call takes it fresh and runs in its
    /// own autorelease pool, so nothing is kept between calls.
    pub struct MacClipboard;

    impl Clipboard for MacClipboard {
        fn change_count(&self) -> i64 {
            autoreleasepool(|_| {
                let count = NSPasteboard::generalPasteboard().changeCount();
                i64::try_from(count).unwrap_or(i64::MAX)
            })
        }

        fn read_text(&self, max_len: usize) -> ClipRead {
            autoreleasepool(|_| {
                let pasteboard = NSPasteboard::generalPasteboard();

                // the types only, no content: a marked item is never read
                if let Some(types) = pasteboard.types() {
                    let marked = types.iter().any(|kind| {
                        let kind = kind.to_string();
                        CONCEALED_MARKERS.iter().any(|marker| kind == *marker)
                    });
                    if marked {
                        return ClipRead::Concealed;
                    }
                }

                let Some(text) = pasteboard.stringForType(&NSString::from_str(TEXT_TYPE)) else {
                    return ClipRead::NoText;
                };
                // the UTF-8 length, checked before copying anything out
                let len = text.len();
                if len == 0 {
                    return ClipRead::NoText;
                }
                if len > max_len {
                    return ClipRead::TooLarge;
                }

                // copied once into a buffer that is wiped on drop
                let copy = Zeroizing::new(text.to_string());
                if copy.len() > max_len {
                    return ClipRead::TooLarge;
                }
                ClipRead::Text(copy)
            })
        }

        fn write_text(&self, text: &str) -> Option<i64> {
            autoreleasepool(|_| {
                let pasteboard = NSPasteboard::generalPasteboard();
                // clearContents takes ownership and returns the new count;
                // writing the string doesn't change it again
                let count = pasteboard.clearContents();
                let written = pasteboard
                    .setString_forType(&NSString::from_str(text), &NSString::from_str(TEXT_TYPE));
                written.then(|| i64::try_from(count).unwrap_or(i64::MAX))
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that the markers are the nspasteboard.org names, spelled exactly
    #[test]
    fn test_concealed_markers() {
        assert!(CONCEALED_MARKERS.contains(&"org.nspasteboard.ConcealedType"));
        assert!(CONCEALED_MARKERS.contains(&"org.nspasteboard.TransientType"));
    }

    /// Test that the platform clipboard exists exactly where it is built
    #[test]
    fn test_platform_clipboard() {
        assert_eq!(platform_clipboard().is_some(), cfg!(target_os = "macos"));
    }

    /// Test the real macOS clipboard: write, count, read back, size limit.
    /// Ignored by default: it replaces the user's clipboard (run by hand).
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "replaces the real clipboard"]
    fn test_os_clipboard_roundtrip() {
        let clipboard = platform_clipboard().unwrap();
        let count = clipboard.write_text("cesaconn clipboard test").unwrap();
        assert_eq!(clipboard.change_count(), count);
        match clipboard.read_text(1024) {
            ClipRead::Text(text) => assert_eq!(text.as_str(), "cesaconn clipboard test"),
            _ => panic!("no text read back"),
        }
        assert!(matches!(clipboard.read_text(4), ClipRead::TooLarge));

        // what a password manager writes: the text plus a concealed marker
        for marker in CONCEALED_MARKERS {
            let pasteboard = objc2_app_kit::NSPasteboard::generalPasteboard();
            pasteboard.clearContents();
            let text = objc2_foundation::NSString::from_str("secret from a password manager");
            assert!(
                pasteboard
                    .setString_forType(&text, &objc2_foundation::NSString::from_str(TEXT_TYPE))
            );
            let empty = objc2_foundation::NSString::from_str("");
            assert!(
                pasteboard.setString_forType(&empty, &objc2_foundation::NSString::from_str(marker))
            );
            assert!(matches!(clipboard.read_text(1024), ClipRead::Concealed));
        }
        clipboard
            .write_text("cesaconn clipboard test done")
            .unwrap();
    }
}
