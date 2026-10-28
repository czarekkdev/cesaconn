//! The pairing code: 8 symbols the users compare on both devices.
//!
//! The daemon derives the code from the handshake hash (HKDF, see
//! `auth_snow::pairing_code` in the networker) and sends only the 8 symbol
//! indices to the UI, which shows each one as an emoji AND its name. The
//! names cover terminals that draw an emoji differently or as a box.
//!
//! 64 symbols = 6 bits each, 8 symbols = 48 bits: a MITM who knows the auth
//! password runs two different Noise sessions, so the two devices show
//! different codes; a lucky match is about 1 in 2.8 * 10^14.
//!
//! The code is not secret (it is shown on screen), and it can't be turned
//! back into the handshake hash.

/// Symbols in one pairing code.
pub const PAIRING_CODE_LEN: usize = 8;

/// Size of the symbol table (6 bits per symbol).
pub const PAIRING_SYMBOLS: usize = 64;

/// The symbol table: `(emoji, name)`. The order is part of the protocol:
/// changing it changes the code both devices show, so never reorder it.
/// Only single-code-point emoji (no variation selectors, no joiners), so
/// every terminal draws them as one character.
pub const SYMBOLS: [(&str, &str); PAIRING_SYMBOLS] = [
    ("🐶", "dog"),
    ("🐱", "cat"),
    ("🐭", "mouse"),
    ("🐰", "rabbit"),
    ("🦊", "fox"),
    ("🐻", "bear"),
    ("🐼", "panda"),
    ("🐨", "koala"),
    ("🐯", "tiger"),
    ("🦁", "lion"),
    ("🐮", "cow"),
    ("🐷", "pig"),
    ("🐸", "frog"),
    ("🐵", "monkey"),
    ("🐔", "chicken"),
    ("🐧", "penguin"),
    ("🦉", "owl"),
    ("🐴", "horse"),
    ("🦄", "unicorn"),
    ("🐝", "bee"),
    ("🦋", "butterfly"),
    ("🐌", "snail"),
    ("🐢", "turtle"),
    ("🐍", "snake"),
    ("🐙", "octopus"),
    ("🦀", "crab"),
    ("🐟", "fish"),
    ("🐬", "dolphin"),
    ("🐳", "whale"),
    ("🐘", "elephant"),
    ("🦒", "giraffe"),
    ("🌵", "cactus"),
    ("🌲", "tree"),
    ("🍀", "clover"),
    ("🍄", "mushroom"),
    ("🌻", "sunflower"),
    ("🌙", "moon"),
    ("⭐", "star"),
    ("🔥", "fire"),
    ("🌈", "rainbow"),
    ("⛄", "snowman"),
    ("💧", "drop"),
    ("🍎", "apple"),
    ("🍌", "banana"),
    ("🍇", "grapes"),
    ("🍉", "watermelon"),
    ("🍋", "lemon"),
    ("🍒", "cherries"),
    ("🍓", "strawberry"),
    ("🥕", "carrot"),
    ("🌽", "corn"),
    ("🍕", "pizza"),
    ("🎂", "cake"),
    ("☕", "coffee"),
    ("🎈", "balloon"),
    ("🎁", "gift"),
    ("🔑", "key"),
    ("🔔", "bell"),
    ("⚓", "anchor"),
    ("🚀", "rocket"),
    ("🚲", "bicycle"),
    ("⚽", "football"),
    ("🎸", "guitar"),
    ("👑", "crown"),
];

/// A pairing code as symbol indices, each below [`PAIRING_SYMBOLS`].
pub type PairingCode = [u8; PAIRING_CODE_LEN];

/// Whether every index is in the table (a code from the wire is checked
/// before it is shown).
pub fn is_valid(code: &PairingCode) -> bool {
    code.iter().all(|&i| usize::from(i) < PAIRING_SYMBOLS)
}

/// The `(emoji, name)` of one symbol, `None` outside the table.
pub fn symbol(index: u8) -> Option<(&'static str, &'static str)> {
    SYMBOLS.get(usize::from(index)).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that every emoji and every name appears once, so two codes
    /// never look alike, and that each emoji is a single character
    #[test]
    fn test_symbols_unique_and_single_char() {
        for (i, (emoji, name)) in SYMBOLS.iter().enumerate() {
            assert_eq!(emoji.chars().count(), 1, "{name} is more than one char");
            assert!(
                !name.is_empty() && name.chars().all(|c| c.is_ascii_lowercase()),
                "{name}"
            );
            for (other_emoji, other_name) in SYMBOLS.iter().skip(i + 1) {
                assert_ne!(emoji, other_emoji);
                assert_ne!(name, other_name);
            }
        }
    }

    /// Test that indices outside the table are refused
    #[test]
    fn test_code_validation() {
        assert!(is_valid(&[0, 1, 2, 3, 60, 61, 62, 63]));
        assert!(!is_valid(&[0, 0, 0, 0, 0, 0, 0, 64]));
        assert!(!is_valid(&[255; PAIRING_CODE_LEN]));
        assert_eq!(symbol(63), Some(("👑", "crown")));
        assert_eq!(symbol(64), None);
    }
}
