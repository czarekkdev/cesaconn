//! The encrypted vault: everything the daemon keeps across restarts.
//! Nothing secret is stored unencrypted, configs included; the only
//! plaintext is format metadata and the three salts.
//!
//! The vault doesn't rely on the OS: its salts live in its own header, so
//! it works the same on every platform. The OS keychain is used only for
//! the opt-in automatic login (`d_key`, see the daemon).
//!
//! Envelope encryption:
//! * Standard mode: `KEK = HKDF-BLAKE2s(ikm = d_key, salt = storage salt,
//!   info = KEK_LABEL)`; the vault holds `a_key`, so the data password
//!   alone opens it.
//! * Enhanced mode: `KEK = HKDF-BLAKE2s(ikm = Argon2id(d_key || a_key,
//!   storage salt), salt = storage salt, info = KEK_BOTH_LABEL)`; `a_key`
//!   is never stored, so both passwords are needed at every start. The
//!   extra Argon2 makes every pairing of a guessed auth password with a
//!   guessed data password cost a full Argon2 run: without it an attacker
//!   would derive each candidate key once and test the pairings with a
//!   cheap HKDF (N + M Argon2 runs for N x M pairs instead of N x M).
//! * The KEK never uses a key directly, and it is useless on the network.
//! * A random DEK encrypts the payload. The KEK only wraps the DEK, so a
//!   password or mode change re-wraps 32 bytes.
//!
//! File layout, all AES-256-GCM:
//! ```text
//! MAGIC (8) || VERSION (1) || mode (1) ||
//!   a_salt (32) || d_salt (32) || storage salt (32)   header, AAD of both layers
//! wrap nonce (12) || wrapped DEK (32 + 16)             AAD = header || WRAP_LABEL
//! data nonce (12) || ciphertext (n * PAD_BLOCK + 16)   AAD = header || DATA_LABEL
//! ```
//! The salts aren't secret (`a_salt` is even sent to joining devices), but
//! with them in the file, anyone holding the file can guess passwords
//! offline: each guess costs a full Argon2 run, each guessed pair in
//! Enhanced mode (daemon.md 8.3).
//!
//! The plaintext of the data layer is `contents len (u32 LE) || contents ||
//! zeros`, padded to whole [`PAD_BLOCK`]s, so the file size doesn't tell how
//! much is inside.

use core::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use blake2::Blake2s256;
use hkdf::SimpleHkdf;
use tracing::warn;
use zeroize::Zeroizing;

use cesa_conn_crypto::{
    aes::{decrypt_with_aad, encrypt_with_aad},
    crand::random_array,
    pswd_manager::derive_key,
};
use cesa_conn_system::ipc::check_private_dir;

use crate::auth_snow::{AuthKey, DataKey, IDENTITY_SEED_LEN};

/* format constants */
/// File magic.
const MAGIC: &[u8; 8] = b"CESAVLT\0";
/// Format version (3: salts and the unlock mode in the header).
const VERSION: u8 = 3;
/// Versions of earlier builds (salts in the keychain): reported as
/// outdated, so the user is told to reset. Any other version is unknown.
const OUTDATED_VERSIONS: [u8; 2] = [1, 2];
/// -> magic (8) + version (1) + mode (1) + three salts (3 * 32)
const HEADER_LEN: usize = 8 + 1 + 1 + 3 * 32;
/// AES-GCM nonce (12) and tag (16)
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// -> DEK (32) + tag (16)
const WRAPPED_DEK_LEN: usize = 32 + TAG_LEN;
/// -> wrap nonce + wrapped DEK
pub const WRAP_LEN: usize = NONCE_LEN + WRAPPED_DEK_LEN;
/// Plaintext is padded to whole blocks of this many bytes.
pub const PAD_BLOCK: usize = 4096;
/// Largest vault file accepted (bytes); checked before reading.
pub const MAX_VAULT_LEN: u64 = 4 * 1024 * 1024;
/// Smallest valid file: header, wrap, data nonce, one block + tag.
const MIN_VAULT_LEN: usize = HEADER_LEN + WRAP_LEN + NONCE_LEN + PAD_BLOCK + TAG_LEN;

/* unlock modes (header byte 9) */
/// Standard: the data password opens the vault, `a_key` is inside.
const MODE_STANDARD: u8 = 0x00;
/// Enhanced: both passwords open the vault, `a_key` is never stored.
const MODE_ENHANCED: u8 = 0x01;

/* domain separation */
const KEK_LABEL: &[u8] = b"cesaconn-storage-v1";
const KEK_BOTH_LABEL: &[u8] = b"cesaconn-storage-both-v1";
const WRAP_LABEL: &[u8] = b"cesaconn-vault-dek";
const DATA_LABEL: &[u8] = b"cesaconn-vault-data";

/* contents (TLV inside the data layer): tag (1) || len (u32 LE) || value */
/// Standard mode only.
const TAG_A_KEY: u8 = 0x01;
const TAG_CONFIG: u8 = 0x03;
const TAG_IDENTITY: u8 = 0x04;
const TAG_PEERS: u8 = 0x05;
/// Largest config blob (bytes).
pub const MAX_CONFIG_LEN: usize = 64 * 1024;
/// Largest encoded trusted-peer list (256 peers of about 2.9 KB fit).
pub const MAX_PEERS_LEN: usize = 1024 * 1024;

/// Vault file name inside the private data directory.
const FILE_NAME: &str = "vault.bin";

/// All errors of the vault.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum VaultErrors {
    /// The file is not a vault, or its layout is wrong.
    Malformed,
    /// The file is a vault of an older format version (1 or 2): this
    /// version can't open it (reset the device and join again).
    Outdated,
    /// The file is a vault of a version this build doesn't know (a newer
    /// build, or damage): left alone, never reported as outdated.
    UnknownVersion,
    /// The DEK didn't unwrap: wrong password(s) (or a swapped header).
    WrongKey,
    /// The DEK unwrapped but the contents didn't decrypt or parse: damaged.
    Corrupt,
    /// The contents don't fit the header's unlock mode (`a_key` stored in
    /// Enhanced mode, or missing in Standard mode).
    WrongMode,
    /// The file is larger than [`MAX_VAULT_LEN`] or the contents too large.
    TooLarge,
    /// Random bytes, HKDF or encryption failed.
    Crypto,
    /// Reading or writing the file failed.
    Io,
    /// The data directory is missing, not ours, or not private.
    InsecureDirectory,
}

impl fmt::Display for VaultErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultErrors::Malformed => write!(f, "not a vault file"),
            VaultErrors::Outdated => write!(f, "vault of an older version"),
            VaultErrors::UnknownVersion => write!(f, "vault of an unknown version"),
            VaultErrors::WrongKey => write!(f, "wrong password"),
            VaultErrors::Corrupt => write!(f, "vault contents are damaged"),
            VaultErrors::WrongMode => write!(f, "vault contents don't fit its unlock mode"),
            VaultErrors::TooLarge => write!(f, "vault is too large"),
            VaultErrors::Crypto => write!(f, "vault cryptography failed"),
            VaultErrors::Io => write!(f, "failed to read or write the vault"),
            VaultErrors::InsecureDirectory => write!(f, "vault directory is not private"),
        }
    }
}

/// How the vault is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The data password opens it; `a_key` is stored inside.
    Standard,
    /// Both passwords open it; `a_key` is never stored.
    Enhanced,
}

impl Mode {
    fn byte(self) -> u8 {
        match self {
            Mode::Standard => MODE_STANDARD,
            Mode::Enhanced => MODE_ENHANCED,
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            MODE_STANDARD => Some(Mode::Standard),
            MODE_ENHANCED => Some(Mode::Enhanced),
            _ => None,
        }
    }
}

/// The plaintext header: the unlock mode and the three salts. Not secret,
/// but authenticated (it is the AAD of both layers). No `Debug`; wiped on
/// drop like every salt in the daemon.
pub struct Header {
    pub mode: Mode,
    /// Argon2 salt of the auth password.
    pub a_salt: Zeroizing<[u8; 32]>,
    /// Argon2 salt of the data password.
    pub d_salt: Zeroizing<[u8; 32]>,
    /// HKDF salt of the KEK (this device's own, never shared).
    pub storage_salt: Zeroizing<[u8; 32]>,
}

impl Header {
    /// The header bytes as written.
    fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        let (magic, rest) = out.split_at_mut(MAGIC.len());
        magic.copy_from_slice(MAGIC);
        let (meta, salts) = rest.split_at_mut(2);
        meta.copy_from_slice(&[VERSION, self.mode.byte()]);
        let (chunks, _) = salts.as_chunks_mut::<32>();
        for (chunk, salt) in chunks
            .iter_mut()
            .zip([&self.a_salt, &self.d_salt, &self.storage_salt])
        {
            chunk.copy_from_slice(salt.as_slice());
        }
        out
    }

    /// Parses the header at the start of `file`. A vault of an earlier
    /// build's version is [`VaultErrors::Outdated`]; any other version is
    /// `UnknownVersion`.
    fn parse(file: &[u8]) -> Result<Self, VaultErrors> {
        let (magic, rest) = file
            .split_first_chunk::<8>()
            .ok_or(VaultErrors::Malformed)?;
        if magic != MAGIC {
            return Err(VaultErrors::Malformed);
        }
        let (&version, rest) = rest.split_first().ok_or(VaultErrors::Malformed)?;
        if OUTDATED_VERSIONS.contains(&version) {
            return Err(VaultErrors::Outdated);
        }
        if version != VERSION {
            return Err(VaultErrors::UnknownVersion);
        }
        let (&mode, rest) = rest.split_first().ok_or(VaultErrors::Malformed)?;
        let mode = Mode::from_byte(mode).ok_or(VaultErrors::Malformed)?;
        let (a_salt, rest) = rest
            .split_first_chunk::<32>()
            .ok_or(VaultErrors::Malformed)?;
        let (d_salt, rest) = rest
            .split_first_chunk::<32>()
            .ok_or(VaultErrors::Malformed)?;
        let (storage_salt, _) = rest
            .split_first_chunk::<32>()
            .ok_or(VaultErrors::Malformed)?;

        Ok(Self {
            mode,
            a_salt: Zeroizing::new(*a_salt),
            d_salt: Zeroizing::new(*d_salt),
            storage_salt: Zeroizing::new(*storage_salt),
        })
    }

    /// A copy with the same salts in `mode`.
    pub fn with_mode(&self, mode: Mode) -> Self {
        Self {
            mode,
            a_salt: self.a_salt.clone(),
            d_salt: self.d_salt.clone(),
            storage_salt: self.storage_salt.clone(),
        }
    }
}

/// The header of a vault file, read without any key: what the daemon needs
/// before unlocking (the mode, so the UI asks for the right passwords, and
/// the salts to derive the keys with).
pub fn read_header(file: &[u8]) -> Result<Header, VaultErrors> {
    if u64::try_from(file.len()).map_or(true, |l| l > MAX_VAULT_LEN) {
        return Err(VaultErrors::TooLarge);
    }
    let header = Header::parse(file)?;
    if file.len() < MIN_VAULT_LEN {
        return Err(VaultErrors::Malformed);
    }
    Ok(header)
}

/// The KEK for `header`'s mode: `a_key` must be given exactly in Enhanced
/// mode (`HKDF(Argon2id(d_key || a_key))`), and not in Standard mode
/// (`HKDF(d_key)`). Enhanced mode runs Argon2: call it off the async
/// workers.
pub fn derive_kek(
    header: &Header,
    d_key: &DataKey,
    a_key: Option<&AuthKey>,
) -> Result<Zeroizing<[u8; 32]>, VaultErrors> {
    let mut kek = Zeroizing::new([0u8; 32]);
    let salt = Some(header.storage_salt.as_slice());

    match (header.mode, a_key) {
        (Mode::Standard, None) => {
            SimpleHkdf::<Blake2s256>::new(salt, d_key.expose().as_slice())
                .expand(KEK_LABEL, kek.as_mut_slice())
                .map_err(|_| VaultErrors::Crypto)?;
        }
        (Mode::Enhanced, Some(a_key)) => {
            // both keys in one zeroizing buffer, data key first
            let mut ikm = Zeroizing::new([0u8; 64]);
            let (d, a) = ikm.split_at_mut(32);
            d.copy_from_slice(d_key.expose().as_slice());
            a.copy_from_slice(a_key.expose().as_slice());
            // one more Argon2 over both keys: a guessed pair costs a full run
            let both = derive_key(ikm.as_slice(), &header.storage_salt)
                .map_err(|_| VaultErrors::Crypto)?;
            drop(ikm);
            SimpleHkdf::<Blake2s256>::new(salt, both.as_slice())
                .expand(KEK_BOTH_LABEL, kek.as_mut_slice())
                .map_err(|_| VaultErrors::Crypto)?;
        }
        _ => return Err(VaultErrors::WrongMode),
    }

    Ok(kek)
}

/// Everything the vault holds. No `Debug`/`Clone`; wiped on drop.
pub struct VaultContents {
    /// `Some` in Standard mode, `None` in Enhanced mode (never stored).
    pub a_key: Option<AuthKey>,
    /// Daemon settings (opaque here); empty until there are settings.
    pub config: Zeroizing<Vec<u8>>,
    /// This device's identity seed (X25519 private key || ML-DSA seed).
    pub identity: Zeroizing<[u8; IDENTITY_SEED_LEN]>,
    /// Trusted peers, encoded by `auth_snow::encode_peers` (opaque here).
    pub peers: Zeroizing<Vec<u8>>,
}

impl VaultContents {
    /// TLV encoding, pre-sized so the buffer never reallocates.
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, VaultErrors> {
        if self.config.len() > MAX_CONFIG_LEN || self.peers.len() > MAX_PEERS_LEN {
            return Err(VaultErrors::TooLarge);
        }

        // up to four entries of tag (1) + len (4), the values
        let len = (4 * 5 + 32 + IDENTITY_SEED_LEN)
            .saturating_add(self.config.len())
            .saturating_add(self.peers.len());
        let mut out = Zeroizing::new(Vec::with_capacity(len));

        let a_key = self
            .a_key
            .as_ref()
            .map(|k| (TAG_A_KEY, k.expose().as_slice()));
        for (tag, value) in a_key.into_iter().chain([
            (TAG_CONFIG, self.config.as_slice()),
            (TAG_IDENTITY, self.identity.as_slice()),
            (TAG_PEERS, self.peers.as_slice()),
        ]) {
            let value_len = u32::try_from(value.len()).map_err(|_| VaultErrors::TooLarge)?;
            out.push(tag);
            out.extend_from_slice(&value_len.to_le_bytes());
            out.extend_from_slice(value);
        }

        Ok(out)
    }

    /// Strict TLV decoding for `mode`: `a_key` first exactly in Standard
    /// mode, then every other tag exactly once, in order, nothing else.
    fn decode(bytes: &[u8], mode: Mode) -> Option<Self> {
        let (a_key, rest) = match mode {
            Mode::Standard => {
                let (a_key, rest) = take_entry(bytes, TAG_A_KEY)?;
                (Some(AuthKey::from_bytes(a_key.try_into().ok()?)), rest)
            }
            Mode::Enhanced => (None, bytes),
        };
        let (config, rest) = take_entry(rest, TAG_CONFIG)?;
        let (identity, rest) = take_entry(rest, TAG_IDENTITY)?;
        let (peers, rest) = take_entry(rest, TAG_PEERS)?;

        if !rest.is_empty() || config.len() > MAX_CONFIG_LEN || peers.len() > MAX_PEERS_LEN {
            return None;
        }

        // exact length, copied straight into a zeroizing buffer
        let identity: &[u8; IDENTITY_SEED_LEN] = identity.try_into().ok()?;
        let mut identity_seed = Zeroizing::new([0u8; IDENTITY_SEED_LEN]);
        identity_seed.copy_from_slice(identity);

        Some(Self {
            a_key,
            config: Zeroizing::new(config.to_vec()),
            identity: identity_seed,
            peers: Zeroizing::new(peers.to_vec()),
        })
    }
}

/// One `tag || len || value` entry with the expected tag.
fn take_entry(bytes: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (&found, rest) = bytes.split_first()?;
    if found != tag {
        return None;
    }

    let (len, rest) = rest.split_first_chunk::<4>()?;
    let len = usize::try_from(u32::from_le_bytes(*len)).ok()?;

    if len > rest.len() {
        return None;
    }

    Some(rest.split_at(len))
}

/// The wrapped DEK (public: a nonce and a ciphertext). It is bound to the
/// header it was made for (mode and salts are its AAD).
#[derive(Clone)]
pub struct WrappedDek([u8; WRAP_LEN]);

/// AAD of one layer: header (as written / as read) || label.
fn aad(header: &[u8; HEADER_LEN], label: &[u8]) -> Vec<u8> {
    [header.as_slice(), label].concat()
}

/// A fresh random DEK.
pub fn generate_dek() -> Result<Zeroizing<[u8; 32]>, VaultErrors> {
    random_array::<32>().map_err(|_| VaultErrors::Crypto)
}

/// Wraps the DEK with the KEK, for a file with `header`.
pub fn wrap_dek(
    header: &Header,
    kek: &[u8; 32],
    dek: &[u8; 32],
) -> Result<WrappedDek, VaultErrors> {
    let (ciphertext, nonce) = encrypt_with_aad(kek, dek, &aad(&header.to_bytes(), WRAP_LABEL))
        .map_err(|_| VaultErrors::Crypto)?;

    let mut out = [0u8; WRAP_LEN];
    let (n, c) = out.split_at_mut(NONCE_LEN);
    n.copy_from_slice(&nonce);
    if ciphertext.len() != c.len() {
        return Err(VaultErrors::Crypto);
    }
    c.copy_from_slice(&ciphertext);

    Ok(WrappedDek(out))
}

/// Builds the whole vault file: `header`, `wrapped` (made for that header),
/// contents encrypted with `dek`. The contents must fit the mode.
pub fn seal(
    header: &Header,
    wrapped: &WrappedDek,
    dek: &[u8; 32],
    contents: &VaultContents,
) -> Result<Vec<u8>, VaultErrors> {
    // a_key is stored exactly in Standard mode
    match (header.mode, &contents.a_key) {
        (Mode::Standard, Some(_)) | (Mode::Enhanced, None) => {}
        (Mode::Standard, None) | (Mode::Enhanced, Some(_)) => return Err(VaultErrors::WrongMode),
    }

    let encoded = contents.encode()?;
    let encoded_len = u32::try_from(encoded.len()).map_err(|_| VaultErrors::TooLarge)?;

    // len prefix + contents, rounded up to whole blocks (never empty)
    let used = encoded.len().saturating_add(4);
    let blocks = used.div_ceil(PAD_BLOCK).max(1);
    let padded_len = blocks.checked_mul(PAD_BLOCK).ok_or(VaultErrors::TooLarge)?;

    let mut plaintext = Zeroizing::new(Vec::with_capacity(padded_len));
    plaintext.extend_from_slice(&encoded_len.to_le_bytes());
    plaintext.extend_from_slice(&encoded);
    plaintext.resize(padded_len, 0);

    let head = header.to_bytes();
    let (ciphertext, nonce) = encrypt_with_aad(dek, &plaintext, &aad(&head, DATA_LABEL))
        .map_err(|_| VaultErrors::Crypto)?;

    let total = (HEADER_LEN + WRAP_LEN + NONCE_LEN).saturating_add(ciphertext.len());
    if u64::try_from(total).map_or(true, |t| t > MAX_VAULT_LEN) {
        return Err(VaultErrors::TooLarge);
    }

    let mut file = Vec::with_capacity(total);
    file.extend_from_slice(&head);
    file.extend_from_slice(&wrapped.0);
    file.extend_from_slice(&nonce);
    file.extend_from_slice(&ciphertext);

    Ok(file)
}

/// `len (u32 LE) || contents || zeros` -> contents. Strict: the length must
/// fit and every padding byte must be zero (nothing hidden after the contents).
fn unpad(plaintext: &[u8]) -> Option<&[u8]> {
    let (len, rest) = plaintext.split_first_chunk::<4>()?;
    let len = usize::try_from(u32::from_le_bytes(*len)).ok()?;
    if len > rest.len() {
        return None;
    }

    let (contents, padding) = rest.split_at(len);
    padding.iter().all(|&b| b == 0).then_some(contents)
}

/// What [`open`] returns: the header, the wrapped DEK (to re-seal without
/// re-wrapping), the DEK and the contents.
pub struct Opened {
    pub header: Header,
    pub wrapped: WrappedDek,
    pub dek: Zeroizing<[u8; 32]>,
    pub contents: VaultContents,
}

/// Opens a vault file with the KEK (derived from this file's header).
pub fn open(kek: &[u8; 32], file: &[u8]) -> Result<Opened, VaultErrors> {
    let header = read_header(file)?;

    let (head, rest) = file
        .split_first_chunk::<HEADER_LEN>()
        .ok_or(VaultErrors::Malformed)?;
    let (wrap, rest) = rest
        .split_first_chunk::<WRAP_LEN>()
        .ok_or(VaultErrors::Malformed)?;
    let (data_nonce, ciphertext) = rest
        .split_first_chunk::<NONCE_LEN>()
        .ok_or(VaultErrors::Malformed)?;

    // the ciphertext must be whole padded blocks plus the tag
    if ciphertext
        .len()
        .saturating_sub(TAG_LEN)
        .checked_rem(PAD_BLOCK)
        != Some(0)
    {
        return Err(VaultErrors::Malformed);
    }

    // 1. unwrap the DEK: the only place a wrong password shows
    let (wrap_nonce, wrapped_dek) = wrap
        .split_first_chunk::<NONCE_LEN>()
        .ok_or(VaultErrors::Malformed)?;
    let dek_bytes = decrypt_with_aad(kek, wrapped_dek, wrap_nonce, &aad(head, WRAP_LABEL))
        .map_err(|_| VaultErrors::WrongKey)?;
    let dek: Zeroizing<[u8; 32]> = Zeroizing::new(
        dek_bytes
            .as_slice()
            .try_into()
            .map_err(|_| VaultErrors::Corrupt)?,
    );

    // 2. decrypt and unpad the contents
    let plaintext = decrypt_with_aad(&dek, ciphertext, data_nonce, &aad(head, DATA_LABEL))
        .map_err(|_| VaultErrors::Corrupt)?;

    let encoded = unpad(&plaintext).ok_or(VaultErrors::Corrupt)?;
    let contents = VaultContents::decode(encoded, header.mode).ok_or(VaultErrors::Corrupt)?;

    Ok(Opened {
        header,
        wrapped: WrappedDek(*wrap),
        dek,
        contents,
    })
}

/* files */

/// The private data directory (`0700`, ours, not a symlink), created if needed:
/// macOS `~/Library/Application Support/cesaconn`, elsewhere
/// `$XDG_DATA_HOME/cesaconn` or `~/.local/share/cesaconn`.
pub fn data_dir() -> Result<PathBuf, VaultErrors> {
    let base = if cfg!(target_os = "macos") {
        std::env::var_os("HOME")
            .map(|h| PathBuf::from(h).join("Library").join("Application Support"))
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
    }
    .ok_or(VaultErrors::InsecureDirectory)?;

    prepare_dir(&base.join("cesaconn"))
}

/// Creates `dir` with `0700` if missing (parents as needed) and checks it is
/// private: a directory someone else made or opened up is refused.
pub fn prepare_dir(dir: &Path) -> Result<PathBuf, VaultErrors> {
    use std::os::unix::fs::DirBuilderExt;

    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent).map_err(|_| VaultErrors::Io)?;
    }

    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(VaultErrors::Io),
    }

    check_private_dir(dir).map_err(|_| VaultErrors::InsecureDirectory)?;

    Ok(dir.to_path_buf())
}

/// The vault file path inside `dir`.
pub fn vault_path(dir: &Path) -> PathBuf {
    dir.join(FILE_NAME)
}

/// Reads the vault file; `Ok(None)` if there is none. The directory is
/// re-checked, the file must be a regular file of ours, `0600`, and at most
/// [`MAX_VAULT_LEN`] bytes (checked before and while reading).
pub fn read_file(path: &Path) -> Result<Option<Vec<u8>>, VaultErrors> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    check_private_dir(path.parent().ok_or(VaultErrors::Io)?)
        .map_err(|_| VaultErrors::InsecureDirectory)?;

    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(VaultErrors::Io),
    };

    if !meta.file_type().is_file()
        || meta.uid() != nix::unistd::geteuid().as_raw()
        || meta.permissions().mode() & 0o077 != 0
    {
        return Err(VaultErrors::InsecureDirectory);
    }
    if meta.len() > MAX_VAULT_LEN {
        return Err(VaultErrors::TooLarge);
    }

    let file = std::fs::File::open(path).map_err(|_| VaultErrors::Io)?;
    let mut bytes = Vec::new();
    // bounded even if the file grows after the check
    file.take(MAX_VAULT_LEN.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| VaultErrors::Io)?;

    if u64::try_from(bytes.len()).map_or(true, |l| l > MAX_VAULT_LEN) {
        return Err(VaultErrors::TooLarge);
    }

    Ok(Some(bytes))
}

/// Writes the vault atomically: a new `0600` temp file in the same private
/// directory, fsynced, renamed over the old one, then the directory fsynced.
/// An error means the old file is still in place. Once the rename is done
/// the new file IS the vault, so a failed directory fsync only logs (see
/// [`after_replace`]): the caller must not keep its old state.
pub fn write_file_atomic(path: &Path, bytes: &[u8]) -> Result<(), VaultErrors> {
    use std::os::unix::fs::OpenOptionsExt;

    let dir = path.parent().ok_or(VaultErrors::Io)?;
    check_private_dir(dir).map_err(|_| VaultErrors::InsecureDirectory)?;

    let suffix = random_array::<8>().map_err(|_| VaultErrors::Crypto)?;
    let tmp_name: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
    let tmp = dir.join(format!(".{FILE_NAME}.{tmp_name}.tmp"));

    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|_| VaultErrors::Io)?;
        file.write_all(bytes).map_err(|_| VaultErrors::Io)?;
        file.sync_all().map_err(|_| VaultErrors::Io)?;
        std::fs::rename(&tmp, path).map_err(|_| VaultErrors::Io)
    })();

    if result.is_err() {
        // best effort: never leave a half-written temp file behind
        let _ = std::fs::remove_file(&tmp);
        return result;
    }

    after_replace(std::fs::File::open(dir).and_then(|d| d.sync_all()))
}

/// The outcome of a write or delete once the file was already replaced
/// (or removed): a failed directory fsync means only that a power cut
/// might still undo the change. Not an error: the change is on disk and
/// the daemon's state must follow it.
fn after_replace(dir_sync: std::io::Result<()>) -> Result<(), VaultErrors> {
    if dir_sync.is_err() {
        warn!("vault changed, but syncing its directory failed: a power cut might undo the change");
    }
    Ok(())
}

/// Deletes the vault file (a device reset); a missing file is not an error.
/// The directory is fsynced, so the deletion survives a crash.
pub fn delete_file(path: &Path) -> Result<(), VaultErrors> {
    let dir = path.parent().ok_or(VaultErrors::Io)?;
    check_private_dir(dir).map_err(|_| VaultErrors::InsecureDirectory)?;

    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(VaultErrors::Io),
    }

    after_replace(std::fs::File::open(dir).and_then(|d| d.sync_all()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(mode: Mode) -> Header {
        Header {
            mode,
            a_salt: Zeroizing::new([0x5A; 32]),
            d_salt: Zeroizing::new([0x5D; 32]),
            storage_salt: Zeroizing::new([0x55; 32]),
        }
    }

    fn contents(config: &[u8]) -> VaultContents {
        VaultContents {
            a_key: Some(AuthKey::from_bytes(&[0xA1; 32])),
            config: Zeroizing::new(config.to_vec()),
            identity: Zeroizing::new([0x1D; IDENTITY_SEED_LEN]),
            peers: Zeroizing::new(b"peer list".to_vec()),
        }
    }

    fn sealed(kek: &[u8; 32], config: &[u8]) -> Vec<u8> {
        let header = header(Mode::Standard);
        let dek = generate_dek().unwrap();
        let wrapped = wrap_dek(&header, kek, &dek).unwrap();
        seal(&header, &wrapped, &dek, &contents(config)).unwrap()
    }

    fn test_dir(name: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!("cesa-vault-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        prepare_dir(&base.join("data")).unwrap()
    }

    /// Test that a sealed vault opens with the right KEK and gives back everything
    #[test]
    fn test_seal_open_roundtrip() {
        let kek = [3u8; 32];
        let opened = open(&kek, &sealed(&kek, b"cfg")).unwrap();

        assert_eq!(**opened.contents.a_key.unwrap().expose(), [0xA1; 32]);
        assert_eq!(opened.contents.config.as_slice(), b"cfg");
        assert_eq!(*opened.contents.identity, [0x1D; IDENTITY_SEED_LEN]);
        assert_eq!(opened.contents.peers.as_slice(), b"peer list");
        assert_eq!(opened.header.mode, Mode::Standard);
        assert_eq!(*opened.header.a_salt, [0x5A; 32]);
        assert_eq!(*opened.header.d_salt, [0x5D; 32]);
        assert_eq!(*opened.header.storage_salt, [0x55; 32]);
    }

    /// Test that the header (mode and salts) reads back without any key,
    /// and that the salts sit in the file as documented
    #[test]
    fn test_header_readable_without_key() {
        let file = sealed(&[3u8; 32], b"");
        let read = read_header(&file).unwrap();

        assert_eq!(read.mode, Mode::Standard);
        assert_eq!(*read.a_salt, [0x5A; 32]);
        assert_eq!(*read.d_salt, [0x5D; 32]);
        assert_eq!(*read.storage_salt, [0x55; 32]);
        assert_eq!(
            file.get(..HEADER_LEN).unwrap(),
            header(Mode::Standard).to_bytes()
        );
    }

    /// Test that only vaults of the earlier versions 1 and 2 (salts in the
    /// keychain) are reported as outdated: any other version is unknown
    /// (never "reset this device"), another magic malformed
    #[test]
    fn test_other_versions() {
        let kek = [3u8; 32];
        for old in [1u8, 2] {
            let mut file = sealed(&kek, b"");
            file[8] = old;
            assert_eq!(read_header(&file).err(), Some(VaultErrors::Outdated));
            assert_eq!(open(&kek, &file).err(), Some(VaultErrors::Outdated));
        }

        for other in [0u8, VERSION + 1, u8::MAX] {
            let mut file = sealed(&kek, b"");
            file[8] = other;
            assert_eq!(read_header(&file).err(), Some(VaultErrors::UnknownVersion));
            assert_eq!(open(&kek, &file).err(), Some(VaultErrors::UnknownVersion));
        }
        // a truncated file of an unknown version isn't "outdated" either
        let short = [MAGIC.as_slice(), &[0u8]].concat();
        assert_eq!(read_header(&short).err(), Some(VaultErrors::UnknownVersion));

        let mut not_ours = sealed(&kek, b"");
        not_ours[0] ^= 1;
        assert_eq!(read_header(&not_ours).err(), Some(VaultErrors::Malformed));

        // an unknown mode byte
        let mut mode = sealed(&kek, b"");
        mode[9] = 2;
        assert_eq!(read_header(&mode).err(), Some(VaultErrors::Malformed));
    }

    /// Test Enhanced mode: a_key isn't in the file, the KEK needs both keys,
    /// and either key alone (or the Standard KEK) doesn't open it
    #[test]
    fn test_enhanced_mode() {
        let header = header(Mode::Enhanced);
        let a_key = AuthKey::from_bytes(&[0xA1; 32]);
        let d_key = DataKey::from_bytes(&[0xD1; 32]);
        let kek = derive_kek(&header, &d_key, Some(&a_key)).unwrap();

        let dek = generate_dek().unwrap();
        let wrapped = wrap_dek(&header, &kek, &dek).unwrap();
        let mut stored = contents(b"cfg");
        stored.a_key = None;
        let file = seal(&header, &wrapped, &dek, &stored).unwrap();

        assert!(!file.windows(32).any(|w| w == [0xA1; 32]));
        assert_eq!(read_header(&file).unwrap().mode, Mode::Enhanced);

        let opened = open(&kek, &file).unwrap();
        assert!(opened.contents.a_key.is_none());
        assert_eq!(opened.contents.config.as_slice(), b"cfg");

        // a wrong auth key or a wrong data key: wrong key
        let other_a = AuthKey::from_bytes(&[0xA2; 32]);
        let other_d = DataKey::from_bytes(&[0xD2; 32]);
        for kek in [
            derive_kek(&header, &d_key, Some(&other_a)).unwrap(),
            derive_kek(&header, &other_d, Some(&a_key)).unwrap(),
            // the Standard KEK of the same data key
            derive_kek(&header.with_mode(Mode::Standard), &d_key, None).unwrap(),
        ] {
            assert_eq!(open(&kek, &file).err(), Some(VaultErrors::WrongKey));
        }
    }

    /// Test that the KEK can't be derived for the wrong mode, and that
    /// contents that don't fit the mode are never sealed or opened
    #[test]
    fn test_mode_mismatch_refused() {
        let a_key = AuthKey::from_bytes(&[0xA1; 32]);
        let d_key = DataKey::from_bytes(&[0xD1; 32]);
        assert_eq!(
            derive_kek(&header(Mode::Standard), &d_key, Some(&a_key)).err(),
            Some(VaultErrors::WrongMode)
        );
        assert_eq!(
            derive_kek(&header(Mode::Enhanced), &d_key, None).err(),
            Some(VaultErrors::WrongMode)
        );

        let dek = generate_dek().unwrap();
        let enhanced = header(Mode::Enhanced);
        let wrapped = wrap_dek(&enhanced, &[1; 32], &dek).unwrap();
        // a_key in Enhanced mode
        assert_eq!(
            seal(&enhanced, &wrapped, &dek, &contents(b"")).err(),
            Some(VaultErrors::WrongMode)
        );
        // no a_key in Standard mode
        let standard = header(Mode::Standard);
        let mut no_key = contents(b"");
        no_key.a_key = None;
        assert_eq!(
            seal(&standard, &wrapped, &dek, &no_key).err(),
            Some(VaultErrors::WrongMode)
        );

        // a Standard file whose mode byte says Enhanced: the AAD fails
        let kek = [3u8; 32];
        let mut file = sealed(&kek, b"");
        file[9] = MODE_ENHANCED;
        assert_eq!(open(&kek, &file).err(), Some(VaultErrors::WrongKey));
    }

    /// Test that decoding is strict about the entries: wrong identity
    /// length, missing or reordered entries, trailing bytes, a_key for the
    /// wrong mode
    #[test]
    fn test_decode_strict_entries() {
        let good = contents(b"c").encode().unwrap();
        assert!(VaultContents::decode(&good, Mode::Standard).is_some());
        // Enhanced mode doesn't take an a_key entry
        assert!(VaultContents::decode(&good, Mode::Enhanced).is_none());

        let mut without_key = contents(b"c");
        without_key.a_key = None;
        let enhanced = without_key.encode().unwrap();
        assert!(VaultContents::decode(&enhanced, Mode::Enhanced).is_some());
        assert!(VaultContents::decode(&enhanced, Mode::Standard).is_none());

        let mut trailing = good.to_vec();
        trailing.push(0);
        assert!(VaultContents::decode(&trailing, Mode::Standard).is_none());

        // identity one byte short (entry length and value both shortened)
        let mut short = contents(b"c");
        short.peers = Zeroizing::new(Vec::new());
        let mut bytes = short.encode().unwrap().to_vec();
        let id_at = bytes
            .windows(5)
            .position(|w| w == [TAG_IDENTITY, 64, 0, 0, 0])
            .unwrap();
        bytes[id_at + 1] = 63;
        bytes.remove(id_at + 5);
        assert!(VaultContents::decode(&bytes, Mode::Standard).is_none());

        // identity one byte long
        let mut bytes = short.encode().unwrap().to_vec();
        let id_at = bytes
            .windows(5)
            .position(|w| w == [TAG_IDENTITY, 64, 0, 0, 0])
            .unwrap();
        bytes[id_at + 1] = 65;
        bytes.insert(id_at + 5, 0);
        assert!(VaultContents::decode(&bytes, Mode::Standard).is_none());

        // peers entry missing
        let cut = good.windows(1).rposition(|w| w == [TAG_PEERS]).unwrap();
        assert!(VaultContents::decode(&good[..cut], Mode::Standard).is_none());
    }

    /// Test that a wrong KEK (wrong data password) is reported as such
    #[test]
    fn test_wrong_key() {
        let file = sealed(&[3u8; 32], b"");
        assert_eq!(open(&[4u8; 32], &file).err(), Some(VaultErrors::WrongKey));
    }

    /// Test that flipping any single byte anywhere in the file is caught,
    /// the salts and the mode in the header included
    #[test]
    fn test_every_byte_is_authenticated() {
        let kek = [3u8; 32];
        let file = sealed(&kek, b"x");

        for i in 0..file.len() {
            let mut bad = file.clone();
            bad[i] ^= 0x01;
            assert!(open(&kek, &bad).is_err(), "byte {i} not authenticated");
        }
    }

    /// Test that truncated, extended and oversized files are refused
    #[test]
    fn test_bad_lengths() {
        let kek = [3u8; 32];
        let file = sealed(&kek, b"");

        assert_eq!(
            open(&kek, &file[..file.len() - 1]).err(),
            Some(VaultErrors::Malformed)
        );
        assert_eq!(open(&kek, &[]).err(), Some(VaultErrors::Malformed));
        assert_eq!(
            read_header(&file[..HEADER_LEN]).err(),
            Some(VaultErrors::Malformed)
        );
        let mut longer = file.clone();
        longer.push(0);
        assert!(open(&kek, &longer).is_err());
        let huge = vec![0u8; usize::try_from(MAX_VAULT_LEN).unwrap() + 1];
        assert_eq!(open(&kek, &huge).err(), Some(VaultErrors::TooLarge));
    }

    /// Test that the file size doesn't depend on how much is inside
    #[test]
    fn test_padding_hides_size() {
        let kek = [3u8; 32];
        assert_eq!(sealed(&kek, b"").len(), sealed(&kek, &[7u8; 2000]).len());
    }

    /// Test that no secret appears in the file in plaintext (the salts in
    /// the header are public by design)
    #[test]
    fn test_no_plaintext_secrets_on_disk() {
        let kek = [3u8; 32];
        let file = sealed(&kek, b"listen_port=3232");

        for secret in [
            [0xA1u8; 32].as_slice(),
            &[0x1D; IDENTITY_SEED_LEN],
            b"listen_port",
            b"peer list",
        ] {
            assert!(!file.windows(secret.len()).any(|w| w == secret));
        }
    }

    /// Test that the DEK re-wrapped under a new KEK opens the same contents
    /// (a password or mode change re-wraps 32 bytes only)
    #[test]
    fn test_rewrap() {
        let header = header(Mode::Standard);
        let dek = generate_dek().unwrap();
        let old = wrap_dek(&header, &[1u8; 32], &dek).unwrap();
        let file = seal(&header, &old, &dek, &contents(b"c")).unwrap();
        let opened = open(&[1u8; 32], &file).unwrap();

        let new = wrap_dek(&opened.header, &[2u8; 32], &opened.dek).unwrap();
        let file = seal(&opened.header, &new, &opened.dek, &opened.contents).unwrap();

        assert!(open(&[1u8; 32], &file).is_err());
        assert_eq!(
            open(&[2u8; 32], &file).unwrap().contents.config.as_slice(),
            b"c"
        );
    }

    /// Test that a DEK wrapped for one header doesn't open under another
    /// (other mode or other salts): the wrap is bound to the header
    #[test]
    fn test_wrap_bound_to_header() {
        let kek = [3u8; 32];
        let dek = generate_dek().unwrap();
        let wrapped = wrap_dek(&header(Mode::Standard), &kek, &dek).unwrap();

        let mut other_salt = header(Mode::Standard);
        other_salt.d_salt = Zeroizing::new([0x77; 32]);
        let file = seal(&other_salt, &wrapped, &dek, &contents(b"")).unwrap();
        assert_eq!(open(&kek, &file).err(), Some(VaultErrors::WrongKey));
    }

    /// Test that the KEK depends on d_key, the storage salt and the mode,
    /// isn't d_key, and in Enhanced mode depends on a_key too
    #[test]
    fn test_kek_derivation() {
        let standard = header(Mode::Standard);
        let d_key = DataKey::from_bytes(&[9; 32]);
        let kek = derive_kek(&standard, &d_key, None).unwrap();

        assert_ne!(*kek, [9; 32]);
        let mut other_salt = header(Mode::Standard);
        other_salt.storage_salt = Zeroizing::new([2; 32]);
        assert_ne!(*kek, *derive_kek(&other_salt, &d_key, None).unwrap());
        assert_ne!(
            *kek,
            *derive_kek(&standard, &DataKey::from_bytes(&[8; 32]), None).unwrap()
        );
        assert_eq!(*kek, *derive_kek(&standard, &d_key, None).unwrap());

        let enhanced = header(Mode::Enhanced);
        let a_key = AuthKey::from_bytes(&[7; 32]);
        let both = derive_kek(&enhanced, &d_key, Some(&a_key)).unwrap();
        assert_ne!(*both, *kek);
        assert_ne!(
            *both,
            *derive_kek(&enhanced, &d_key, Some(&AuthKey::from_bytes(&[6; 32]))).unwrap()
        );
        // the two keys aren't interchangeable
        assert_ne!(
            *both,
            *derive_kek(
                &enhanced,
                &DataKey::from_bytes(&[7; 32]),
                Some(&AuthKey::from_bytes(&[9; 32]))
            )
            .unwrap()
        );
    }

    /// Test that the Enhanced KEK runs Argon2 over both keys before HKDF, so
    /// a guessed pair can't be tested with a cheap HKDF of two keys derived
    /// once each (the reference is built by hand from the documented steps)
    #[test]
    fn test_enhanced_kek_runs_argon2() {
        let enhanced = header(Mode::Enhanced);
        let d_key = DataKey::from_bytes(&[9; 32]);
        let a_key = AuthKey::from_bytes(&[7; 32]);
        let kek = derive_kek(&enhanced, &d_key, Some(&a_key)).unwrap();

        let ikm = [[9u8; 32], [7u8; 32]].concat();
        let salt = Some(enhanced.storage_salt.as_slice());
        let mut cheap = [0u8; 32];
        SimpleHkdf::<Blake2s256>::new(salt, &ikm)
            .expand(KEK_BOTH_LABEL, &mut cheap)
            .unwrap();
        assert_ne!(*kek, cheap, "the pair must not be testable with HKDF alone");

        let both = derive_key(&ikm, &enhanced.storage_salt).unwrap();
        let mut expected = [0u8; 32];
        SimpleHkdf::<Blake2s256>::new(salt, both.as_slice())
            .expand(KEK_BOTH_LABEL, &mut expected)
            .unwrap();
        assert_eq!(*kek, expected);
    }

    /// Test that a failed directory fsync after the file was replaced isn't
    /// reported as a failed save (the new file is the vault already)
    #[test]
    fn test_after_replace_is_saved() {
        assert_eq!(after_replace(Ok(())), Ok(()));
        let failed = std::io::Error::other("fsync failed");
        assert_eq!(after_replace(Err(failed)), Ok(()));
    }

    /// Test that unpadding is strict: length must fit, padding must be zeros
    #[test]
    fn test_unpad_strict() {
        assert_eq!(unpad(&[2, 0, 0, 0, 7, 8, 0, 0]), Some([7u8, 8].as_slice()));
        assert_eq!(unpad(&[2, 0, 0, 0, 7, 8]), Some([7u8, 8].as_slice()));
        // non-zero byte hidden in the padding
        assert_eq!(unpad(&[2, 0, 0, 0, 7, 8, 0, 1]), None);
        // length past the end
        assert_eq!(unpad(&[9, 0, 0, 0, 7, 8]), None);
        assert_eq!(unpad(&[1, 0, 0]), None);
    }

    /// Test that a changed header is refused even if the explicit header
    /// checks were missing: the AAD is the header as read
    #[test]
    fn test_header_bound_by_aad() {
        let kek = [3u8; 32];
        let mut file = sealed(&kek, b"");
        // a salt byte: the header still parses
        file[HEADER_LEN - 1] ^= 1;
        assert!(read_header(&file).is_ok());

        let (head, rest) = file.split_first_chunk::<HEADER_LEN>().unwrap();
        let (wrap, _) = rest.split_first_chunk::<WRAP_LEN>().unwrap();
        let (nonce, wrapped) = wrap.split_first_chunk::<NONCE_LEN>().unwrap();
        assert!(decrypt_with_aad(&kek, wrapped, nonce, &aad(head, WRAP_LABEL)).is_err());
    }

    /// Test that oversized config is refused instead of written
    #[test]
    fn test_config_limit() {
        let header = header(Mode::Standard);
        let dek = generate_dek().unwrap();
        let wrapped = wrap_dek(&header, &[1; 32], &dek).unwrap();
        assert_eq!(
            seal(
                &header,
                &wrapped,
                &dek,
                &contents(&vec![0; MAX_CONFIG_LEN + 1])
            )
            .err(),
            Some(VaultErrors::TooLarge)
        );

        let mut many_peers = contents(b"");
        many_peers.peers = Zeroizing::new(vec![0; MAX_PEERS_LEN + 1]);
        assert_eq!(
            seal(&header, &wrapped, &dek, &many_peers).err(),
            Some(VaultErrors::TooLarge)
        );
    }

    /// Test that a reset deletes the vault file and that a missing one is fine
    #[test]
    fn test_file_delete() {
        let dir = test_dir("delete");
        let path = vault_path(&dir);

        // nothing there: not an error
        assert_eq!(delete_file(&path), Ok(()));

        write_file_atomic(&path, b"secret").unwrap();
        assert_eq!(delete_file(&path), Ok(()));
        assert_eq!(read_file(&path), Ok(None));
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    }

    /// Test the file side: atomic write is 0600, reads back, no temp left,
    /// and a file others can read or a symlink is refused
    #[test]
    fn test_file_write_read() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_dir("file");
        let path = vault_path(&dir);

        assert_eq!(read_file(&path), Ok(None));

        write_file_atomic(&path, b"one").unwrap();
        write_file_atomic(&path, b"two").unwrap();
        assert_eq!(read_file(&path).unwrap().unwrap(), b"two");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(read_file(&path), Err(VaultErrors::InsecureDirectory));

        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("/etc/hosts", &path).unwrap();
        assert_eq!(read_file(&path), Err(VaultErrors::InsecureDirectory));

        std::fs::remove_dir_all(dir.parent().unwrap()).unwrap();
    }

    /// Test that a data directory others can open is refused
    #[test]
    fn test_dir_must_be_private() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_dir("perm");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert_eq!(
            prepare_dir(&dir).err(),
            Some(VaultErrors::InsecureDirectory)
        );
        assert_eq!(
            write_file_atomic(&vault_path(&dir), b"x").err(),
            Some(VaultErrors::InsecureDirectory)
        );

        std::fs::remove_dir_all(dir.parent().unwrap()).unwrap();
    }
}
