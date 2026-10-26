/*
TODO:
device identity (DeviceKeypairs) and the trusted peers go into the vault once the daemon starts the networker
*/

//! The encrypted vault: everything the daemon keeps across restarts.
//! Nothing is stored unencrypted, configs included.
//!
//! Envelope encryption:
//! * `KEK = HKDF-BLAKE2s(ikm = d_key, salt = storage salt, info = KEK_LABEL)`.
//!   The KEK never uses `d_key` directly, and it is useless on the network.
//! * A random DEK encrypts the payload. The KEK only wraps the DEK, so changing
//!   the data password re-wraps 32 bytes.
//! * The salts (`d_salt`, storage salt) live in the OS keychain, never here.
//!
//! File layout, all AES-256-GCM:
//! ```text
//! MAGIC (8) || VERSION (1)                        header, AAD of both layers
//! wrap nonce (12) || wrapped DEK (32 + 16)        AAD = header || WRAP_LABEL
//! data nonce (12) || ciphertext (n * PAD_BLOCK + 16)  AAD = header || DATA_LABEL
//! ```
//! The plaintext of the data layer is `contents len (u32 LE) || contents ||
//! zeros`, padded to whole [`PAD_BLOCK`]s, so the file size doesn't tell how
//! much is inside. The only plaintext on disk is format metadata.

use core::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use blake2::Blake2s256;
use hkdf::SimpleHkdf;
use zeroize::Zeroizing;

use cesa_conn_crypto::{
    aes::{decrypt_with_aad, encrypt_with_aad},
    crand::random_array,
};
use cesa_conn_system::ipc::check_private_dir;

use crate::auth_snow::{AuthKey, DataKey, IDENTITY_SEED_LEN};

/* format constants */
/// File magic.
const MAGIC: &[u8; 8] = b"CESAVLT\0";
/// Format version.
const VERSION: u8 = 2;
/// -> magic (8) + version (1)
const HEADER_LEN: usize = 9;
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

/* domain separation */
const KEK_LABEL: &[u8] = b"cesaconn-storage-v1";
const WRAP_LABEL: &[u8] = b"cesaconn-vault-dek";
const DATA_LABEL: &[u8] = b"cesaconn-vault-data";

/* contents (TLV inside the data layer): tag (1) || len (u32 LE) || value */
const TAG_A_KEY: u8 = 0x01;
const TAG_A_SALT: u8 = 0x02;
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
    /// The file is not a vault of this version, or its layout is wrong.
    Malformed,
    /// The DEK didn't unwrap: wrong data password (or a swapped header).
    WrongKey,
    /// The DEK unwrapped but the contents didn't decrypt or parse: damaged.
    Corrupt,
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
            VaultErrors::Malformed => write!(f, "not a vault file of this version"),
            VaultErrors::WrongKey => write!(f, "wrong data password"),
            VaultErrors::Corrupt => write!(f, "vault contents are damaged"),
            VaultErrors::TooLarge => write!(f, "vault is too large"),
            VaultErrors::Crypto => write!(f, "vault cryptography failed"),
            VaultErrors::Io => write!(f, "failed to read or write the vault"),
            VaultErrors::InsecureDirectory => write!(f, "vault directory is not private"),
        }
    }
}

/// The two keychain salts. No `Debug`/`Clone`; wiped on drop.
pub struct Salts {
    /// Argon2 salt of the data password.
    pub d_salt: Zeroizing<[u8; 32]>,
    /// HKDF salt of the KEK.
    pub storage_salt: Zeroizing<[u8; 32]>,
}

impl Salts {
    /// `d_salt || storage salt`, as stored in the keychain.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 64]> {
        let mut out = Zeroizing::new([0u8; 64]);
        let (d, s) = out.split_at_mut(32);
        d.copy_from_slice(self.d_salt.as_slice());
        s.copy_from_slice(self.storage_salt.as_slice());
        out
    }

    /// Parses exactly 64 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (d, s) = bytes.split_first_chunk::<32>()?;
        let s: &[u8; 32] = s.try_into().ok()?;

        Some(Self {
            d_salt: Zeroizing::new(*d),
            storage_salt: Zeroizing::new(*s),
        })
    }
}

/// `KEK = HKDF-BLAKE2s(ikm = d_key, salt = storage salt, info = KEK_LABEL)`.
pub fn derive_kek(
    d_key: &DataKey,
    storage_salt: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, VaultErrors> {
    let mut kek = Zeroizing::new([0u8; 32]);

    SimpleHkdf::<Blake2s256>::new(Some(storage_salt.as_slice()), d_key.expose().as_slice())
        .expand(KEK_LABEL, kek.as_mut_slice())
        .map_err(|_| VaultErrors::Crypto)?;

    Ok(kek)
}

/// Everything the vault holds. No `Debug`/`Clone`; wiped on drop.
pub struct VaultContents {
    pub a_key: AuthKey,
    pub a_salt: Zeroizing<[u8; 32]>,
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

        // five entries of tag (1) + len (4), the values
        let len = (5 * 5 + 32 + 32 + IDENTITY_SEED_LEN)
            .saturating_add(self.config.len())
            .saturating_add(self.peers.len());
        let mut out = Zeroizing::new(Vec::with_capacity(len));

        for (tag, value) in [
            (TAG_A_KEY, self.a_key.expose().as_slice()),
            (TAG_A_SALT, self.a_salt.as_slice()),
            (TAG_CONFIG, self.config.as_slice()),
            (TAG_IDENTITY, self.identity.as_slice()),
            (TAG_PEERS, self.peers.as_slice()),
        ] {
            let value_len = u32::try_from(value.len()).map_err(|_| VaultErrors::TooLarge)?;
            out.push(tag);
            out.extend_from_slice(&value_len.to_le_bytes());
            out.extend_from_slice(value);
        }

        Ok(out)
    }

    /// Strict TLV decoding: every tag exactly once, in order, nothing else.
    fn decode(bytes: &[u8]) -> Option<Self> {
        let (a_key, rest) = take_entry(bytes, TAG_A_KEY)?;
        let (a_salt, rest) = take_entry(rest, TAG_A_SALT)?;
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
            a_key: AuthKey::from_bytes(a_key.try_into().ok()?),
            a_salt: Zeroizing::new(a_salt.try_into().ok()?),
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

/// The wrapped DEK (public: a nonce and a ciphertext).
#[derive(Clone)]
pub struct WrappedDek([u8; WRAP_LEN]);

fn header() -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    let (magic, version) = header.split_at_mut(MAGIC.len());
    magic.copy_from_slice(MAGIC);
    version.fill(VERSION);
    header
}

/// AAD of one layer: header (as written / as read) || label.
fn aad(header: &[u8; HEADER_LEN], label: &[u8]) -> Vec<u8> {
    [header.as_slice(), label].concat()
}

/// A fresh random DEK.
pub fn generate_dek() -> Result<Zeroizing<[u8; 32]>, VaultErrors> {
    random_array::<32>().map_err(|_| VaultErrors::Crypto)
}

/// Wraps the DEK with the KEK.
pub fn wrap_dek(kek: &[u8; 32], dek: &[u8; 32]) -> Result<WrappedDek, VaultErrors> {
    let (ciphertext, nonce) =
        encrypt_with_aad(kek, dek, &aad(&header(), WRAP_LABEL)).map_err(|_| VaultErrors::Crypto)?;

    let mut out = [0u8; WRAP_LEN];
    let (n, c) = out.split_at_mut(NONCE_LEN);
    n.copy_from_slice(&nonce);
    if ciphertext.len() != c.len() {
        return Err(VaultErrors::Crypto);
    }
    c.copy_from_slice(&ciphertext);

    Ok(WrappedDek(out))
}

/// Builds the whole vault file: header, `wrapped`, contents encrypted with `dek`.
pub fn seal(
    wrapped: &WrappedDek,
    dek: &[u8; 32],
    contents: &VaultContents,
) -> Result<Vec<u8>, VaultErrors> {
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

    let (ciphertext, nonce) = encrypt_with_aad(dek, &plaintext, &aad(&header(), DATA_LABEL))
        .map_err(|_| VaultErrors::Crypto)?;

    let total = (HEADER_LEN + WRAP_LEN + NONCE_LEN).saturating_add(ciphertext.len());
    if u64::try_from(total).map_or(true, |t| t > MAX_VAULT_LEN) {
        return Err(VaultErrors::TooLarge);
    }

    let mut file = Vec::with_capacity(total);
    file.extend_from_slice(&header());
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

/// What [`open`] returns: the wrapped DEK (to re-seal without re-wrapping),
/// the DEK and the contents.
pub struct Opened {
    pub wrapped: WrappedDek,
    pub dek: Zeroizing<[u8; 32]>,
    pub contents: VaultContents,
}

/// Opens a vault file with the KEK.
pub fn open(kek: &[u8; 32], file: &[u8]) -> Result<Opened, VaultErrors> {
    if u64::try_from(file.len()).map_or(true, |l| l > MAX_VAULT_LEN) {
        return Err(VaultErrors::TooLarge);
    }
    if file.len() < MIN_VAULT_LEN {
        return Err(VaultErrors::Malformed);
    }

    let (head, rest) = file
        .split_first_chunk::<HEADER_LEN>()
        .ok_or(VaultErrors::Malformed)?;
    if *head != header() {
        return Err(VaultErrors::Malformed);
    }

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
    let contents = VaultContents::decode(encoded).ok_or(VaultErrors::Corrupt)?;

    Ok(Opened {
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
        std::fs::rename(&tmp, path).map_err(|_| VaultErrors::Io)?;
        std::fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(|_| VaultErrors::Io)
    })();

    if result.is_err() {
        // best effort: never leave a half-written temp file behind
        let _ = std::fs::remove_file(&tmp);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contents(config: &[u8]) -> VaultContents {
        VaultContents {
            a_key: AuthKey::from_bytes(&[0xA1; 32]),
            a_salt: Zeroizing::new([0xA5; 32]),
            config: Zeroizing::new(config.to_vec()),
            identity: Zeroizing::new([0x1D; IDENTITY_SEED_LEN]),
            peers: Zeroizing::new(b"peer list".to_vec()),
        }
    }

    fn sealed(kek: &[u8; 32], config: &[u8]) -> Vec<u8> {
        let dek = generate_dek().unwrap();
        let wrapped = wrap_dek(kek, &dek).unwrap();
        seal(&wrapped, &dek, &contents(config)).unwrap()
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

        assert_eq!(**opened.contents.a_key.expose(), [0xA1; 32]);
        assert_eq!(*opened.contents.a_salt, [0xA5; 32]);
        assert_eq!(opened.contents.config.as_slice(), b"cfg");
        assert_eq!(*opened.contents.identity, [0x1D; IDENTITY_SEED_LEN]);
        assert_eq!(opened.contents.peers.as_slice(), b"peer list");
    }

    /// Test that a vault of the previous version (no identity) is refused as
    /// "not a vault of this version", not misread
    #[test]
    fn test_old_version_refused() {
        let kek = [3u8; 32];
        let mut file = sealed(&kek, b"");
        file[HEADER_LEN - 1] = 1;
        assert_eq!(open(&kek, &file).err(), Some(VaultErrors::Malformed));
    }

    /// Test that decoding is strict about the new entries: wrong identity
    /// length, missing or reordered entries, trailing bytes
    #[test]
    fn test_decode_strict_entries() {
        let good = contents(b"c").encode().unwrap();
        assert!(VaultContents::decode(&good).is_some());

        let mut trailing = good.to_vec();
        trailing.push(0);
        assert!(VaultContents::decode(&trailing).is_none());

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
        assert!(VaultContents::decode(&bytes).is_none());

        // identity one byte long
        let mut bytes = short.encode().unwrap().to_vec();
        let id_at = bytes
            .windows(5)
            .position(|w| w == [TAG_IDENTITY, 64, 0, 0, 0])
            .unwrap();
        bytes[id_at + 1] = 65;
        bytes.insert(id_at + 5, 0);
        assert!(VaultContents::decode(&bytes).is_none());

        // peers entry missing
        let cut = good.windows(1).rposition(|w| w == [TAG_PEERS]).unwrap();
        assert!(VaultContents::decode(&good[..cut]).is_none());
    }

    /// Test that a wrong KEK (wrong data password) is reported as such
    #[test]
    fn test_wrong_key() {
        let file = sealed(&[3u8; 32], b"");
        assert_eq!(open(&[4u8; 32], &file).err(), Some(VaultErrors::WrongKey));
    }

    /// Test that flipping any single byte anywhere in the file is caught
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

    /// Test that no secret appears in the file in plaintext
    #[test]
    fn test_no_plaintext_secrets_on_disk() {
        let kek = [3u8; 32];
        let file = sealed(&kek, b"listen_port=3232");

        for secret in [
            [0xA1u8; 32].as_slice(),
            &[0xA5u8; 32],
            &[0x1D; IDENTITY_SEED_LEN],
            b"listen_port",
            b"peer list",
        ] {
            assert!(!file.windows(secret.len()).any(|w| w == secret));
        }
    }

    /// Test that the DEK re-wrapped under a new KEK opens the same contents
    /// (data password change re-wraps 32 bytes only)
    #[test]
    fn test_rewrap() {
        let dek = generate_dek().unwrap();
        let old = wrap_dek(&[1u8; 32], &dek).unwrap();
        let file = seal(&old, &dek, &contents(b"c")).unwrap();
        let opened = open(&[1u8; 32], &file).unwrap();

        let new = wrap_dek(&[2u8; 32], &opened.dek).unwrap();
        let file = seal(&new, &opened.dek, &opened.contents).unwrap();

        assert!(open(&[1u8; 32], &file).is_err());
        assert_eq!(
            open(&[2u8; 32], &file).unwrap().contents.config.as_slice(),
            b"c"
        );
    }

    /// Test that the KEK depends on both d_key and the storage salt, and isn't d_key
    #[test]
    fn test_kek_derivation() {
        let d_key = DataKey::from_bytes(&[9; 32]);
        let kek = derive_kek(&d_key, &[1; 32]).unwrap();

        assert_ne!(*kek, [9; 32]);
        assert_ne!(*kek, *derive_kek(&d_key, &[2; 32]).unwrap());
        assert_ne!(
            *kek,
            *derive_kek(&DataKey::from_bytes(&[8; 32]), &[1; 32]).unwrap()
        );
        assert_eq!(*kek, *derive_kek(&d_key, &[1; 32]).unwrap());
    }

    /// Test that the keychain salt blob round-trips and only 64 bytes parse
    #[test]
    fn test_salts_bytes() {
        let salts = Salts {
            d_salt: random_array::<32>().unwrap(),
            storage_salt: random_array::<32>().unwrap(),
        };
        let back = Salts::from_bytes(salts.to_bytes().as_slice()).unwrap();

        assert_eq!(*back.d_salt, *salts.d_salt);
        assert_eq!(*back.storage_salt, *salts.storage_salt);
        assert!(Salts::from_bytes(&[0; 63]).is_none());
        assert!(Salts::from_bytes(&[0; 65]).is_none());
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

    /// Test that a different version byte is refused even if the explicit
    /// header check were missing: the AAD is the header as read
    #[test]
    fn test_header_bound_by_aad() {
        let kek = [3u8; 32];
        let mut file = sealed(&kek, b"");
        file[HEADER_LEN - 1] = VERSION.wrapping_add(1);

        let (head, rest) = file.split_first_chunk::<HEADER_LEN>().unwrap();
        let (wrap, _) = rest.split_first_chunk::<WRAP_LEN>().unwrap();
        let (nonce, wrapped) = wrap.split_first_chunk::<NONCE_LEN>().unwrap();
        assert!(decrypt_with_aad(&kek, wrapped, nonce, &aad(head, WRAP_LABEL)).is_err());
    }

    /// Test that oversized config is refused instead of written
    #[test]
    fn test_config_limit() {
        let dek = generate_dek().unwrap();
        let wrapped = wrap_dek(&[1; 32], &dek).unwrap();
        assert_eq!(
            seal(&wrapped, &dek, &contents(&vec![0; MAX_CONFIG_LEN + 1])).err(),
            Some(VaultErrors::TooLarge)
        );

        let mut many_peers = contents(b"");
        many_peers.peers = Zeroizing::new(vec![0; MAX_PEERS_LEN + 1]);
        assert_eq!(
            seal(&wrapped, &dek, &many_peers).err(),
            Some(VaultErrors::TooLarge)
        );
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
