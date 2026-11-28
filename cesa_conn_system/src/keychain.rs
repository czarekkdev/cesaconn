//! OS keychain access for the daemon's one keychain item.
//!
//! The vault doesn't need the keychain (its salts are in its own header).
//! The only item is [`Item::DataKey`]: `d_key (32)`, kept only while the
//! user has opted in to automatic login, after a warning that its security
//! then rests on the OS.
//!
//! macOS: the login keychain, never iCloud-synchronised. The stricter data
//! protection keychain (`WhenUnlockedThisDeviceOnly`) needs the entitlement that
//! comes with release signing; switching to it is part of release signing.
//! Other platforms: not supported yet ([`KeychainErrors::Unsupported`]), so
//! there is no automatic login there (the vault works the same).
//!
//! Values come back in `Zeroizing` buffers. The copy inside the Security
//! framework (a `CFData`) is released by the OS and can't be wiped from here.

use core::fmt;
use zeroize::Zeroizing;

/// Keychain service name of every CesaConn item.
pub const SERVICE: &str = "dev.czarekk.cesaconn";

/// The items the daemon keeps in the keychain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Item {
    /// `d_key` (32 bytes), automatic login only.
    DataKey,
}

impl Item {
    /// Keychain account name of the item.
    pub fn account(self) -> &'static str {
        match self {
            Item::DataKey => "data-key",
        }
    }
}

/// All errors of the keychain layer.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum KeychainErrors {
    /// No supported keychain on this platform.
    Unsupported,
    /// The keychain refused or failed the operation (locked, denied, ...).
    Failed,
}

impl fmt::Display for KeychainErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeychainErrors::Unsupported => write!(f, "no supported OS keychain on this platform"),
            KeychainErrors::Failed => write!(f, "the OS keychain refused the operation"),
        }
    }
}

/// Where the daemon keeps keychain items. A trait so tests can use memory.
pub trait SecretStore: Send + Sync {
    /// Whether this store can keep anything on this platform at all (a
    /// switch that needs it is shown as unavailable otherwise).
    fn supported(&self) -> bool;
    /// The item's value, or `None` if it doesn't exist.
    fn get(&self, item: Item) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainErrors>;
    /// Creates or replaces the item.
    fn set(&self, item: Item, secret: &[u8]) -> Result<(), KeychainErrors>;
    /// Removes the item; removing a missing item is not an error.
    fn delete(&self, item: Item) -> Result<(), KeychainErrors>;
}

/// The OS keychain.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsKeychain;

#[cfg(target_os = "macos")]
mod macos {
    use super::{Item, KeychainErrors, SERVICE};
    use security_framework::passwords::{
        PasswordOptions, delete_generic_password_options, generic_password,
        set_generic_password_options,
    };
    use zeroize::Zeroizing;

    /// errSecItemNotFound
    const ITEM_NOT_FOUND: i32 = -25300;

    fn options(item: Item) -> PasswordOptions {
        let mut options = PasswordOptions::new_generic_password(SERVICE, item.account());
        // never in iCloud Keychain: these items stay on this device
        options.set_access_synchronized(Some(false));
        options
    }

    pub fn get(item: Item) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainErrors> {
        match generic_password(options(item)) {
            Ok(value) => Ok(Some(Zeroizing::new(value))),
            Err(e) if e.code() == ITEM_NOT_FOUND => Ok(None),
            Err(_) => Err(KeychainErrors::Failed),
        }
    }

    pub fn set(item: Item, secret: &[u8]) -> Result<(), KeychainErrors> {
        let mut options = options(item);
        options.set_label("CesaConn");
        set_generic_password_options(secret, options).map_err(|_| KeychainErrors::Failed)
    }

    pub fn delete(item: Item) -> Result<(), KeychainErrors> {
        match delete_generic_password_options(options(item)) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == ITEM_NOT_FOUND => Ok(()),
            Err(_) => Err(KeychainErrors::Failed),
        }
    }
}

#[cfg(target_os = "macos")]
impl SecretStore for OsKeychain {
    fn supported(&self) -> bool {
        true
    }

    fn get(&self, item: Item) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainErrors> {
        macos::get(item)
    }

    fn set(&self, item: Item, secret: &[u8]) -> Result<(), KeychainErrors> {
        macos::set(item, secret)
    }

    fn delete(&self, item: Item) -> Result<(), KeychainErrors> {
        macos::delete(item)
    }
}

/// No supported keychain here yet: every operation fails, nothing is stored.
#[cfg(not(target_os = "macos"))]
impl SecretStore for OsKeychain {
    fn supported(&self) -> bool {
        false
    }

    fn get(&self, _item: Item) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainErrors> {
        Err(KeychainErrors::Unsupported)
    }

    fn set(&self, _item: Item, _secret: &[u8]) -> Result<(), KeychainErrors> {
        Err(KeychainErrors::Unsupported)
    }

    fn delete(&self, _item: Item) -> Result<(), KeychainErrors> {
        Err(KeychainErrors::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that the item keeps the account name it always had, so a key
    /// saved by an earlier build is still found (and removed by a reset)
    #[test]
    fn test_item_account_name() {
        assert_eq!(Item::DataKey.account(), "data-key");
    }

    /// Test the real macOS keychain: set, get, replace, delete, delete again.
    /// Ignored by default: it writes to the login keychain (run by hand).
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "writes to the real login keychain"]
    fn test_os_keychain_roundtrip() {
        let store = OsKeychain;
        let item = Item::DataKey;

        store.delete(item).unwrap();
        assert_eq!(store.get(item).unwrap(), None);

        store.set(item, &[1; 32]).unwrap();
        assert_eq!(store.get(item).unwrap().unwrap().as_slice(), &[1; 32]);

        store.set(item, &[2; 32]).unwrap();
        assert_eq!(store.get(item).unwrap().unwrap().as_slice(), &[2; 32]);

        store.delete(item).unwrap();
        store.delete(item).unwrap();
        assert_eq!(store.get(item).unwrap(), None);
    }

    /// Test that without a keychain backend nothing pretends to work
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn test_unsupported_platform_fails() {
        assert!(!OsKeychain.supported());
        assert_eq!(
            OsKeychain.get(Item::DataKey),
            Err(KeychainErrors::Unsupported)
        );
        assert_eq!(
            OsKeychain.set(Item::DataKey, &[0; 32]),
            Err(KeychainErrors::Unsupported)
        );
    }
}
