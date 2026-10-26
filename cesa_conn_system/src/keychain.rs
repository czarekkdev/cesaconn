//! OS keychain access for the daemon's few keychain items.
//!
//! Only two items exist, both owned by the daemon:
//! * [`Item::Salts`]: `d_salt (32) || storage salt (32)`. Without them the
//!   encrypted vault can't be opened even with the right password.
//! * [`Item::DataKey`]: `d_key (32)`, only with automatic login enabled.
//!
//! macOS: the login keychain, never iCloud-synchronised. The stricter data
//! protection keychain (`WhenUnlockedThisDeviceOnly`) needs the entitlement that
//! comes with release signing; switching to it is part of release signing.
//! Other platforms: not supported yet ([`KeychainErrors::Unsupported`]), so
//! the daemon stays RAM-only there and says so.
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
    /// `d_salt || storage salt` (64 bytes).
    Salts,
    /// `d_key` (32 bytes), automatic login only.
    DataKey,
}

impl Item {
    /// Keychain account name of the item.
    pub fn account(self) -> &'static str {
        match self {
            Item::Salts => "salts",
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

    /// Test that item names are distinct (one item can't overwrite the other)
    #[test]
    fn test_item_accounts_distinct() {
        assert_ne!(Item::Salts.account(), Item::DataKey.account());
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
        assert_eq!(
            OsKeychain.get(Item::Salts),
            Err(KeychainErrors::Unsupported)
        );
        assert_eq!(
            OsKeychain.set(Item::Salts, &[0; 64]),
            Err(KeychainErrors::Unsupported)
        );
    }
}
