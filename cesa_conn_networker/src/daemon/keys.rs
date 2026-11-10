//! Passwords, keys and the vault: setting and changing a password,
//! creating, unlocking and re-sealing the vault, the saved settings,
//! forgetting a device and resetting this one.

use super::*;

impl Daemon {
    /// Sets a new password: derive, save (if the vault is open), then keep.
    pub(super) async fn set_password(
        self: &Arc<Self>,
        kind: KeyKind,
        update: PasswordUpdate,
    ) -> Result<(), DaemonError> {
        if password_chars(&update.password) < MIN_NEW_PASSWORD_LEN {
            return Err(DaemonError::WeakPassword);
        }
        if self.keys.read().await.locked {
            return Err(DaemonError::Locked);
        }

        let salt = self.salt_for(kind).await?;
        let key = self.derive(update, salt).await?;

        // saved first, kept second: a failed save changes nothing
        if self.keys.read().await.vault.is_some() {
            self.save_changed_key(kind, &key).await?;
        }

        {
            let mut keys = self.keys.write().await;
            match kind {
                KeyKind::Auth => keys.a_key = Some(AuthKey::new(key)),
                KeyKind::Data => keys.d_key = Some(DataKey::new(key)),
            }
        }

        match kind {
            KeyKind::Auth => info!("auth key set"),
            KeyKind::Data => info!("data key set"),
        }

        // running connections use the new key from now on
        self.update_network_keys().await;

        // first time both keys exist: create the vault (and the group)
        if self.keys.read().await.vault.is_none() {
            self.create_vault(None, Config::default()).await;
        }

        Ok(())
    }

    /// The trusted peers, encoded for the vault. Read before the key lock is
    /// taken, so the two locks are never held together.
    pub(super) async fn encoded_peers(&self) -> Result<Zeroizing<Vec<u8>>, DaemonError> {
        let list = self.peer_list().await;
        let peers = list.read().await;
        let encoded = encode_peers(&peers).ok_or_else(|| {
            error!("trusted peers don't fit in the vault");
            DaemonError::StorageFailed
        })?;
        drop(peers);

        Ok(Zeroizing::new(encoded))
    }

    /// Re-saves the open vault with a changed key. A new `d_key` re-wraps the
    /// DEK (and replaces the automatic-login key); a new `a_key` re-seals.
    pub(super) async fn save_changed_key(
        &self,
        kind: KeyKind,
        key: &[u8; 32],
    ) -> Result<(), DaemonError> {
        let Some(storage) = &self.storage else {
            return Ok(());
        };

        let peers = self.encoded_peers().await?;
        let addresses = self.encoded_addresses().await;

        let (file, new_wrap, auto_login) = {
            let keys = self.keys.read().await;
            let (Some(open), Some(a_key), Some(a_salt)) = (&keys.vault, &keys.a_key, &keys.a_salt)
            else {
                return Err(DaemonError::Internal);
            };

            let (a_key, wrapped) = match kind {
                KeyKind::Auth => (AuthKey::from_bytes(key), open.wrapped.clone()),
                KeyKind::Data => {
                    let kek = vault::derive_kek(&DataKey::from_bytes(key), &open.storage_salt)
                        .map_err(storage_error)?;
                    (
                        a_key.clone(),
                        vault::wrap_dek(&kek, &open.dek).map_err(storage_error)?,
                    )
                }
            };

            let contents = VaultContents {
                a_key,
                a_salt: a_salt.clone(),
                config: open.config.encode(&addresses),
                identity: open.identity.clone(),
                peers,
            };
            let file = vault::seal(&wrapped, &open.dek, &contents).map_err(storage_error)?;

            (file, wrapped, keys.auto_login)
        };

        let path = storage.path.clone();
        blocking(move || vault::write_file_atomic(&path, &file))
            .await?
            .map_err(storage_error)?;

        if let KeyKind::Data = kind {
            {
                let mut keys = self.keys.write().await;
                if let Some(open) = keys.vault.as_mut() {
                    open.wrapped = new_wrap;
                }
            }

            if auto_login {
                let store = storage.store.clone();
                let d_key = Zeroizing::new(*key);
                let saved = blocking(move || store.set(Item::DataKey, d_key.as_slice())).await;

                if !matches!(saved, Ok(Ok(()))) {
                    // the old keychain key no longer opens the vault: remove it
                    let store = storage.store.clone();
                    let _ = blocking(move || store.delete(Item::DataKey)).await;
                    self.keys.write().await.auto_login = false;
                    warn!("automatic login turned off: the keychain refused the new key");
                }
            }
        }

        info!("vault saved");
        Ok(())
    }

    /// Creates the vault once both keys are set, with this device's
    /// `identity` (a new one if `None`) and `config`. On failure the keys
    /// stay in RAM only (the status says `saved = false`) and nothing is
    /// half-written.
    pub(super) async fn create_vault(
        &self,
        identity: Option<Zeroizing<[u8; IDENTITY_SEED_LEN]>>,
        config: Config,
    ) {
        let Some(storage) = &self.storage else {
            return;
        };

        // copies (zeroizing) taken under the guard, which is dropped right away
        let copies = {
            let keys = self.keys.read().await;
            (
                keys.a_key.clone(),
                keys.a_salt.clone(),
                keys.d_key.clone(),
                keys.d_salt.clone(),
            )
        };

        let (Some(a_key), Some(a_salt), Some(d_key), Some(d_salt)) = copies else {
            return;
        };

        let Ok(peers) = self.encoded_peers().await else {
            return;
        };
        let addresses = self.encoded_addresses().await;

        let prepared = {
            (|| {
                let storage_salt = random_array::<32>().map_err(|_| VaultErrors::Crypto)?;
                let salts = Salts {
                    d_salt: d_salt.clone(),
                    storage_salt: storage_salt.clone(),
                };
                let dek = vault::generate_dek()?;
                let kek = vault::derive_kek(&d_key, &storage_salt)?;
                let wrapped = vault::wrap_dek(&kek, &dek)?;
                // the device identity is born with the vault (a joining
                // device made it for the join already)
                let identity = match identity {
                    Some(identity) => identity,
                    None => DeviceKeypairs::new_seed().map_err(|_| VaultErrors::Crypto)?,
                };
                let contents = VaultContents {
                    a_key: a_key.clone(),
                    a_salt: a_salt.clone(),
                    config: config.encode(&addresses),
                    identity: identity.clone(),
                    peers,
                };
                let file = vault::seal(&wrapped, &dek, &contents)?;

                Ok::<_, VaultErrors>((
                    salts,
                    file,
                    OpenVault {
                        dek,
                        wrapped,
                        storage_salt,
                        config,
                        identity,
                    },
                ))
            })()
        };

        let (salts, file, open) = match prepared {
            Ok(prepared) => prepared,
            Err(e) => {
                error!(error = %e, "preparing the vault failed: keys stay in RAM only");
                return;
            }
        };

        // 1. salts into the keychain (without them the file can't be opened)
        let store = storage.store.clone();
        let salt_bytes = salts.to_bytes();
        match blocking(move || store.set(Item::Salts, salt_bytes.as_slice())).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                warn!(error = %e, "keychain refused the salts: keys stay in RAM only");
                return;
            }
            Err(_) => return,
        }

        // 2. the vault file
        let path = storage.path.clone();
        match blocking(move || vault::write_file_atomic(&path, &file)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                error!(error = %e, "writing the vault failed: keys stay in RAM only");
                return;
            }
            Err(_) => return,
        }

        self.keys.write().await.vault = Some(open);
        info!("keys saved in the encrypted vault");
    }

    /// Opens the saved vault with the data password.
    pub(super) async fn unlock(&self, update: PasswordUpdate) -> Result<(), DaemonError> {
        let Some(storage) = &self.storage else {
            return Err(DaemonError::NotSaved);
        };

        {
            let keys = self.keys.read().await;
            if !keys.locked {
                return Err(if keys.vault.is_some() {
                    DaemonError::BadRequest
                } else {
                    DaemonError::NotSaved
                });
            }

            // too soon after wrong passwords: refused at once, before any
            // keychain access or Argon2, and not counted as another guess
            if wait_secs(keys.unlock_not_before, Instant::now()) > 0 {
                return Err(DaemonError::UnlockDelayed);
            }
        }

        let store = storage.store.clone();
        let salts = match blocking(move || store.get(Item::Salts)).await? {
            Ok(Some(bytes)) => Salts::from_bytes(&bytes).ok_or(DaemonError::StorageFailed)?,
            Ok(None) => {
                error!("the vault's salts are missing from the keychain");
                return Err(DaemonError::StorageFailed);
            }
            Err(e) => {
                error!(error = %e, "keychain unavailable");
                return Err(DaemonError::StorageFailed);
            }
        };

        let d_key = self.derive(update, salts.d_salt.clone()).await?;

        let result = self.unlock_with(DataKey::new(d_key)).await;

        {
            let mut keys = self.keys.write().await;
            match result {
                Ok(()) => {
                    keys.unlock_failures = 0;
                    keys.unlock_not_before = None;
                }
                Err(DaemonError::WrongPassword) => {
                    keys.unlock_failures = keys.unlock_failures.saturating_add(1);
                    let delay = unlock_delay(keys.unlock_failures);
                    // can't overflow: the delay is at most MAX_UNLOCK_DELAY and an
                    // Instant a minute from now always fits
                    let now = Instant::now();
                    keys.unlock_not_before = Some(now.checked_add(delay).unwrap_or(now));
                    warn!(
                        failures = keys.unlock_failures,
                        delay_secs = delay.as_secs(),
                        "wrong data password"
                    );
                }
                Err(_) => {}
            }
        }

        result
    }

    /// Opens the vault with `d_key` (typed password or automatic login).
    pub(super) async fn unlock_with(&self, d_key: DataKey) -> Result<(), DaemonError> {
        let Some(storage) = &self.storage else {
            return Err(DaemonError::NotSaved);
        };

        let store = storage.store.clone();
        let salts = match blocking(move || store.get(Item::Salts)).await? {
            Ok(Some(bytes)) => Salts::from_bytes(&bytes).ok_or(DaemonError::StorageFailed)?,
            _ => return Err(DaemonError::StorageFailed),
        };

        let path = storage.path.clone();
        let file = blocking(move || vault::read_file(&path))
            .await?
            .map_err(storage_error)?
            .ok_or(DaemonError::NotSaved)?;

        let kek = vault::derive_kek(&d_key, &salts.storage_salt).map_err(storage_error)?;
        let opened = vault::open(&kek, &file).map_err(storage_error)?;
        let peers = decode_peers(&opened.contents.peers).ok_or_else(|| {
            error!("saved trusted peers are damaged");
            DaemonError::StorageFailed
        })?;
        let (config, addresses) = Config::decode(&opened.contents.config).ok_or_else(|| {
            error!("saved settings are damaged");
            DaemonError::StorageFailed
        })?;

        *self.peer_list().await.write().await = peers;
        self.peer_book.load(addresses).await;

        let mut keys = self.keys.write().await;
        keys.a_key = Some(opened.contents.a_key);
        keys.a_salt = Some(opened.contents.a_salt);
        keys.d_key = Some(d_key);
        keys.d_salt = Some(salts.d_salt);
        keys.vault = Some(OpenVault {
            dek: opened.dek,
            wrapped: opened.wrapped,
            storage_salt: salts.storage_salt,
            config,
            identity: opened.contents.identity,
        });
        keys.locked = false;
        drop(keys);

        info!("vault unlocked");
        Ok(())
    }

    /// Keeps `d_key` in the OS keychain (or removes it from there).
    pub(super) async fn set_auto_login(&self, on: bool) -> Result<(), DaemonError> {
        let Some(storage) = &self.storage else {
            return Err(DaemonError::NotSaved);
        };

        let d_key = {
            let keys = self.keys.read().await;
            if keys.locked {
                return Err(DaemonError::Locked);
            }
            if keys.vault.is_none() {
                return Err(DaemonError::NotSaved);
            }
            keys.d_key
                .as_ref()
                .map(|k| k.expose().clone())
                .ok_or(DaemonError::NotSaved)?
        };

        let store = storage.store.clone();
        let result = if on {
            blocking(move || store.set(Item::DataKey, d_key.as_slice())).await?
        } else {
            drop(d_key);
            blocking(move || store.delete(Item::DataKey)).await?
        };

        result.map_err(|e| {
            error!(error = %e, "keychain refused the automatic-login change");
            DaemonError::StorageFailed
        })?;

        self.keys.write().await.auto_login = on;

        if on {
            warn!("automatic login on: d_key is in the OS keychain, its security rests on the OS");
        } else {
            info!("automatic login off: d_key removed from the OS keychain");
        }

        Ok(())
    }

    /// Turns the Sync switch on or off: saved in the vault first, then
    /// networking follows ([`Daemon::apply_network`], run by `change`).
    pub(super) async fn set_sync(&self, on: bool) -> Result<(), DaemonError> {
        let config = Config {
            sync: on,
            ..self.saved_config().await?
        };
        self.save_config(config).await?;

        if on {
            info!("sync on");
        } else {
            info!("sync off");
        }

        Ok(())
    }

    /// Turns clipboard sync on or off: saved in the vault first. It works
    /// while networking runs (Sync on); off, nothing is read or applied.
    pub(super) async fn set_clipboard(&self, on: bool) -> Result<(), DaemonError> {
        if on && self.clipboard.is_none() {
            return Err(DaemonError::ClipboardUnavailable);
        }

        let config = Config {
            clipboard: on,
            ..self.saved_config().await?
        };
        self.save_config(config).await?;

        if on {
            info!("clipboard sync on");
        } else {
            info!("clipboard sync off");
        }

        Ok(())
    }

    /// The settings of the open vault: `Locked` / `NotSaved` without one (a
    /// setting must survive a restart: none without a vault).
    pub(super) async fn saved_config(&self) -> Result<Config, DaemonError> {
        let keys = self.keys.read().await;
        if keys.locked {
            return Err(DaemonError::Locked);
        }
        keys.vault
            .as_ref()
            .map(|open| open.config)
            .ok_or(DaemonError::NotSaved)
    }

    /// Saves `config` (saved first, kept second: a failed save changes
    /// nothing). The caller holds the change slot.
    pub(super) async fn save_config(&self, config: Config) -> Result<(), DaemonError> {
        self.reseal(Some(config)).await?;

        let mut keys = self.keys.write().await;
        if let Some(open) = keys.vault.as_mut() {
            open.config = config;
        }
        drop(keys);
        Ok(())
    }

    /// Removes the paired device(s) with this fingerprint from this device:
    /// from memory first (new handshakes treat it as unknown at once), then
    /// from the vault; a failed save puts them back and changes nothing.
    ///
    /// Local only: the device still knows the group passwords and this
    /// device, and may pair again through "Add device" if the user accepts.
    /// Keeping it out for good needs new group passwords (daemon.md 14.1).
    pub(super) async fn forget_peer(
        &self,
        fingerprint: &[u8; FINGERPRINT_LEN],
    ) -> Result<(), DaemonError> {
        {
            let keys = self.keys.read().await;
            if keys.locked {
                return Err(DaemonError::Locked);
            }
        }

        let list = self.peer_list().await;
        let is_it = |peer: &TrustedPeer| bool::from(peer.fingerprint().ct_eq(fingerprint));
        // every match: two keys with one 64-bit fingerprint are one device
        // in practice, and the user picked it by that fingerprint
        let removed: Vec<(usize, TrustedPeer)> = {
            let mut peers = list.write().await;
            let removed = peers
                .iter()
                .enumerate()
                .filter(|(_, peer)| is_it(peer))
                .map(|(index, peer)| (index, peer.clone()))
                .collect();
            peers.retain(|peer| !is_it(peer));
            drop(peers);
            removed
        };

        if removed.is_empty() {
            return Err(DaemonError::UnknownPeer);
        }

        // RAM only (no storage, nothing saved yet): nothing more to do
        if self.keys.read().await.vault.is_some()
            && let Err(e) = self.reseal(None).await
        {
            // saved first, kept second: put them back where they were
            let mut peers = list.write().await;
            for (index, peer) in removed {
                let at = index.min(peers.len());
                peers.insert(at, peer);
            }
            drop(peers);
            return Err(e);
        }

        for (_, peer) in &removed {
            self.peer_book.remove(peer).await;
        }

        info!(count = removed.len(), "forgot a paired device");
        Ok(())
    }

    /// Wipes this device back to fresh, as if CesaConn never ran: it leaves
    /// its group. Allowed while locked (the way out of a forgotten data
    /// password: the vault is lost anyway) and without any password: the
    /// same user can delete these files by hand, a reset reveals nothing.
    ///
    /// Order: networking, invite and join end first (nothing new pairs);
    /// the vault file goes next, the decisive step (no vault, no group:
    /// the keychain items mean nothing without it, the daemon starts fresh);
    /// then memory; the keychain items last. A failed vault delete changes
    /// nothing else; a failed keychain delete still leaves a fresh device
    /// and is reported, a second reset removes the leftovers.
    pub(super) async fn reset_device(self: &Arc<Self>) -> Result<(), DaemonError> {
        // a join that started before never commits after this
        self.resets.fetch_add(1, Ordering::SeqCst);
        self.cancel_join().await;
        // the bridge finishes on its own (its save sees no vault)
        drop(self.stop_network().await);

        if let Some(storage) = &self.storage {
            let path = storage.path.clone();
            blocking(move || vault::delete_file(&path))
                .await?
                .map_err(storage_error)?;
        }

        // the keys are wiped (zeroized) with the old slots
        *self.keys.write().await = KeySlots::default();
        // a new list: a late handshake of the old network can't add to it
        *self.trusted_peers.write().await = Arc::default();
        self.peer_book.clear().await;
        self.pairings.write().await.waiting.clear();
        self.other_group.store(false, Ordering::SeqCst);
        warn!("this device was reset: keys, vault and paired devices are gone");

        if let Some(storage) = &self.storage {
            for item in [Item::Salts, Item::DataKey] {
                let store = storage.store.clone();
                match blocking(move || store.delete(item)).await {
                    Ok(Ok(())) => {}
                    _ => {
                        error!(
                            ?item,
                            "removing a keychain item failed: reset again to remove it"
                        );
                        return Err(DaemonError::StorageFailed);
                    }
                }
            }
        }

        Ok(())
    }

    /// Re-seals the open vault as it is, with `config` if given. The caller
    /// holds the change slot.
    pub(super) async fn reseal(&self, config: Option<Config>) -> Result<(), DaemonError> {
        let Some(storage) = &self.storage else {
            return Err(DaemonError::NotSaved);
        };

        let peers = self.encoded_peers().await?;
        let addresses = self.encoded_addresses().await;

        let file = {
            let keys = self.keys.read().await;
            let (Some(open), Some(a_key), Some(a_salt)) = (&keys.vault, &keys.a_key, &keys.a_salt)
            else {
                return Err(DaemonError::NotSaved);
            };

            let contents = VaultContents {
                a_key: a_key.clone(),
                a_salt: a_salt.clone(),
                config: config.unwrap_or(open.config).encode(&addresses),
                identity: open.identity.clone(),
                peers,
            };
            let file = vault::seal(&open.wrapped, &open.dek, &contents);
            drop(keys);
            file.map_err(storage_error)?
        };

        let path = storage.path.clone();
        blocking(move || vault::write_file_atomic(&path, &file))
            .await?
            .map_err(storage_error)?;

        info!("vault saved");
        Ok(())
    }

    /// Writes the trusted peers to the vault after a pairing, as its own
    /// state change (waits for the change slot).
    pub(super) async fn save_peers(&self) {
        let Ok(_turn) = self.change_slot.clone().acquire_owned().await else {
            return;
        };

        if self.keys.read().await.vault.is_none() {
            return;
        }

        if let Err(e) = self.reseal(None).await {
            error!(error = %e, "saving the trusted devices failed: they are kept in memory, the next change saves them");
        }
    }
}
