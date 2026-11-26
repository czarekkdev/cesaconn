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

    /// Re-saves the open vault with a changed key. Standard mode: a new
    /// `d_key` re-wraps the DEK (and replaces the automatic-login key), a
    /// new `a_key` re-seals. Enhanced mode: the KEK uses both keys, so
    /// either change re-wraps.
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

        // copies taken under the guard: the KEK may need Argon2 (Enhanced),
        // which never runs while the key lock is held
        let (header, dek, old_wrap, a_key, d_key, contents, auto_login) = {
            let keys = self.keys.read().await;
            let (Some(open), Some(a_key), Some(d_key)) = (&keys.vault, &keys.a_key, &keys.d_key)
            else {
                return Err(DaemonError::Internal);
            };

            // the keys after the change
            let (a_key, d_key) = match kind {
                KeyKind::Auth => (AuthKey::from_bytes(key), d_key.clone()),
                KeyKind::Data => (a_key.clone(), DataKey::from_bytes(key)),
            };
            let contents = VaultContents {
                a_key: stored_a_key(&open.header, &a_key),
                config: open.config.encode(&addresses),
                identity: open.identity.clone(),
                peers,
            };
            (
                open.header.with_mode(open.header.mode),
                open.dek.clone(),
                open.wrapped.clone(),
                a_key,
                d_key,
                contents,
                keys.auto_login,
            )
        };

        let rewrap = matches!(kind, KeyKind::Data) || header.mode == Mode::Enhanced;
        let new_wrap = if rewrap {
            let kek = self
                .kek(&header, &d_key, kek_a_key(&header, &a_key))
                .await?
                .map_err(storage_error)?;
            vault::wrap_dek(&header, &kek, &dek).map_err(storage_error)?
        } else {
            old_wrap
        };
        let file = vault::seal(&header, &new_wrap, &dek, &contents).map_err(storage_error)?;
        drop(contents);

        let path = storage.path.clone();
        blocking(move || vault::write_file_atomic(&path, &file))
            .await?
            .map_err(storage_error)?;

        {
            let mut keys = self.keys.write().await;
            if let Some(open) = keys.vault.as_mut() {
                open.wrapped = new_wrap;
            }
        }

        if let KeyKind::Data = kind
            && auto_login
        {
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

        info!("vault saved");
        Ok(())
    }

    /// Creates the vault once both keys are set, in Standard mode, with
    /// this device's `identity` (a new one if `None`) and `config`. On
    /// failure the keys stay in RAM only (the status says `saved = false`)
    /// and nothing is half-written.
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
                let header = Header {
                    mode: Mode::Standard,
                    a_salt,
                    d_salt,
                    storage_salt: random_array::<32>().map_err(|_| VaultErrors::Crypto)?,
                };
                let dek = vault::generate_dek()?;
                let kek = vault::derive_kek(&header, &d_key, None)?;
                let wrapped = vault::wrap_dek(&header, &kek, &dek)?;
                // the device identity is born with the vault (a joining
                // device made it for the join already)
                let identity = match identity {
                    Some(identity) => identity,
                    None => DeviceKeypairs::new_seed().map_err(|_| VaultErrors::Crypto)?,
                };
                let contents = VaultContents {
                    a_key: Some(a_key.clone()),
                    config: config.encode(&addresses),
                    identity: identity.clone(),
                    peers,
                };
                let file = vault::seal(&header, &wrapped, &dek, &contents)?;

                Ok::<_, VaultErrors>((
                    file,
                    OpenVault {
                        dek,
                        wrapped,
                        header,
                        config,
                        identity,
                    },
                ))
            })()
        };

        let (file, open) = match prepared {
            Ok(prepared) => prepared,
            Err(e) => {
                error!(error = %e, "preparing the vault failed: keys stay in RAM only");
                return;
            }
        };

        // one file holds everything (salts in its header): nothing else to save
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

    /// The saved vault file and its header (its mode and salts), for an
    /// unlock: the keys are derived from this header and this same file is
    /// opened, so a file replaced meanwhile can't turn a right password into
    /// a counted wrong one. Refused at once when the daemon isn't locked,
    /// the vault is outdated, or the unlock delay runs (before any Argon2,
    /// and not counted as another guess).
    async fn locked_file(&self) -> Result<(Header, Vec<u8>), DaemonError> {
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
            if keys.outdated {
                return Err(DaemonError::VaultOutdated);
            }

            // too soon after wrong passwords: refused at once, before any
            // file access or Argon2, and not counted as another guess
            if wait_secs(keys.unlock_not_before, Instant::now()) > 0 {
                return Err(DaemonError::UnlockDelayed);
            }
        }

        let path = storage.path.clone();
        let file = blocking(move || vault::read_file(&path))
            .await?
            .map_err(storage_error)?
            .ok_or(DaemonError::NotSaved)?;
        let header = vault::read_header(&file).map_err(storage_error)?;
        Ok((header, file))
    }

    /// Opens the saved vault with the data password (Standard mode).
    pub(super) async fn unlock(&self, update: PasswordUpdate) -> Result<(), DaemonError> {
        let (header, file) = self.locked_file().await?;
        if header.mode == Mode::Enhanced {
            // the UI asks for both passwords; nothing is derived, no guess counted
            return Err(DaemonError::NeedsBothPasswords);
        }

        let d_key = self.derive(update, header.d_salt.clone()).await?;
        let result = self.open_file(&file, DataKey::new(d_key), None).await;
        self.count_unlock(&result).await;
        result
    }

    /// Opens the saved vault with both passwords (Enhanced mode). Both are
    /// derived before anything is tried, so a wrong one doesn't show which
    /// of the two was wrong, and every attempt costs three Argon2 runs (one
    /// per password, one for the KEK over both keys).
    pub(super) async fn unlock_both(&self, passwords: JoinPasswords) -> Result<(), DaemonError> {
        let (header, file) = self.locked_file().await?;
        if header.mode != Mode::Enhanced {
            return Err(DaemonError::BadRequest);
        }

        let JoinPasswords { auth, data } = passwords;
        let a_key = self.derive(auth, header.a_salt.clone()).await?;
        let d_key = self.derive(data, header.d_salt.clone()).await?;
        let result = self
            .open_file(&file, DataKey::new(d_key), Some(AuthKey::new(a_key)))
            .await;
        self.count_unlock(&result).await;
        result
    }

    /// Counts a wrong password (the unlock delay), or clears the count.
    async fn count_unlock(&self, result: &Result<(), DaemonError>) {
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
                    "wrong password"
                );
            }
            Err(_) => {}
        }
    }

    /// Opens the vault on disk now with `d_key` (automatic login).
    pub(super) async fn unlock_with(&self, d_key: DataKey) -> Result<(), DaemonError> {
        let Some(storage) = &self.storage else {
            return Err(DaemonError::NotSaved);
        };

        let path = storage.path.clone();
        let file = blocking(move || vault::read_file(&path))
            .await?
            .map_err(storage_error)?
            .ok_or(DaemonError::NotSaved)?;
        self.open_file(&file, d_key, None).await
    }

    /// Opens the vault `file` with `d_key`, and `a_key` in Enhanced mode,
    /// and takes its keys and contents.
    async fn open_file(
        &self,
        file: &[u8],
        d_key: DataKey,
        a_key: Option<AuthKey>,
    ) -> Result<(), DaemonError> {
        let header = vault::read_header(file).map_err(storage_error)?;

        let kek = self
            .kek(&header, &d_key, a_key.as_ref())
            .await?
            .map_err(|e| match e {
                // a Standard key for an Enhanced vault or the other way round
                VaultErrors::WrongMode => DaemonError::NeedsBothPasswords,
                other => storage_error(other),
            })?;
        let opened = vault::open(&kek, file).map_err(storage_error)?;
        let peers = decode_peers(&opened.contents.peers).ok_or_else(|| {
            error!("saved trusted peers are damaged");
            DaemonError::StorageFailed
        })?;
        let (config, addresses) = Config::decode(&opened.contents.config).ok_or_else(|| {
            error!("saved settings are damaged");
            DaemonError::StorageFailed
        })?;
        // Standard: the stored one; Enhanced: the one derived from pw1 (it
        // opened the vault, so it is the right one)
        let a_key = opened
            .contents
            .a_key
            .or(a_key)
            .ok_or(DaemonError::Internal)?;

        *self.peer_list().await.write().await = peers;
        self.peer_book.load(addresses).await;

        let mut keys = self.keys.write().await;
        keys.a_key = Some(a_key);
        keys.a_salt = Some(opened.header.a_salt.clone());
        keys.d_key = Some(d_key);
        keys.d_salt = Some(opened.header.d_salt.clone());
        keys.vault = Some(OpenVault {
            dek: opened.dek,
            wrapped: opened.wrapped,
            header: opened.header,
            config,
            identity: opened.contents.identity,
        });
        keys.locked = false;
        keys.locked_enhanced = false;
        drop(keys);

        info!("vault unlocked");
        Ok(())
    }

    /// The KEK of `header`'s mode, off the async workers. Enhanced mode runs
    /// Argon2 (over both keys), so it takes the derive slot like every
    /// Argon2: one at a time, even if this future is dropped.
    async fn kek(
        &self,
        header: &Header,
        d_key: &DataKey,
        a_key: Option<&AuthKey>,
    ) -> Result<Result<Zeroizing<[u8; 32]>, VaultErrors>, DaemonError> {
        let slot = self
            .derive_slot
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| DaemonError::Internal)?;

        let header = header.with_mode(header.mode);
        let d_key = d_key.clone();
        let a_key = a_key.cloned();
        blocking(move || {
            let kek = vault::derive_kek(&header, &d_key, a_key.as_ref());
            drop(slot);
            kek
        })
        .await
    }

    /// Keeps `d_key` in the OS keychain (or removes it from there). Not in
    /// Enhanced mode: it keeps no key anywhere.
    pub(super) async fn set_auto_login(&self, on: bool) -> Result<(), DaemonError> {
        let Some(storage) = &self.storage else {
            return Err(DaemonError::NotSaved);
        };

        let d_key = {
            let keys = self.keys.read().await;
            if keys.locked {
                return Err(DaemonError::Locked);
            }
            let Some(open) = &keys.vault else {
                return Err(DaemonError::NotSaved);
            };
            if on && open.header.mode == Mode::Enhanced {
                return Err(DaemonError::AutoLoginConflict);
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

    /// Turns Enhanced mode on (both passwords at every start, `a_key` no
    /// longer stored) or off. A new DEK is made, wrapped under the new KEK,
    /// and the whole file re-sealed with the new header, so the file on
    /// disk is always in exactly one mode, and the DEK of an older copy of
    /// the file doesn't open the new one. Refused while automatic login is
    /// on; turning it on first removes any automatic-login key the daemon
    /// may not know about (refused if that removal fails).
    pub(super) async fn set_enhanced(&self, on: bool) -> Result<(), DaemonError> {
        let Some(storage) = &self.storage else {
            return Err(DaemonError::NotSaved);
        };

        let mode = if on { Mode::Enhanced } else { Mode::Standard };
        let peers = self.encoded_peers().await?;
        let addresses = self.encoded_addresses().await;

        // copies taken under the guard: the Enhanced KEK needs Argon2, which
        // never runs while the key lock is held
        let (header, a_key, d_key, contents) = {
            let keys = self.keys.read().await;
            if keys.locked {
                return Err(DaemonError::Locked);
            }
            let (Some(open), Some(a_key), Some(d_key)) = (&keys.vault, &keys.a_key, &keys.d_key)
            else {
                return Err(DaemonError::NotSaved);
            };
            if open.header.mode == mode {
                return Ok(());
            }
            if on && keys.auto_login {
                return Err(DaemonError::AutoLoginConflict);
            }

            let header = open.header.with_mode(mode);
            let contents = VaultContents {
                a_key: stored_a_key(&header, a_key),
                config: open.config.encode(&addresses),
                identity: open.identity.clone(),
                peers,
            };
            let copies = (header, a_key.clone(), d_key.clone(), contents);
            drop(keys);
            copies
        };

        // a keychain read refused at start leaves `auto_login` off even if
        // a key is still there: Enhanced keeps no key anywhere, so remove
        // it now (removing a missing key is not an error)
        if on && storage.store.supported() {
            let store = storage.store.clone();
            if let Err(e) = blocking(move || store.delete(Item::DataKey)).await? {
                error!(error = %e, "Enhanced security not turned on: removing a possible automatic-login key failed");
                return Err(DaemonError::StorageFailed);
            }
        }

        let kek = self
            .kek(&header, &d_key, kek_a_key(&header, &a_key))
            .await?
            .map_err(storage_error)?;
        drop((a_key, d_key));
        // a new DEK: an older copy of the file (and its DEK) doesn't open
        // what is saved from now on
        let dek = vault::generate_dek().map_err(storage_error)?;
        let wrapped = vault::wrap_dek(&header, &kek, &dek).map_err(storage_error)?;
        let file = vault::seal(&header, &wrapped, &dek, &contents).map_err(storage_error)?;
        drop(contents);

        // saved first, kept second: a failed save changes nothing
        let path = storage.path.clone();
        blocking(move || vault::write_file_atomic(&path, &file))
            .await?
            .map_err(storage_error)?;

        let mut keys = self.keys.write().await;
        if let Some(open) = keys.vault.as_mut() {
            open.header = header;
            open.wrapped = wrapped;
            open.dek = dek;
        }
        drop(keys);

        if on {
            info!(
                "Enhanced security on: both passwords at every start, the auth key is no longer stored"
            );
        } else {
            warn!("Enhanced security off: the auth key is stored in the vault again");
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
    /// an automatic-login key means nothing without it, the daemon starts
    /// fresh); then memory; the keychain item last. A failed vault delete
    /// changes nothing else; a failed keychain delete still leaves a fresh
    /// device and is reported, a second reset removes the leftover.
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
            let store = storage.store.clone();
            match blocking(move || store.delete(Item::DataKey)).await {
                // nothing can be in a keychain this platform doesn't have
                Ok(Ok(()) | Err(KeychainErrors::Unsupported)) => {}
                _ => {
                    error!("removing the automatic-login key failed: reset again to remove it");
                    return Err(DaemonError::StorageFailed);
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
            let (Some(open), Some(a_key)) = (&keys.vault, &keys.a_key) else {
                return Err(DaemonError::NotSaved);
            };

            let contents = VaultContents {
                a_key: stored_a_key(&open.header, a_key),
                config: config.unwrap_or(open.config).encode(&addresses),
                identity: open.identity.clone(),
                peers,
            };
            let file = vault::seal(&open.header, &open.wrapped, &open.dek, &contents);
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

/// What the KEK of `header`'s mode takes of `a_key`: nothing (Standard)
/// or all of it (Enhanced).
fn kek_a_key<'a>(header: &Header, a_key: &'a AuthKey) -> Option<&'a AuthKey> {
    (header.mode == Mode::Enhanced).then_some(a_key)
}

/// What the vault stores of `a_key`: all of it in Standard mode, nothing
/// in Enhanced mode.
fn stored_a_key(header: &Header, a_key: &AuthKey) -> Option<AuthKey> {
    (header.mode == Mode::Standard).then(|| a_key.clone())
}
