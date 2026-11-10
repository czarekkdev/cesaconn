//! Joining a group (design doc 11): a fresh device gets the salts and
//! pairs with a member, then commits everything at once.

use super::*;

impl Daemon {
    /// Starts joining the group of a device whose user opened "Add
    /// device": only on a fresh device (no keys, no vault) that can save
    /// what it gets. The passwords move into the join's task and are wiped
    /// when it ends: success, [`JOIN_WINDOW`], [`JOIN_MAX_ATTEMPTS`],
    /// `CancelJoin` or shutdown.
    ///
    /// `at`: a typed address (another network, a VPN): the join goes through
    /// the device there instead of searching the LAN.
    pub(super) async fn join_group(
        self: &Arc<Self>,
        passwords: JoinPasswords,
        at: Option<IpAddr>,
    ) -> Result<(), DaemonError> {
        // a joined device must survive a restart
        if self.storage.is_none() {
            return Err(DaemonError::NotSaved);
        }
        if at.is_some_and(is_own_address) {
            return Err(DaemonError::OwnAddress);
        }
        let at = at.map(|ip| self.member_at(ip));
        if !self.is_fresh().await {
            return Err(DaemonError::AlreadyInGroup);
        }
        // a reset from here on makes this join void
        let resets = self.resets.load(Ordering::SeqCst);

        // this device's identity, kept by the vault once the join commits
        let identity = DeviceKeypairs::new_seed().map_err(|e| {
            error!(error = %e, "failed to generate the device identity");
            DaemonError::Internal
        })?;

        let token = CancellationToken::new();
        let generation = self.next_join.fetch_add(1, Ordering::SeqCst);
        {
            // check-then-set under one write guard; nothing awaited inside
            let mut join = self.join.write().await;
            if join.as_ref().is_some_and(|slot| !slot.token.is_cancelled()) {
                return Err(DaemonError::JoinRunning);
            }
            *join = Some(JoinSlot {
                generation,
                token: token.clone(),
            });
            drop(join);
        }

        match at {
            Some(member) => {
                info!(addr = %member.tcp, "joining a group through the device at the address")
            }
            None => info!("joining a group: looking for a device with \"Add device\" open"),
        }

        let daemon = self.clone();
        tokio::spawn(async move {
            select! {
                () = token.cancelled() => info!("join cancelled"),
                result = timeout(
                    Duration::from_secs(JOIN_WINDOW),
                    daemon.run_join(passwords, identity, resets, at),
                ) => match result {
                    Ok(Ok(())) => info!("joined the group"),
                    Ok(Err(e)) => warn!(error = %e, "join failed"),
                    Err(_) => warn!("join timed out"),
                },
            }
            // (the passwords were dropped with the join future: wiped)
            daemon.end_join(generation).await;
        });

        Ok(())
    }

    /// No keys, no vault, nothing locked: a device that may join.
    pub(super) async fn is_fresh(&self) -> bool {
        let keys = self.keys.read().await;
        !keys.locked
            && keys.vault.is_none()
            && keys.a_key.is_none()
            && keys.d_key.is_none()
            && keys.a_salt.is_none()
            && keys.d_salt.is_none()
    }

    /// Ends the running join (its passwords are wiped with its task).
    pub(super) async fn cancel_join(&self) {
        let slot = self.join.write().await.take();
        if let Some(slot) = slot {
            slot.token.cancel();
            self.finish_join().await;
        }
    }

    /// Clears the join `generation` if it is still the current one.
    pub(super) async fn end_join(&self, generation: u64) {
        {
            let mut join = self.join.write().await;
            if join
                .as_ref()
                .is_none_or(|slot| slot.generation != generation)
            {
                return;
            }
            *join = None;
        }
        self.finish_join().await;
    }

    /// A join runs: one whose slot is set and not cancelled. Read from the
    /// slot itself, so an old join ending can't switch off a newer one.
    pub(super) async fn join_running(&self) -> bool {
        self.join
            .read()
            .await
            .as_ref()
            .is_some_and(|slot| !slot.token.is_cancelled())
    }

    /// No join any more: its waiting prompts are rejected (unless an
    /// "Add device" window or a new join still asks about devices).
    pub(super) async fn finish_join(&self) {
        if !self.adding.load(Ordering::SeqCst) && !self.join_running().await {
            self.pairings.write().await.waiting.clear();
        }
    }

    /// The join itself: search for members (or take the one at `at`), try
    /// each until one succeeds or [`JOIN_MAX_ATTEMPTS`] salt attempts are
    /// used up. A device that gives no salt (its window isn't open yet)
    /// costs no attempt: it is asked again after [`JOIN_RETRY_PAUSE`].
    pub(super) async fn run_join(
        self: &Arc<Self>,
        passwords: JoinPasswords,
        identity: Zeroizing<[u8; IDENTITY_SEED_LEN]>,
        resets: u64,
        at: Option<MemberAddrs>,
    ) -> Result<(), DaemonError> {
        let mut attempts = 0u32;

        while attempts < JOIN_MAX_ATTEMPTS {
            let members = match at {
                Some(member) => vec![member],
                None => self.find_members().await,
            };
            for member in members {
                if attempts >= JOIN_MAX_ATTEMPTS {
                    break;
                }
                let before = attempts;
                match self
                    .join_attempt(&passwords, &identity, member, &mut attempts)
                    .await
                {
                    Ok(joined) => {
                        // its own task: a timeout or CancelJoin from here on
                        // can't cut the commit half-way (keychain without vault)
                        let daemon = self.clone();
                        return tokio::spawn(async move {
                            daemon.commit_join(joined, identity, resets).await
                        })
                        .await
                        .map_err(|_| DaemonError::Internal)?;
                    }
                    // no salt there (its window isn't open yet): no attempt used,
                    // quiet, since a typed address is asked every few seconds
                    Err(e) if attempts == before => {
                        debug!(addr = %member.tcp, error = %e, "no join through the device yet");
                    }
                    Err(e) => warn!(addr = %member.tcp, error = %e, "join attempt failed"),
                }
            }

            sleep(Duration::from_secs(JOIN_RETRY_PAUSE)).await;
        }

        warn!(
            attempts = JOIN_MAX_ATTEMPTS,
            "join: every salt attempt used up without joining"
        );
        Err(DaemonError::NetworkOff)
    }

    /// Devices announcing an open "Add device" window on the LAN.
    pub(super) async fn find_members(&self) -> Vec<MemberAddrs> {
        #[cfg(test)]
        {
            let members = self.test_members.read().await.clone();
            if !members.is_empty() {
                return members;
            }
        }

        let Ok(own) = InstanceId::generate() else {
            return Vec::new();
        };

        match udp_find_broadcasters(ADD_DEVICE_SEARCH, own).await {
            // only the IP comes from discovery (an unauthenticated hint)
            Ok(found) => found
                .into_iter()
                .map(|(addr, _)| MemberAddrs {
                    salt: SocketAddr::new(addr.ip(), SALT_PORT),
                    tcp: SocketAddr::new(addr.ip(), TCP_PORT),
                })
                .collect(),
            Err(e) => {
                warn!(error = %e, "searching for a device to join failed");
                Vec::new()
            }
        }
    }

    /// One try with one member:
    /// 1. the salt query: `a_salt` (unauthenticated, see `salt_service`);
    /// 2. a candidate `a_key` from pw1 and that salt (counts as an attempt);
    /// 3. the handshake, the user pairs the devices, `d_salt` comes over
    ///    that same connection ([`tcp_networker::join_handler`]);
    /// 4. `d_key` from pw2 and `d_salt`.
    ///
    /// A fake salt fails in step 3: it is bound into SPAKE2.
    pub(super) async fn join_attempt(
        self: &Arc<Self>,
        passwords: &JoinPasswords,
        identity: &Zeroizing<[u8; IDENTITY_SEED_LEN]>,
        member: MemberAddrs,
        attempts: &mut u32,
    ) -> Result<Joined, DaemonError> {
        // 1. the salt
        let a_salt = query_salt(member.salt).await.map_err(|e| {
            debug!(addr = %member.salt, error = %e, "no salt from the device");
            DaemonError::NetworkOff
        })?;

        // 2. the candidate auth key
        *attempts = attempts.saturating_add(1);
        let a_key = AuthKey::new(
            self.derive(
                PasswordUpdate {
                    password: passwords.auth.password.clone(),
                },
                a_salt.clone(),
            )
            .await?,
        );

        // 3. handshake, pairing, d_salt; d_key isn't known yet and the
        // GroupSalt exchange doesn't use it: a random one that opens nothing
        let unused_d_key = random_array::<32>().map_err(|_| DaemonError::Internal)?;
        let (pairing, inbox) = Pairing::channel();
        let context = NetworkerContext {
            keys: Arc::new(RwLock::new(Keys::new(
                a_key.clone(),
                &a_salt,
                DataKey::new(unused_d_key),
            ))),
            device_keypairs: Arc::new(DeviceKeypairs::from_seed(identity)),
            // nobody is trusted yet: the member must be paired just now
            trusted_peers: Arc::default(),
            pairing,
            guess_limiter: self.guess_limiter.clone(),
            salt_offer: Arc::default(),
            // the join's own: the commit keeps the member's address
            peer_book: Arc::default(),
            peer_port: self.peer_port.load(Ordering::SeqCst),
            clipboard: None,
        };
        // ends when the context (and with it the pairing sender) is dropped
        tokio::spawn(self.clone().join_bridge(inbox));

        let stream = timeout(Duration::from_secs(TIMEOUT), TcpStream::connect(member.tcp))
            .await
            .map_err(|_| DaemonError::NetworkOff)?
            .map_err(|_| DaemonError::NetworkOff)?;

        // a full handshake: boxed, so the future isn't kept on the stack
        let (peer, d_salt) = Box::pin(tcp_networker::join_handler(context, member.tcp, stream))
            .await
            .map_err(|e| {
                debug!(addr = %member.tcp, error = %e, "joining through the device failed");
                DaemonError::NetworkOff
            })?;

        // 4. the data key
        let d_key = DataKey::new(
            self.derive(
                PasswordUpdate {
                    password: passwords.data.password.clone(),
                },
                d_salt.clone(),
            )
            .await?,
        );

        Ok(Joined {
            a_key,
            a_salt,
            d_key,
            d_salt,
            peer,
            addr: member.tcp,
        })
    }

    /// Hands the join's pairing requests to the user (no saving: the commit
    /// saves everything at once).
    pub(super) async fn join_bridge(self: Arc<Self>, mut inbox: PairingInbox) {
        // ends when the join attempt drops its context (the sender): the
        // attempt itself is bounded by the handshake deadline, the pairing
        // timeout and JOIN_WINDOW; an in-process channel, not the network
        // nosemgrep: cesa.net.read-without-timeout
        while let Some(request) = inbox.requests.recv().await {
            self.queue_pairing(request).await;
        }
    }

    /// Keeps what the join brought: keys, salts, the member as a trusted
    /// peer, a new vault with Sync on (joining means syncing), networking.
    pub(super) async fn commit_join(
        self: &Arc<Self>,
        joined: Joined,
        identity: Zeroizing<[u8; IDENTITY_SEED_LEN]>,
        resets: u64,
    ) -> Result<(), DaemonError> {
        let turn = self
            .change_slot
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| DaemonError::Internal)?;

        // the user reset this device meanwhile: the join belongs to before
        if self.resets.load(Ordering::SeqCst) != resets {
            warn!("a join from before the reset finished: dropped, nothing kept");
            return Err(DaemonError::Internal);
        }
        // the state may have changed while the user was pairing
        if !self.is_fresh().await {
            return Err(DaemonError::AlreadyInGroup);
        }

        {
            let mut keys = self.keys.write().await;
            keys.a_key = Some(joined.a_key);
            keys.a_salt = Some(joined.a_salt);
            keys.d_key = Some(joined.d_key);
            keys.d_salt = Some(joined.d_salt);
        }
        self.peer_book.seen(&joined.peer, joined.addr).await;
        self.peer_list().await.write().await.push(joined.peer);

        // clipboard stays off: every feature is off until the user turns it on
        self.create_vault(
            Some(identity),
            Config {
                sync: true,
                clipboard: false,
            },
        )
        .await;
        let saved = self.keys.read().await.vault.is_some();

        drop(turn);
        self.apply_network().await;

        if saved {
            Ok(())
        } else {
            // the keys stay in RAM, like a first device whose save failed
            Err(DaemonError::StorageFailed)
        }
    }
}
