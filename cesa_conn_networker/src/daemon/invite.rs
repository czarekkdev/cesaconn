//! The "Add device" window (design doc 13, 13.2): announcing, the LAN
//! search, connecting to found and typed addresses, the group check.

use super::*;

impl Daemon {
    /// Opens the "Add device" window for [`INVITE_WINDOW`] seconds: this
    /// device is announced on the LAN, answers salt queries (a new device
    /// joining, see [`crate::salt_service`]), hands `d_salt` to a device it
    /// pairs with just now, and asks the user about new devices. For the
    /// whole window it also searches (in [`ADD_DEVICE_SEARCH`] rounds) for
    /// other members with a window open and connects to them (re-pairing two
    /// devices that are both in the group already).
    ///
    /// `at`: a typed address (another network, a VPN) to connect to as
    /// well, also when the window is open already ([`connect_at`]).
    pub(super) async fn add_device(
        self: &Arc<Self>,
        at: Option<IpAddr>,
    ) -> Result<(), DaemonError> {
        if at.is_some_and(is_own_address) {
            return Err(DaemonError::OwnAddress);
        }

        // already open: one window at a time, an address joins that one
        if let Some(invite) = self.open_invite().await? {
            self.run_invite(invite);
        }
        if let Some(ip) = at {
            self.connect_at_in_window(ip).await;
        }

        Ok(())
    }

    /// The LAN part of a window just opened, in its own task: announce,
    /// search and connect until the window ends, then close it.
    pub(super) fn run_invite(self: &Arc<Self>, invite: Invite) {
        info!(seconds = INVITE_WINDOW, "add device: invite window open");

        let daemon = self.clone();
        tokio::spawn(async move {
            let Invite {
                context,
                token,
                id,
                window,
                generation,
                addrs,
            } = invite;

            select! {
                () = token.cancelled() => {},
                () = invite_window(context, id, window.clone(), daemon.other_group.clone(), addrs) => {},
            }
            // the salt goes away with the window, whatever ended it; a
            // window the user stopped (or a newer one) isn't touched here
            if daemon.end_invite(Some(generation)).await {
                info!("add device: invite window closed");
            }
        });
    }

    /// The invite part of [`Daemon::add_device`] without the LAN: marks the
    /// window open, offers `d_salt` to devices paired just now and starts
    /// the salt query (closed when `Invite::window` is cancelled, at the
    /// latest after [`INVITE_WINDOW`]). `None` if a window is open already.
    pub(super) async fn open_invite(&self) -> Result<Option<Invite>, DaemonError> {
        let (context, token) = {
            let network = self.network.read().await;
            match network.as_ref() {
                Some(network) if network.running() => {
                    (network.context.clone(), network.token.clone())
                }
                _ => return Err(DaemonError::NetworkOff),
            }
        };

        // copies (zeroizing) under the guard, which is dropped right away
        let (a_salt, d_salt) = {
            let keys = self.keys.read().await;
            match (&keys.a_salt, &keys.d_salt) {
                (Some(a_salt), Some(d_salt)) => (a_salt.clone(), d_salt.clone()),
                _ => return Err(DaemonError::NetworkOff),
            }
        };

        let id = InstanceId::generate().map_err(|e| {
            error!(error = %e, "failed to generate a discovery id");
            DaemonError::Internal
        })?;

        if self.adding.swap(true, Ordering::SeqCst) {
            return Ok(None);
        }
        // a new window starts without the last one's findings
        self.other_group.store(false, Ordering::SeqCst);

        let window = CancellationToken::new();
        let generation = self.next_invite.fetch_add(1, Ordering::SeqCst);
        let addrs = Arc::new(WindowAddrs::default());
        *self.invite.write().await = Some(InviteSlot {
            generation,
            window: window.clone(),
            offer: context.salt_offer.clone(),
            addrs: addrs.clone(),
        });

        // the salt query exists only during the window: no port outside it
        match TcpListener::bind(self.salt_addr).await {
            Ok(listener) => {
                tokio::spawn(serve_salt(listener, a_salt, window.clone()));
            }
            Err(e) => {
                warn!(error = %e, addr = %self.salt_addr, "salt query unavailable: new devices can't join, members can still pair");
            }
        }

        *context.salt_offer.write().await = Some(d_salt);

        // the window's own end, whatever else runs in it
        let closing = window.clone();
        tokio::spawn(async move {
            select! {
                () = closing.cancelled() => {},
                () = sleep(Duration::from_secs(INVITE_WINDOW)) => closing.cancel(),
            }
        });

        Ok(Some(Invite {
            context,
            token,
            id,
            window,
            generation,
            addrs,
        }))
    }

    /// Where a device at a typed address listens: its salt query and its
    /// listener, on the fixed ports.
    pub(super) fn member_at(&self, ip: IpAddr) -> MemberAddrs {
        MemberAddrs {
            salt: SocketAddr::new(ip, self.peer_salt_port.load(Ordering::SeqCst)),
            tcp: SocketAddr::new(ip, self.peer_port.load(Ordering::SeqCst)),
        }
    }

    /// The typed address of `AddDeviceAt` is connected to within the open
    /// window (just opened, or open already).
    pub(super) async fn connect_at_in_window(self: &Arc<Self>, ip: IpAddr) {
        let slot = self
            .invite
            .read()
            .await
            .as_ref()
            .map(|slot| (slot.window.clone(), slot.addrs.clone()));
        let running = self
            .network
            .read()
            .await
            .as_ref()
            .filter(|network| network.running())
            .map(|network| (network.context.clone(), network.token.clone()));

        match (slot, running) {
            (Some((window, addrs)), Some((context, token))) => {
                self.spawn_connect_at(context, token, window, addrs, ip);
            }
            // the window ended (or networking stopped) right in between: the
            // user presses again
            _ => warn!(%ip, "add device: no open window to connect to the address from"),
        }
    }

    /// Runs [`connect_at`] for `ip` in its own task, until it is done or
    /// networking ends.
    pub(super) fn spawn_connect_at(
        self: &Arc<Self>,
        context: NetworkerContext,
        token: CancellationToken,
        window: CancellationToken,
        addrs: Arc<WindowAddrs>,
        ip: IpAddr,
    ) {
        let (member, other_group) = (self.member_at(ip), self.other_group.clone());
        tokio::spawn(async move {
            select! {
                () = token.cancelled() => {},
                () = connect_at(context, member, window, addrs, other_group) => {},
            }
        });
    }

    /// Ends the invite window `generation` (`None`: whichever is open):
    /// announcing, searching and the salt query stop, `d_salt` is no longer
    /// offered, no new device is asked about. `false` if that window isn't
    /// open (ended already, or a newer one is open).
    pub(super) async fn end_invite(&self, generation: Option<u64>) -> bool {
        let slot = {
            let mut invite = self.invite.write().await;
            let current = invite.as_ref().map(|slot| slot.generation);
            if generation.is_some_and(|wanted| current != Some(wanted)) {
                return false;
            }
            invite.take()
        };
        let Some(slot) = slot else {
            return false;
        };

        close_invite(&slot.window, &slot.offer).await;
        self.adding.store(false, Ordering::SeqCst);
        true
    }

    /// The user stops "Add device" before its 2 min are over. Pairings it
    /// was asking about are rejected (unless a join still asks about them).
    pub(super) async fn stop_add_device(&self) {
        if self.end_invite(None).await {
            info!("add device: stopped by the user");
            if !self.join_running().await {
                self.pairings.write().await.waiting.clear();
            }
        }
    }
}

/// Ends an invite window: the salt query stops and `d_salt` is no longer
/// offered to anyone.
pub(super) async fn close_invite(window: &CancellationToken, offer: &SaltOffer) {
    window.cancel();
    *offer.write().await = None;
}

/// An open invite window ([`Daemon::open_invite`]).
pub(super) struct Invite {
    pub(super) context: NetworkerContext,
    /// The network's token: the window ends with networking.
    pub(super) token: CancellationToken,
    /// This window's discovery id.
    pub(super) id: InstanceId,
    /// Cancelled when the window ends; stops the salt query.
    pub(super) window: CancellationToken,
    /// This window's generation (see [`Daemon::end_invite`]).
    pub(super) generation: u64,
    /// The addresses this window works with (see [`WindowAddrs`]).
    pub(super) addrs: Arc<WindowAddrs>,
}

/// The LAN part of the invite window ([`Daemon::add_device`]): announce
/// this device until `window` ends, and meanwhile search for other members
/// and connect to every one found; waits for those connections.
pub(super) async fn invite_window(
    context: NetworkerContext,
    id: InstanceId,
    window: CancellationToken,
    other_group: Arc<AtomicBool>,
    addrs: Arc<WindowAddrs>,
) {
    tokio::join!(
        announce_until(id, window.clone()),
        search_and_connect(context, id, window.clone(), other_group, addrs),
    );
}

/// "Add device" with a typed address (a device on another network, e.g.
/// behind a VPN, that discovery can't reach): asks the device there for
/// its group salt every [`JOIN_RETRY_PAUSE`] until its own window is open
/// (the salt query only exists then), then connects once. A device of
/// another group is reported instead (as in [`on_found`]). Unlike a found
/// device it doesn't wait for the other side to connect: the user named
/// it, and the other side may not see this one at all.
pub(super) async fn connect_at(
    context: NetworkerContext,
    member: MemberAddrs,
    window: CancellationToken,
    addrs: Arc<WindowAddrs>,
    other_group: Arc<AtomicBool>,
) {
    if !addrs.typed.claim(member.tcp.ip()).await {
        debug!(addr = %member.tcp, "add device: that address is waited for in this window already");
        return;
    }
    let own_a_salt = context.keys.read().await.a_salt.clone();
    info!(addr = %member.tcp, "add device: waiting for the device at the address to open Add device");

    loop {
        let check = select! {
            () = window.cancelled() => return,
            check = check_group(&own_a_salt, member.salt) => check,
        };
        match check {
            GroupCheck::Same => {
                if addrs.connected.claim(member.tcp.ip()).await {
                    // a full handshake: boxed, so the future isn't kept on the stack
                    let _ = Box::pin(connect_to(context, member.tcp)).await;
                } else {
                    debug!(addr = %member.tcp, "add device: connected to that device in this window already");
                }
                return;
            }
            GroupCheck::Different => {
                warn!(addr = %member.tcp, "the device at the address is in a different group (other salts): not connecting; to add it, reset it and use Join on it");
                other_group.store(true, Ordering::SeqCst);
                return;
            }
            GroupCheck::Unknown => {
                debug!(addr = %member.tcp, "no Add device window at the address yet");
                select! {
                    () = window.cancelled() => return,
                    () = sleep(Duration::from_secs(JOIN_RETRY_PAUSE)) => {},
                }
            }
        }
    }
}

/// What a found device's salt says about its group.
#[derive(Debug, PartialEq)]
pub(super) enum GroupCheck {
    /// Same `a_salt`: a device of this group.
    Same,
    /// Another `a_salt`: a device of another group. SPAKE2 would fail for
    /// sure (the salt is bound into it), so connecting only costs both
    /// sides a guess-limiter slot.
    Different,
    /// No answer (no salt query there, rate limited, an older build).
    Unknown,
}

/// What the invite window does with one device it found.
#[derive(Debug, PartialEq)]
pub(super) enum Found {
    /// This side connects (lower id).
    Connect,
    /// The other side connects (it has the lower id).
    TheyConnect,
    /// Another group: nobody connects, the user is told.
    OtherGroup,
}

/// Decides about a device found during "Add device": a device of another
/// group is reported (`other_group`) instead of a doomed handshake, on both
/// sides whichever would connect; otherwise only the lower id connects, so
/// a pair makes one connection (and one prompt each), not two.
pub(super) async fn on_found(
    own_a_salt: &[u8; 32],
    salt_addr: SocketAddr,
    id: InstanceId,
    their_id: InstanceId,
    other_group: &AtomicBool,
) -> Found {
    if check_group(own_a_salt, salt_addr).await == GroupCheck::Different {
        warn!(%salt_addr, "found a device of a different group (other salts): not connecting; to add it, reset it and use Join on it");
        other_group.store(true, Ordering::SeqCst);
        return Found::OtherGroup;
    }

    if id < their_id {
        Found::Connect
    } else {
        Found::TheyConnect
    }
}

/// Asks the device at `salt_addr` for its group salt and compares it with
/// `own_a_salt`. Unauthenticated, like every salt answer: a forged answer
/// can at most make this device skip a real member (a DoS, like forged
/// announcements), never pair with the wrong one.
pub(super) async fn check_group(own_a_salt: &[u8; 32], salt_addr: SocketAddr) -> GroupCheck {
    match query_salt(salt_addr).await {
        Ok(theirs) if bool::from(theirs.as_slice().ct_eq(own_a_salt.as_slice())) => {
            GroupCheck::Same
        }
        Ok(_) => GroupCheck::Different,
        Err(_) => GroupCheck::Unknown,
    }
}

/// Announces this device in [`MAX_BROADCAST_DURATION`] rounds until `window`
/// is cancelled.
pub(super) async fn announce_until(id: InstanceId, window: CancellationToken) {
    while !window.is_cancelled() {
        select! {
            () = window.cancelled() => break,
            announced = udp_broadcast_presence(MAX_BROADCAST_DURATION, id) => {
                if let Err(e) = announced {
                    warn!(error = %e, "announcing this device failed");
                    // no busy loop on a failing socket
                    select! {
                        () = window.cancelled() => break,
                        () = sleep(Duration::from_secs(JOIN_RETRY_PAUSE)) => {},
                    }
                }
            },
        }
    }
}

/// Searches in [`ADD_DEVICE_SEARCH`] rounds until `window` ends for other
/// members with the window open, connects once to every new one this side
/// should connect to, then waits for those connections. Searching the whole
/// window (not only its start) matters: the two users rarely press "Add
/// device" at the same moment, and only the lower id connects.
pub(super) async fn search_and_connect(
    context: NetworkerContext,
    id: InstanceId,
    window: CancellationToken,
    other_group: Arc<AtomicBool>,
    addrs: Arc<WindowAddrs>,
) {
    let own_a_salt = context.keys.read().await.a_salt.clone();
    let mut connects = JoinSet::new();

    while !window.is_cancelled() {
        let found = select! {
            () = window.cancelled() => break,
            found = udp_find_broadcasters(ADD_DEVICE_SEARCH, id) => found,
        };
        let found = match found {
            Ok(found) => found,
            Err(e) => {
                warn!(error = %e, "searching for devices failed");
                // no busy loop on a failing socket
                select! {
                    () = window.cancelled() => break,
                    () = sleep(Duration::from_secs(JOIN_RETRY_PAUSE)) => {},
                }
                continue;
            }
        };

        for (addr, their_id) in found {
            // each found device is checked once per window
            if !addrs.searched.claim(addr.ip()).await {
                continue;
            }

            // its own task: a device that doesn't answer the group check
            // (up to the timeouts) never holds up the search or the others
            let (context, own_a_salt, other_group, addrs) = (
                context.clone(),
                own_a_salt.clone(),
                other_group.clone(),
                addrs.clone(),
            );
            connects.spawn(async move {
                // only the IP comes from discovery (an unauthenticated hint)
                let salt_addr = SocketAddr::new(addr.ip(), SALT_PORT);
                match on_found(&own_a_salt, salt_addr, id, their_id, &other_group).await {
                    // one connection per device and window (typed ones included)
                    Found::Connect if addrs.connected.claim(addr.ip()).await => {
                        // a full handshake: boxed, so the future isn't kept on the stack
                        Box::pin(connect_to(context, SocketAddr::new(addr.ip(), TCP_PORT))).await
                    }
                    Found::Connect => {
                        debug!(%addr, "connected to that device in this window already");
                        Ok(())
                    }
                    Found::TheyConnect => {
                        debug!(%addr, "found device connects to us");
                        Ok(())
                    }
                    Found::OtherGroup => Ok(()),
                }
            });
        }
    }

    while connects.join_next().await.is_some() {}
}

/// One outgoing `ConnectNewDevice` connection: authenticates, and pairs if
/// the two devices don't know each other yet (the user is asked).
pub(super) async fn connect_to(
    context: NetworkerContext,
    addr: SocketAddr,
) -> Result<(), TcpNetworkerErrors> {
    let stream = timeout(Duration::from_secs(TIMEOUT), TcpStream::connect(addr))
        .await
        .map_err(|_| TcpNetworkerErrors::FailedToConnect)?
        .map_err(|_| TcpNetworkerErrors::FailedToConnect)?;

    // a full handshake: boxed, so the future isn't kept on the stack
    let result = Box::pin(tcp_networker::connect_handler(
        context,
        addr,
        stream,
        ActionType::ConnectNewDevice,
        Zeroizing::new(Vec::new()),
    ))
    .await;

    match &result {
        Ok(()) => info!(%addr, "connected to the device"),
        Err(e) => warn!(%addr, error = %e, "connecting to the device failed"),
    }

    result
}
