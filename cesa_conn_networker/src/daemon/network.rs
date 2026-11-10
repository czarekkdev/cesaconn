//! Networking: starting and stopping it with the state, the listener,
//! and the bridge between the handshakes and the pairing prompts.

use super::*;

impl Daemon {
    /// Starts or stops networking to match the state: it runs exactly while
    /// the vault is open with both keys and the Sync switch is on.
    pub(super) async fn apply_network(self: &Arc<Self>) {
        let wanted = {
            let keys = self.keys.read().await;
            match &keys.vault {
                Some(open)
                    if open.config.sync
                        && !keys.locked
                        && keys.a_key.is_some()
                        && keys.d_key.is_some() =>
                {
                    Some(open.identity.clone())
                }
                _ => None,
            }
        };

        let running = self
            .network
            .read()
            .await
            .as_ref()
            .is_some_and(Network::running);

        match (wanted, running) {
            (Some(identity), false) => self.start_network(identity).await,
            // the bridge finishes on its own, nobody needs to wait here
            (None, true) => drop(self.stop_network().await),
            _ => {}
        }
    }

    /// Starts the TCP listener and the pairing bridge with this device's
    /// identity, the shared keys and trusted peers.
    pub(super) async fn start_network(
        self: &Arc<Self>,
        identity: Zeroizing<[u8; IDENTITY_SEED_LEN]>,
    ) {
        // copies (zeroizing) under the guard, which is dropped right away
        let keys = {
            let keys = self.keys.read().await;
            match (&keys.a_key, &keys.a_salt, &keys.d_key) {
                (Some(a_key), Some(a_salt), Some(d_key)) => {
                    Keys::new(a_key.clone(), a_salt, d_key.clone())
                }
                _ => return,
            }
        };

        let listener = match TcpListener::bind(self.listen_addr).await {
            Ok(listener) => listener,
            Err(e) => {
                error!(error = %e, addr = %self.listen_addr, "failed to start the TCP listener: networking stays off");
                return;
            }
        };
        let local_addr = match listener.local_addr() {
            Ok(addr) => addr,
            Err(e) => {
                error!(error = %e, "failed to read the TCP listener's address: networking stays off");
                return;
            }
        };

        let (pairing, inbox) = Pairing::channel();
        let token = CancellationToken::new();
        let (clip_sender, clip_inbox) = mpsc::channel(CLIP_INBOX);
        let context = NetworkerContext {
            keys: Arc::new(RwLock::new(keys)),
            device_keypairs: Arc::new(DeviceKeypairs::from_seed(&identity)),
            trusted_peers: self.peer_list().await,
            pairing,
            guess_limiter: self.guess_limiter.clone(),
            // offered only while an invite window is open
            salt_offer: Arc::default(),
            peer_book: self.peer_book.clone(),
            peer_port: self.peer_port.load(Ordering::SeqCst),
            clipboard: Some(clip_sender),
        };
        drop(identity);

        listen(listener, context.clone(), token.clone());
        let bridge = tokio::spawn(self.clone().pairing_bridge(inbox, token.clone()));
        // without an OS clipboard the inbox is dropped: updates are `Ignored`
        if let Some(clipboard) = self.clipboard.clone() {
            tokio::spawn(self.clone().clipboard_task(
                clipboard,
                clip_inbox,
                context.clone(),
                token.clone(),
            ));
        }
        // the paired devices hear from us: a password that differs shows at once
        tokio::spawn(self.clone().hello_round(context.clone(), token.clone()));

        // check-then-act under one write guard; nothing is awaited while held
        let mut network = self.network.write().await;
        if network.as_ref().is_some_and(Network::running) {
            drop(network);
            // started twice (can't happen under the change slot): undo this one
            token.cancel();
            return;
        }
        *network = Some(Network {
            token,
            context,
            bridge,
        });
        // a new network has no "Add device" window, whatever the last one
        // had (a listener that failed on its own never closed its window)
        self.adding.store(false, Ordering::SeqCst);
        drop(network);

        info!(%local_addr, "networking on: listening for paired devices");
    }

    /// Stops networking; returns the bridge, which saves the peers once
    /// more and ends (awaited at shutdown only: it needs the change slot).
    pub(super) async fn stop_network(&self) -> Option<JoinHandle<()>> {
        let network = self.network.write().await.take()?;

        network.token.cancel();
        // the invite window ends with networking (salt port, offer)
        self.end_invite(None).await;
        self.adding.store(false, Ordering::SeqCst);
        // dropped = rejected; the handshakes tell their peers
        self.pairings.write().await.waiting.clear();
        info!("networking off");

        Some(network.bridge)
    }

    /// Hands changed keys to the running connections.
    pub(super) async fn update_network_keys(self: &Arc<Self>) {
        let keys = {
            let keys = self.keys.read().await;
            match (&keys.a_key, &keys.a_salt, &keys.d_key) {
                (Some(a_key), Some(a_salt), Some(d_key)) => {
                    Keys::new(a_key.clone(), a_salt, d_key.clone())
                }
                _ => return,
            }
        };

        // the networker's own lock, taken after the daemon's is released
        let running = self
            .network
            .read()
            .await
            .as_ref()
            .filter(|network| network.running())
            .map(|network| (network.context.clone(), network.token.clone()));

        // what the old keys showed no longer holds (and pauses end)
        self.peer_book.keys_changed().await;

        if let Some((context, token)) = running {
            *context.keys.write().await = keys;
            // the paired devices are asked again with the new keys at once
            tokio::spawn(self.clone().hello_round(context, token));
        }
    }

    /// Between the handshakes and the UI: queues pairing requests for the
    /// user and saves the peers after a pairing. Ends with networking.
    pub(super) async fn pairing_bridge(
        self: Arc<Self>,
        mut inbox: PairingInbox,
        token: CancellationToken,
    ) {
        loop {
            select! {
                () = token.cancelled() => break,
                request = inbox.requests.recv() => match request {
                    Some(request) => self.queue_pairing(request).await,
                    None => break,
                },
                // its own task: the bridge keeps taking requests while the
                // save waits for the change slot
                () = inbox.saved.notified() => {
                    let daemon = self.clone();
                    tokio::spawn(async move { daemon.save_peers().await });
                }
                // a paired device moved: its new address is saved too
                () = self.peer_book.changed.notified() => {
                    let daemon = self.clone();
                    tokio::spawn(async move { daemon.save_peers().await });
                }
            }
        }

        // (waiting requests were dropped by stop_network: rejected)

        // a pairing that finished just as networking stopped is saved too
        self.save_peers().await;
    }

    /// Keeps `request` for the user, or rejects it: outside the
    /// "Add device" window or a join nobody asked to pair, and the queue is
    /// bounded.
    pub(super) async fn queue_pairing(&self, request: PairingRequest) {
        if !self.adding.load(Ordering::SeqCst) && !self.join_running().await {
            warn!(name = %request.name, "pairing request outside \"Add device\", rejected");
            request.answer(false);
            return;
        }

        let mut pairings = self.pairings.write().await;
        pairings.prune();

        if pairings.waiting.len() >= MAX_PENDING_PAIRINGS {
            drop(pairings);
            warn!(name = %request.name, "too many pairings waiting, rejected");
            request.answer(false);
            return;
        }

        let id = pairings.next_id;
        pairings.next_id = id.wrapping_add(1);
        info!(id, name = %request.name, "new device wants to pair: waiting for the user");
        pairings.waiting.push((id, request));
    }

    /// The oldest pairing still waiting for the user.
    pub(super) async fn pending_pairing(&self) -> Option<PairingPrompt> {
        let mut pairings = self.pairings.write().await;
        pairings.prune();

        pairings.waiting.first().map(|(id, request)| PairingPrompt {
            id: *id,
            name: request.name.clone(),
            code: request.code,
        })
    }

    /// The user's answer to pairing `id`. The answer names the code the
    /// user saw: ids start again after a restart, so an id alone could
    /// accept a pairing nobody compared.
    pub(super) async fn answer_pairing(
        &self,
        id: u32,
        code: &PairingCode,
        accept: bool,
    ) -> Result<(), DaemonError> {
        let request = {
            let mut pairings = self.pairings.write().await;
            pairings.prune();
            let index = pairings
                .waiting
                .iter()
                .position(|(waiting, request)| *waiting == id && request.code == *code)
                .ok_or(DaemonError::PairingExpired)?;
            pairings.waiting.remove(index).1
        };

        info!(id, name = %request.name, accept, "pairing answered");
        request.answer(accept);
        Ok(())
    }
}

/// Runs the accept loop in its own task until the token is cancelled. If
/// it fails on its own, it cancels the token, so all of networking stops.
pub(super) fn listen(listener: TcpListener, context: NetworkerContext, token: CancellationToken) {
    tokio::spawn(async move {
        // the accept loop runs until the token is cancelled; every
        // connection in it has its own timeouts and handshake deadline
        // nosemgrep: cesa.net.read-without-timeout
        let result = tcp_networker::recv(&listener, context, token.clone()).await;

        if let Err(e) = result {
            error!(error = %e, "TCP listener stopped: networking off");
            token.cancel();
        }
    });
}
