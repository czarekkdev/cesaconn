//! Clipboard sync (design doc 12) and the hello (13.1): the clipboard
//! task, and the send rounds to every paired device.

use super::*;

impl Daemon {
    /// Clipboard sync while networking runs: applies updates from paired
    /// devices (`inbox`) and sends this device's new clipboard text to them.
    ///
    /// The clipboard's change counter is polled every [`CLIP_POLL_MS`]; a
    /// change is sent once the counter held still for one more poll (fast
    /// repeated copies send the last one), and only while no earlier send
    /// round runs (the latest text goes when it ends). An update applied
    /// here moves the counter too: that counter is taken as seen, so it is
    /// never sent back. Content marked concealed / transient by a password
    /// manager is never read. Nothing is read or applied while the switch
    /// is off.
    pub(super) async fn clipboard_task(
        self: Arc<Self>,
        clipboard: Arc<dyn Clipboard>,
        mut inbox: mpsc::Receiver<ClipDelivery>,
        context: NetworkerContext,
        token: CancellationToken,
    ) {
        // random per run: the receivers' ordering starts over with it
        let Ok(epoch) = random_array::<8>() else {
            error!("failed to generate a clipboard epoch: clipboard sync stays off");
            return;
        };
        let mut seq = 0u64;
        let mut ordering = clip_sync::UpdateOrder::default();
        // what is on the clipboard now was copied before: never sent
        let Some(start) = self.clip_count(&clipboard).await else {
            error!("the clipboard can't be read: clipboard sync stays off");
            return;
        };
        let mut watch = ClipWatch::new(start);
        let mut round: Option<JoinHandle<()>> = None;

        loop {
            select! {
                () = token.cancelled() => break,
                delivery = inbox.recv() => {
                    let Some(delivery) = delivery else { break };
                    let ack = self
                        .apply_clip(&clipboard, &mut ordering, &delivery, &mut watch)
                        .await;
                    // the connection may have given up waiting: nothing to do then
                    let _ = delivery.answer.send(ack);
                }
                () = sleep(Duration::from_millis(CLIP_POLL_MS)) => {
                    let on = self.clipboard_on().await;
                    // a failed read is no change (a made-up counter would be one)
                    let Some(count) = self.clip_count(&clipboard).await else {
                        continue;
                    };
                    let busy = round.as_ref().is_some_and(|round| !round.is_finished());
                    if watch.tick(on, count, busy) == ClipTick::Wait {
                        continue;
                    }

                    let Some(payload) = self.read_clip(&clipboard, &epoch, &mut seq).await else {
                        continue;
                    };
                    round = Some(tokio::spawn(self.clone().send_round(
                        context.clone(),
                        token.clone(),
                        ActionType::ClipboardSync,
                        payload,
                    )));
                }
            }
        }
    }

    /// The clipboard's change counter (read off the async workers); `None`
    /// if the read failed.
    pub(super) async fn clip_count(&self, clipboard: &Arc<dyn Clipboard>) -> Option<i64> {
        let clipboard = clipboard.clone();
        blocking(move || clipboard.change_count()).await.ok()
    }

    /// Reads the clipboard text and encodes the next update; `None` for
    /// nothing to send (no text, concealed, too long).
    pub(super) async fn read_clip(
        &self,
        clipboard: &Arc<dyn Clipboard>,
        epoch: &[u8; 8],
        seq: &mut u64,
    ) -> Option<Arc<Zeroizing<Vec<u8>>>> {
        let clipboard = clipboard.clone();
        let text = match blocking(move || clipboard.read_text(CLIP_MAX_LEN)).await {
            Ok(ClipRead::Text(text)) => text,
            Ok(ClipRead::Concealed) => {
                debug!("clipboard content marked concealed: not synced");
                return None;
            }
            Ok(ClipRead::TooLarge) => {
                info!(max = CLIP_MAX_LEN, "clipboard text too long: not synced");
                return None;
            }
            Ok(ClipRead::NoText) | Err(_) => return None,
        };

        *seq = seq.saturating_add(1);
        let payload = clip_sync::encode(epoch, *seq, &text)?;
        debug!(len = text.len(), seq = *seq, "clipboard changed: sending");
        Some(Arc::new(payload))
    }

    /// Applies an update from a paired device: only with the switch on,
    /// only a well-formed one, only newer than the last one from that
    /// device. The counter of our own write is taken as seen.
    pub(super) async fn apply_clip(
        &self,
        clipboard: &Arc<dyn Clipboard>,
        ordering: &mut clip_sync::UpdateOrder,
        delivery: &ClipDelivery,
        watch: &mut ClipWatch,
    ) -> DataAck {
        if !self.clipboard_on().await {
            return DataAck::Ignored;
        }
        let Some(message) = clip_sync::decode(&delivery.payload) else {
            warn!(peer = %delivery.peer.name(), "malformed clipboard update, ignored");
            return DataAck::Ignored;
        };
        if !ordering.accept(delivery.peer.static_key(), &message.epoch, message.seq) {
            debug!(peer = %delivery.peer.name(), seq = message.seq, "older clipboard update, ignored");
            return DataAck::Ignored;
        }

        let (clipboard, text) = (clipboard.clone(), message.text);
        let len = text.len();
        match blocking(move || clipboard.write_text(&text)).await {
            Ok(Some(count)) => {
                watch.written(count);
                info!(peer = %delivery.peer.name(), len, seq = message.seq, "clipboard updated from a paired device");
                DataAck::Applied
            }
            _ => {
                warn!(peer = %delivery.peer.name(), "the OS refused the clipboard update");
                DataAck::Ignored
            }
        }
    }

    /// Sends `Hello` to every paired device at its last address.
    pub(super) async fn hello_round(
        self: Arc<Self>,
        context: NetworkerContext,
        token: CancellationToken,
    ) {
        let payload = Arc::new(Zeroizing::new(HELLO_PAYLOAD.to_vec()));
        self.send_round(context, token, ActionType::Hello, payload)
            .await;
    }

    /// Sends `payload` to every paired device at its last address that
    /// isn't paused, all at once, each bounded by [`SEND_DEADLINE`]; ends
    /// when every send did, or with networking.
    pub(super) async fn send_round(
        self: Arc<Self>,
        context: NetworkerContext,
        token: CancellationToken,
        action_type: ActionType,
        payload: Arc<Zeroizing<Vec<u8>>>,
    ) {
        let peers = self.trusted_copy().await;
        let targets = self.peer_book.targets(&peers).await;
        let mut sends = JoinSet::new();
        for (peer, addr) in targets {
            sends.spawn(send_to(
                context.clone(),
                peer,
                addr,
                action_type,
                payload.clone(),
            ));
        }

        select! {
            () = token.cancelled() => sends.abort_all(),
            () = async { while sends.join_next().await.is_some() {} } => {}
        }
    }
}

/// What one clipboard poll decided.
#[derive(Debug, PartialEq)]
pub(super) enum ClipTick {
    /// Nothing to send now.
    Wait,
    /// Read the clipboard and send it.
    Send,
}

/// The clipboard task's view of the clipboard's change counter (12.3).
pub(super) struct ClipWatch {
    /// The counter last seen (or written by us).
    pub(super) last_count: i64,
    /// A change made while the switch was on waits to be sent.
    pub(super) pending: bool,
}

impl ClipWatch {
    pub(super) fn new(count: i64) -> Self {
        Self {
            last_count: count,
            pending: false,
        }
    }

    /// One poll: `count` is the counter now, `on` the switch, `busy` a send
    /// round still running. A change is sent once the counter held still
    /// for one more poll and no round runs; a change made while the switch
    /// is off, or the switch going off before it was sent, is never sent.
    pub(super) fn tick(&mut self, on: bool, count: i64, busy: bool) -> ClipTick {
        if count != self.last_count {
            self.last_count = count;
            self.pending = on;
            return ClipTick::Wait;
        }
        if !on {
            self.pending = false;
            return ClipTick::Wait;
        }
        if !self.pending || busy {
            return ClipTick::Wait;
        }
        self.pending = false;
        ClipTick::Send
    }

    /// We wrote `count` (an update from a paired device): taken as seen,
    /// so it is never sent back.
    pub(super) fn written(&mut self, count: i64) {
        self.last_count = count;
    }
}

/// One `Hello` or clipboard update to one paired device at `addr`: a
/// device that doesn't answer is shown as unreachable; a password that
/// differs is marked by the networker (`send_answered`).
pub(super) async fn send_to(
    context: NetworkerContext,
    peer: TrustedPeer,
    addr: SocketAddr,
    action_type: ActionType,
    payload: Arc<Zeroizing<Vec<u8>>>,
) {
    let peer_book = context.peer_book.clone();
    let stream = match timeout(Duration::from_secs(TIMEOUT), TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => stream,
        _ => {
            debug!(%addr, peer = %peer.name(), "paired device not reachable");
            peer_book.set_state(&peer, PeerState::Unreachable).await;
            return;
        }
    };

    // a full handshake: boxed, so the future isn't kept on the stack
    let sent = timeout(
        Duration::from_secs(SEND_DEADLINE),
        Box::pin(tcp_networker::send_answered(
            context,
            addr,
            stream,
            action_type,
            &payload,
        )),
    )
    .await;

    match sent {
        Ok(Ok((answered, ack))) => {
            debug!(%addr, peer = %answered.name(), action_type = ?action_type, ack = ?ack, "sent to a paired device");
        }
        Ok(Err(TcpNetworkerErrors::WrongPassword)) => {
            warn!(%addr, peer = %peer.name(), "the paired device uses a different auth password");
        }
        Ok(Err(e)) => {
            warn!(%addr, peer = %peer.name(), error = %e, "sending to a paired device failed")
        }
        Err(_) => warn!(%addr, peer = %peer.name(), "sending to a paired device timed out"),
    }
}
