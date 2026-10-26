// Fixtures for locks.yml
use std::sync::Arc;
use tokio::sync::RwLock;

async fn reacquire(keys: Arc<RwLock<Keys>>) {
    // ruleid: cesa.race.check-then-act
    let g = keys.read().await;
    // ruleid: cesa.lock.reacquire-same-lock, cesa.lock.guard-held-across-await
    keys.write().await.a_key = g.a_key.clone();
}

async fn reacquire_rr(peers: Arc<RwLock<Vec<u8>>>) {
    let mut w = peers.write().await;
    w.push(1);
    // ruleid: cesa.lock.reacquire-same-lock, cesa.lock.guard-held-across-await
    let n = peers.read().await.len();
}

async fn dropped_ok(peers: Arc<RwLock<Vec<u8>>>) {
    // still a check-then-act window between the two guards:
    // ruleid: cesa.race.check-then-act
    let g = peers.read().await;
    let n = g.len();
    drop(g);
    // ok: cesa.lock.reacquire-same-lock
    peers.write().await.push(n as u8);
}

async fn temporaries_ok(keys: Arc<RwLock<Keys>>, salts: Arc<RwLock<Salts>>) {
    // ok: cesa.lock.reacquire-same-lock
    keys.write().await.a_key.clone_from_slice(&d[1..33]);
    // ok: cesa.lock.reacquire-same-lock
    keys.write().await.d_key.clone_from_slice(&d[33..65]);
}

async fn scoped_ok(peers: Arc<RwLock<Vec<u8>>>) {
    {
        let g = peers.read().await;
        g.len();
    }
    // ok: cesa.lock.reacquire-same-lock
    peers.write().await.push(1);
}

async fn blocking(l: Arc<RwLock<u8>>) {
    // ruleid: cesa.lock.blocking-lock-in-async
    let g = l.blocking_read();
}

fn sync_blocking_ok(l: Arc<RwLock<u8>>) {
    // ok: cesa.lock.blocking-lock-in-async
    let g = l.blocking_read();
}

async fn across_await(peers: Arc<RwLock<Vec<u8>>>, s: &mut TcpStream) {
    let g = peers.write().await;
    // ruleid: cesa.lock.guard-held-across-await
    s.write_all(&g).await?;
}

async fn across_await_ok(peers: Arc<RwLock<Vec<u8>>>, s: &mut TcpStream) {
    let g = peers.read().await;
    let copy = g.clone();
    drop(g);
    // ok: cesa.lock.guard-held-across-await
    s.write_all(&copy).await?;
}

async fn nested(keys: Arc<RwLock<Keys>>, salts: Arc<RwLock<Salts>>) {
    let k = keys.write().await;
    // ruleid: cesa.lock.nested-different-locks, cesa.lock.guard-held-across-await
    let s = salts.write().await;
}

async fn scrutinee(peers: Arc<RwLock<Vec<u8>>>) {
    // ruleid: cesa.lock.guard-in-scrutinee
    for p in peers.read().await.iter() {
        connect(p).await;
    }
    // ruleid: cesa.lock.guard-in-scrutinee
    match peers.read().await.first() {
        Some(x) => {}
        None => {}
    }
}

async fn check_then_act(trusted: Arc<RwLock<Vec<SocketAddr>>>, a: SocketAddr) {
    // ruleid: cesa.race.check-then-act
    if !trusted.read().await.contains(&a) {
        trusted.write().await.push(a);
    }
}

async fn lost_update(trusted: Arc<RwLock<Vec<SocketAddr>>>) {
    // ruleid: cesa.race.check-then-act
    let snapshot = trusted.read().await.clone();
    trusted.write().await.extend(snapshot.iter().filter(|x| ok(x)));
}

async fn single_guard_ok(trusted: Arc<RwLock<Vec<SocketAddr>>>, a: SocketAddr) {
    let mut t = trusted.write().await;
    // ok: cesa.race.check-then-act
    if !t.contains(&a) {
        t.push(a);
    }
}

fn try_lock(l: Arc<RwLock<u8>>) {
    // ruleid: cesa.lock.try-lock-unwrap
    let g = l.try_read().unwrap();
}

// ruleid: cesa.race.static-mut
static mut COUNTER: u32 = 0;

struct P(*mut u8);
// ruleid: cesa.race.unsafe-send-sync
unsafe impl Send for P {}

fn atomics(f: &AtomicBool) {
    // ruleid: cesa.race.relaxed-atomic
    f.store(true, Ordering::Relaxed);
    // ok: cesa.race.relaxed-atomic
    f.store(true, Ordering::Release);
}

async fn iflet(peers: Arc<RwLock<Vec<u8>>>) {
    // ruleid: cesa.lock.guard-in-scrutinee
    if let Some(p) = peers.read().await.first() {
        connect(p).await;
    }
    let first = peers.read().await.first().cloned();
    // ok: cesa.lock.guard-in-scrutinee
    if let Some(p) = first {
        connect(p).await;
    }
}
