// Fixtures for network.yml
use crate::tcp_networker::recv;
async fn recv(conn: &mut TcpStream, init_buf: &[u8]) -> Result<(), E> {
    let size_bytes = &mut [0u8; 8];
    size_bytes.copy_from_slice(&init_buf[1..9]);
    // ruleid: cesa.net.unbounded-alloc-from-wire, cesa.net.wire-length-cast
    let size = u64::from_le_bytes(*size_bytes);
    let mut buf = vec![0u8; size as usize];
    timeout(D, conn.read_exact(&mut buf)).await??;
    Ok(())
}

async fn recv_cast(conn: &mut UnixStream) {
    let mut size_buffer = [0u8; 8];
    // ruleid: cesa.net.unbounded-alloc-from-wire, cesa.net.wire-length-cast
    let size = u64::from_le_bytes(size_buffer) as usize;
    let mut addrs_buffer = Vec::with_capacity(size);
}

async fn recv_checked(conn: &mut TcpStream, b: [u8; 8]) -> Result<(), E> {
    // ok: cesa.net.unbounded-alloc-from-wire
    let size = u64::from_le_bytes(b);
    if size > MAX_PACKET {
        return Err(E::TooBig);
    }
    // ok: cesa.net.unbounded-alloc-from-wire
    let buf = vec![0u8; usize::try_from(size)?];
    Ok(())
}

async fn recv_min(b: [u8; 4]) {
    // ok: cesa.net.unbounded-alloc-from-wire
    let size = u32::from_be_bytes(b);
    let capped = size.min(MAX);
    // ok: cesa.net.unbounded-alloc-from-wire
    let buf = vec![0u8; capped as usize];
}

fn compare(recv_plaintext: &[u8], auth_key: &[u8], confirm_recieved: &[u8], confirm_expect: &[u8], tag: Tags, len: usize) {
    // ruleid: cesa.net.non-constant-time-compare
    let confirmed = recv_plaintext == auth_key;
    // ruleid: cesa.net.non-constant-time-compare
    if confirm_expect != confirm_recieved { return; }
    // ok: cesa.net.non-constant-time-compare
    if confirm_expect.ct_eq(confirm_recieved).unwrap_u8() != 1 { return; }
    // ok: cesa.net.non-constant-time-compare
    if tag == Tags::IsSavedTag { return; }
    // ok: cesa.net.non-constant-time-compare
    if auth_key.len() == 32 { return; }
    // ok: cesa.net.non-constant-time-compare
    if *name == *message { return; }
}

fn nonces(cipher: Aes256Gcm, n: [u8; 12]) {
    // ruleid: cesa.net.static-aead-nonce
    cipher.encrypt(Nonce::from_slice(&[0u8; 12]), b"x");
    // ok: cesa.net.static-aead-nonce
    cipher.encrypt(Nonce::from_slice(&n), b"x");
}

async fn reads(stream: &mut TcpStream, socket: UdpSocket, keys: Arc<RwLock<Keys>>) {
    let mut buf = [0u8; 37];
    // ruleid: cesa.net.read-without-timeout
    stream.read_exact(&mut buf).await?;
    // ruleid: cesa.net.read-without-timeout
    let (len, addr) = socket.recv_from(&mut buf).await?;
    // ok: cesa.net.read-without-timeout
    timeout(Duration::from_secs(5), stream.read_exact(&mut buf)).await??;
    let read = stream.read_exact(&mut buf);
    // ok: cesa.net.read-without-timeout
    timeout(Duration::from_secs(TIMEOUT), read).await??;
    // ok: cesa.net.read-without-timeout
    let k = keys.read().await;
}

async fn binds() {
    // ruleid: cesa.net.bind-all-interfaces
    let socket = UdpSocket::bind("0.0.0.0:6363").await;
    // ok: cesa.net.bind-all-interfaces
    let l = TcpListener::bind("127.0.0.1:3232").await;
}

async fn unwraps(stream: &mut TcpStream, k: &[u8], p: &[u8]) {
    // ruleid: cesa.net.unwrap-on-io
    stream.write_all(&p).await.unwrap();
    // ruleid: cesa.net.unwrap-on-io
    let x = decrypt_tunnel(k, p).unwrap();
    // ok: cesa.net.unwrap-on-io
    stream.write_all(&p).await?;
}

#[cfg(test)]
mod tests {
    async fn t(stream: &mut TcpStream) {
        // ok: cesa.net.read-without-timeout, cesa.net.unwrap-on-io
        stream.read_exact(&mut [0u8; 4]).await.unwrap();
    }
}

fn modulo_is_not_a_bound(size_buffer: [u8; 8]) {
    // ruleid: cesa.net.unbounded-alloc-from-wire, cesa.net.wire-length-cast
    let size = u64::from_le_bytes(size_buffer) as usize;
    if size % 4 != 0 {
        return;
    }
    let mut addrs_buffer = vec![0u8; size];
}

fn upper_bound_ok(size_buffer: [u8; 8]) {
    // ok: cesa.net.unbounded-alloc-from-wire
    // ruleid: cesa.net.wire-length-cast
    let size = u64::from_le_bytes(size_buffer);
    if size == 0 || size > MAX {
        return;
    }
    let b = vec![0u8; size as usize];
}

async fn free_fn_named_recv(listener: &TcpListener) {
    // ok: cesa.net.read-without-timeout
    // ruleid: cesa.net.unwrap-on-io
    recv(
        &listener,
        keys,
    )
    .await
    .unwrap();
}
