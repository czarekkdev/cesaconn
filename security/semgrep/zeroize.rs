// Fixtures for zeroize.yml — run: semgrep --test security/semgrep
use zeroize::Zeroizing;

fn raw_buffers(data: &[u8]) {
    // ruleid: cesa.zeroize.raw-secret-buffer
    let mut keys_bytes = [0u8; 64];
    // ruleid: cesa.zeroize.raw-secret-buffer
    let shared_secret: [u8; 32] = derive();
    // ruleid: cesa.zeroize.raw-secret-buffer
    let psk = vec![0u8; 32];
    // ruleid: cesa.zeroize.raw-secret-buffer
    let a_key: Vec<u8> = data.to_vec();
    // ok: cesa.zeroize.raw-secret-buffer
    let key = Zeroizing::new([0u8; 32]);
    // ok: cesa.zeroize.raw-secret-buffer
    let public_key = [0u8; 32];
    // ok: cesa.zeroize.raw-secret-buffer
    let key_len = [0u8; 4];
    // ok: cesa.zeroize.raw-secret-buffer
    let buf = [0u8; 1024];
}

async fn copy_out(keys: Arc<RwLock<Keys>>) {
    // ruleid: cesa.zeroize.raw-secret-buffer, cesa.zeroize.copy-out-of-zeroizing
    let raw_key: [u8; 32] = *keys.read().await.a_key;
    // ok: cesa.zeroize.copy-out-of-zeroizing
    let k = encrypt(&*keys.read().await.a_key, b"x");
    // ok: cesa.zeroize.copy-out-of-zeroizing
    let z = Zeroizing::new(*keys.read().await.d_key);
}

fn to_vec(secret: &[u8], kp: &KeyPair) {
    // ruleid: cesa.zeroize.secret-to-vec
    let a = secret.to_vec();
    // ruleid: cesa.zeroize.secret-to-vec
    let b = kp.private_key.to_vec();
    // ok: cesa.zeroize.secret-to-vec
    let c = Zeroizing::new(secret.to_vec());
    // ok: cesa.zeroize.secret-to-vec
    let d = kp.public.to_vec();
}

fn logging(a_key: &[u8], key_len: usize) {
    // ruleid: cesa.zeroize.secret-in-log
    println!("key = {:?}", a_key);
    // ruleid: cesa.zeroize.secret-in-log
    tracing::debug!("derived {a_key:x?}");
    // ruleid: cesa.zeroize.secret-in-log
    error!("bad: {:?}", keys.d_key);
    // ok: cesa.zeroize.secret-in-log
    error!("failed to set local key");
    // ok: cesa.zeroize.secret-in-log
    println!("key len {}", key_len);
    // ok: cesa.zeroize.secret-in-log
    info!("public: {:?}", public_key);
}

// ruleid: cesa.zeroize.debug-derive-on-secret
#[derive(Debug, Clone)]
pub struct Keys {
    pub a_key: Zeroizing<[u8; 32]>,
    pub d_key: Zeroizing<[u8; 32]>,
}

// ok: cesa.zeroize.debug-derive-on-secret
#[derive(Clone)]
pub struct Keys2 {
    pub a_key: Zeroizing<[u8; 32]>,
}

pub struct Plain {
    // ruleid: cesa.zeroize.secret-struct-field-plain
    pub private_key: [u8; 32],
    // ok: cesa.zeroize.secret-struct-field-plain
    pub public_key: [u8; 32],
    // ok: cesa.zeroize.secret-struct-field-plain
    pub a_key: Zeroizing<[u8; 32]>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Wiped {
    // ok: cesa.zeroize.secret-struct-field-plain
    seed: [u8; 32],
}

fn leaks(k: Keys) {
    // ruleid: cesa.zeroize.mem-forget
    std::mem::forget(k);
    // ruleid: cesa.zeroize.mem-forget
    let s: &'static mut [u8] = Box::leak(b);
    // ruleid: cesa.zeroize.manually-drop
    let m = ManuallyDrop::new(k);
}

#[cfg(test)]
mod tests {
    fn t() {
        // ok: cesa.zeroize.raw-secret-buffer
        let key = [7u8; 32];
    }
}

impl Keys {
    pub fn update(&mut self, data: Self) {
        // ok: cesa.zeroize.copy-out-of-zeroizing
        *self.a_key = *data.a_key;
    }
}

fn multiline(device_keypairs: &K) {
    // ok: cesa.zeroize.secret-to-vec
    let ver = device_keypairs
        .mldsa_kep
        .verification_key
        .to_vec();
}

impl Keys {
    // ruleid: cesa.zeroize.secret-param-by-value
    pub fn new(a_key: [u8; 32], d_key_ref: &[u8; 32]) -> Self { todo!() }
    // ok: cesa.zeroize.secret-param-by-value
    pub fn new2(x25519_pub_key: [u8; 32], k: Zeroizing<[u8; 32]>) -> Self { todo!() }
}
