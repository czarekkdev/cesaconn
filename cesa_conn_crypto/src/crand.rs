use nist_drbg_rs::{Drbg, HmacSha512Drbg, Policy};
use rand::{Rng, make_rng, rngs::StdRng};

// Wraps OS entropy in an HMAC-SHA512 DRBG (NIST SP 800-90A) so the output
// meets ML-KEM keygen entropy requirements. The personalization string
// domain-separates this generator from any other DRBG instances in the process.
pub fn random_array() -> [u8; 64] {
    let mut entropy = [0u8; 32];
    let mut nonce = [0u8; 16];

    make_rng::<StdRng>().fill_bytes(&mut entropy);
    make_rng::<StdRng>().fill_bytes(&mut nonce);

    let personalization_string = b"cesaconn-mlkem-keygen";

    let mut drbg = HmacSha512Drbg::new(&entropy, &nonce, personalization_string, Policy::default())
        .expect("sufficient entropy provided");

    let mut output = [0u8; 64];
    drbg.generate(&mut output).expect("counter not exhausted");

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_not_all_zeros() {
        let out = random_array();
        assert_ne!(out, [0u8; 64]);
    }

    #[test]
    fn consecutive_calls_differ() {
        let a = random_array();
        let b = random_array();
        assert_ne!(a, b);
    }

    // Verifies the DRBG layer is deterministic given fixed inputs, independent
    // of the OS RNG path exercised in random_array().
    #[test]
    fn drbg_is_deterministic_with_fixed_seed() {
        let entropy = [0x42u8; 32];
        let nonce = [0x13u8; 16];
        let personalization = b"cesaconn-mlkem-keygen";

        let mut drbg1 = HmacSha512Drbg::new(&entropy, &nonce, personalization, Policy::default())
            .expect("sufficient entropy provided");
        let mut drbg2 = HmacSha512Drbg::new(&entropy, &nonce, personalization, Policy::default())
            .expect("sufficient entropy provided");

        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        drbg1.generate(&mut out1).unwrap();
        drbg2.generate(&mut out2).unwrap();

        assert_eq!(out1, out2);
    }

    // Different personalization strings must produce different output to
    // confirm domain separation works at the DRBG level.
    #[test]
    fn different_personalization_produces_different_output() {
        let entropy = [0x55u8; 32];
        let nonce = [0x77u8; 16];

        let mut drbg_a = HmacSha512Drbg::new(&entropy, &nonce, b"cesaconn-mlkem-keygen", Policy::default())
            .expect("sufficient entropy provided");
        let mut drbg_b = HmacSha512Drbg::new(&entropy, &nonce, b"cesaconn-other-purpose", Policy::default())
            .expect("sufficient entropy provided");

        let mut out_a = [0u8; 64];
        let mut out_b = [0u8; 64];
        drbg_a.generate(&mut out_a).unwrap();
        drbg_b.generate(&mut out_b).unwrap();

        assert_ne!(out_a, out_b);
    }
}
