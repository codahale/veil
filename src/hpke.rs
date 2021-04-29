use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use strobe_rs::{SecParam, Strobe};

use crate::common::MAC_LEN;

pub fn encrypt(
    d_s: &Scalar,
    q_s: &RistrettoPoint,
    d_e: &Scalar,
    q_e: &RistrettoPoint,
    q_r: &RistrettoPoint,
    plaintext: &[u8],
) -> Vec<u8> {
    // Initialize the protocol.
    let mut hpke = Strobe::new(b"veil.hpke", SecParam::B256);
    hpke.meta_ad(&(MAC_LEN as u32).to_le_bytes(), false);

    // Include the sender and receiver as associated data.
    hpke.ad(q_s.compress().as_bytes(), false);
    hpke.ad(q_r.compress().as_bytes(), false);

    // Calculate the static Diffie-Hellman shared secret and key the protocol with it.
    let zz_s = d_s * q_r;
    hpke.key(zz_s.compress().as_bytes(), false);

    // Encode the ephemeral public key and encrypt it.
    let mut ct_q_e = q_e.compress().as_bytes().to_vec();
    hpke.send_enc(&mut ct_q_e, false);

    // Calculate the ephemeral Diffie-Hellman shared secret and key the protocol with it.
    let zz_e = d_e * q_r;
    hpke.key(zz_e.compress().as_bytes(), false);

    // Encrypt the plaintext.
    let mut ct = Vec::from(plaintext);
    hpke.send_enc(&mut ct, false);

    // Calculate a MAC of the entire operation transcript.
    let mut mac = [0u8; MAC_LEN].to_vec();
    hpke.send_mac(&mut mac, false);

    // Return the encrypted ephemeral public key, the ciphertext, and the MAC.
    let mut out = Vec::with_capacity(ct_q_e.len() + ct.len() + mac.len());
    out.append(&mut ct_q_e);
    out.append(&mut ct);
    out.append(&mut mac);

    out
}

pub fn decrypt(
    d_r: &Scalar,
    q_r: &RistrettoPoint,
    q_s: &RistrettoPoint,
    ciphertext: &[u8],
) -> Option<(RistrettoPoint, Vec<u8>)> {
    // Initialize the protocol.
    let mut hpke = Strobe::new(b"veil.hpke", SecParam::B256);
    hpke.meta_ad(&(MAC_LEN as u32).to_le_bytes(), false);

    // Include the sender and receiver as associated data.
    hpke.ad(q_s.compress().as_bytes(), false);
    hpke.ad(q_r.compress().as_bytes(), false);

    // Calculate the static Diffie-Hellman shared secret and key the protocol with it.
    let zz_s = d_r * q_s;
    hpke.key(zz_s.compress().as_bytes(), false);

    // Decrypt the ephemeral public key.
    let mut q_e_c = [0u8; 32];
    q_e_c.copy_from_slice(&ciphertext[..32]);
    hpke.recv_enc(&mut q_e_c, false);

    // Decode the ephemeral public key.
    let q_e = CompressedRistretto(q_e_c).decompress();
    if q_e.is_none() {
        return None;
    }

    // Calculate the ephemeral Diffie-Hellman shared secret and key the protocol with it.
    let zz_e = d_r * q_e.unwrap();
    hpke.key(zz_e.compress().as_bytes(), false);

    // Decrypt the plaintext.
    let mut plaintext = Vec::with_capacity(ciphertext.len() - 32 - MAC_LEN);
    plaintext.extend_from_slice(&ciphertext[32..ciphertext.len() - MAC_LEN]);
    hpke.recv_enc(&mut plaintext, false);

    // Verify the MAC.
    let mut mac = Vec::with_capacity(MAC_LEN);
    mac.extend_from_slice(&ciphertext[ciphertext.len() - MAC_LEN..]);
    if !hpke.recv_mac(&mut mac).is_ok() {
        return None;
    }

    // Return the ephemeral public key and the plaintext.
    Some((q_e.unwrap(), plaintext.to_vec()))
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    use rand_core::OsRng;

    use crate::hpke::{decrypt, encrypt};

    #[test]
    fn round_trip() {
        let (d_s, q_s, d_e, q_e, d_r, q_r) = setup();

        let ciphertext = encrypt(&d_s, &q_s, &d_e, &q_e, &q_r, b"this is an example");
        let (pk, plaintext) = decrypt(&d_r, &q_r, &q_s, &ciphertext).unwrap();

        assert_eq!(q_e, pk);
        assert_eq!(b"this is an example".to_vec(), plaintext);
    }

    #[test]
    fn bad_ephemeral_public_key() {
        let (d_s, q_s, d_e, q_e, d_r, q_r) = setup();

        let mut ciphertext = encrypt(&d_s, &q_s, &d_e, &q_e, &q_r, b"this is an example");

        ciphertext[0] ^= 1;

        let output = decrypt(&d_r, &q_r, &q_s, &ciphertext);

        assert_eq!(None, output);
    }

    #[test]
    fn bad_ciphertext() {
        let (d_s, q_s, d_e, q_e, d_r, q_r) = setup();

        let mut ciphertext = encrypt(&d_s, &q_s, &d_e, &q_e, &q_r, b"this is an example");

        ciphertext[36] ^= 1;

        let output = decrypt(&d_r, &q_r, &q_s, &ciphertext);

        assert_eq!(None, output);
    }

    #[test]
    fn bad_mac() {
        let (d_s, q_s, d_e, q_e, d_r, q_r) = setup();

        let mut ciphertext = encrypt(&d_s, &q_s, &d_e, &q_e, &q_r, b"this is an example");

        ciphertext[64] ^= 1;

        let output = decrypt(&d_r, &q_r, &q_s, &ciphertext);

        assert_eq!(None, output);
    }

    fn setup() -> (
        Scalar,
        RistrettoPoint,
        Scalar,
        RistrettoPoint,
        Scalar,
        RistrettoPoint,
    ) {
        let mut rng = OsRng::default();

        let d_s = Scalar::random(&mut rng);
        let q_s = RISTRETTO_BASEPOINT_POINT * d_s;

        let d_e = Scalar::random(&mut rng);
        let q_e = RISTRETTO_BASEPOINT_POINT * d_e;

        let d_r = Scalar::random(&mut rng);
        let q_r = RISTRETTO_BASEPOINT_POINT * d_r;

        (d_s, q_s, d_e, q_e, d_r, q_r)
    }
}
