use sha2::{Digest};

pub fn format_nonce<const N: usize, H: Digest + Default>(nonce_slice: Option<&[u8]>) -> [u8; N] {
    match nonce_slice {
        Some(n) if n.len() < N => {
            let mut padded = [0u8; N];
            padded[N - n.len()..].copy_from_slice(n);
            padded
        }
        Some(n) if n.len() > N => {
            let mut hasher = H::default();
            hasher.update(n);
            let hash = hasher.finalize();
            let mut hashed_nonce = [0u8; N];
            hashed_nonce.copy_from_slice(&hash[..N]);
            hashed_nonce
        }
        Some(n) => {
            let mut exact = [0u8; N];
            exact.copy_from_slice(n);
            exact
        }
        None => [0u8; N],
    }
}
