use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

/// Generates a secure nonce.
pub fn generate_nonce() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(17)
        .map(char::from)
        .collect()
}
