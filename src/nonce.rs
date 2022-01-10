use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

pub fn generate_nonce() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect()
}
