use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

pub fn generate_nonce() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(11)
        .map(char::from)
        .collect()
}
