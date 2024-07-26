use ed25519_dalek::PUBLIC_KEY_LENGTH;

pub fn ed25519_public_key_to_key_id(public_key: &[u8; PUBLIC_KEY_LENGTH]) -> u8 {
    *public_key
        .last()
        .expect("fixed size array has a last element")
}
