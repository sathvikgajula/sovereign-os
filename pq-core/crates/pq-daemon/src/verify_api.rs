use nostr_sdk::prelude::*;
use arti_client::{BootstrapStatus};
use tor_socksproto::{SocksRequest};

pub fn verify() {
    let builder = EventBuilder::new(Kind::TextNote, "test");
    let event = builder.build(Keys::generate().public_key());
    let _ = event.discovery();
}
