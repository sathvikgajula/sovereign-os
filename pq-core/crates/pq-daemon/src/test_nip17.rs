use nostr_sdk::prelude::*;
fn test(keys: &Keys, event: &Event) {
    let unwrap = nip59::extract_rumor(keys, event);
}
