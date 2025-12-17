pub mod app;

use serde::{Serialize, Deserialize};
use spacedb::NodeHasher;
use spaces_protocol::bitcoin::ScriptBuf;
use spaces_protocol::slabel::SLabel;
use spacedb::Sha256Hasher as sha256;
use libveritas::sname::{Label, SName};
pub extern crate spaces_protocol;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HandleRequest {
    pub handle: SName,
    pub script_pubkey: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Batch {
    pub space: SLabel,
    pub entries: Vec<BatchEntry>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BatchEntry {
    pub sub_label: Label,
    pub script_pubkey: ScriptBuf,
}

impl Batch {
    pub fn new(space: SLabel) -> Self {
        Batch {
            space,
            entries: Vec::new(),
        }
    }

    pub fn extend(&mut self, other: Self) {
        self.entries.extend(other.entries)
    }

    pub fn to_zk_input(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        let space_hash = sha256::hash(self.space.as_ref());
        bytes.extend_from_slice(&space_hash);

        for entry in &self.entries {
            let subspace_hash = sha256::hash(entry.sub_label.as_slabel().as_ref());
            bytes.extend_from_slice(&subspace_hash);

            let script_hash = sha256::hash(entry.script_pubkey.as_bytes());
            bytes.extend_from_slice(&script_hash);
        }

        bytes
    }
}
