//! Client-only, memory-backed MLS operations. Errors intentionally contain no input.

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::{Deserialize as _, Serialize as _};

pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
pub const MAX_MEMBERS: usize = 16;
pub const MAX_INPUT: usize = 32768;
pub const MAX_PLAINTEXT: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid,
    State,
    Crypto,
    Membership,
}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, PartialEq, Eq)]
pub struct Identity {
    pub credential: Vec<u8>,
    pub public_key: Vec<u8>,
}

pub struct Change {
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
    pub epoch: u64,
}

pub struct Application {
    pub sender: Identity,
    pub plaintext: Vec<u8>,
}

// A new provider is used for each room session. Dropping the session drops all
// room secret references, including one-use key packages. No serialization API.
pub struct Session {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    identity: Identity,
    host_key: Vec<u8>,
    group: Option<MlsGroup>,
    package_generated: bool,
}

fn credential(id: &Identity) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(id.credential.clone()).into(),
        signature_key: id.public_key.clone().into(),
    }
}

fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .max_past_epochs(0)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(0, 64))
        .build()
}

fn create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .max_past_epochs(0)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(0, 64))
        .build()
}

fn decode_message(bytes: &[u8]) -> Result<MlsMessageIn> {
    if bytes.is_empty() || bytes.len() > MAX_INPUT {
        return Err(Error::Invalid);
    }
    MlsMessageIn::tls_deserialize_exact(bytes).map_err(|_| Error::Invalid)
}

fn member_identity(member: &Member) -> Identity {
    Identity {
        credential: member.credential.serialized_content().to_vec(),
        public_key: member.signature_key.clone(),
    }
}

impl Session {
    pub fn new(id: Identity, seed: &[u8]) -> Result<Self> {
        if seed.len() != 32
            || id.public_key.len() != 32
            || id.credential.is_empty()
            || id.credential.len() > 256
        {
            return Err(Error::Invalid);
        }
        // The Go caller validates that seed and public key match on identity load.
        let signer = SignatureKeyPair::from_raw(
            CIPHERSUITE.signature_algorithm(),
            seed.to_vec(),
            id.public_key.clone(),
        );
        Ok(Self {
            provider: OpenMlsRustCrypto::default(),
            signer,
            identity: id,
            host_key: Vec::new(),
            group: None,
            package_generated: false,
        })
    }

    pub fn key_package(&mut self) -> Result<Vec<u8>> {
        if self.group.is_some() || self.package_generated {
            return Err(Error::State);
        }
        let bundle = KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &self.provider,
                &self.signer,
                credential(&self.identity),
            )
            .map_err(|_| Error::Crypto)?;
        let bytes = bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(|_| Error::Crypto)?;
        self.package_generated = true;
        Ok(bytes)
    }

    pub fn create(&mut self, group_id: &[u8]) -> Result<()> {
        if self.group.is_some() || group_id.len() != 16 {
            return Err(Error::State);
        }
        let group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &create_config(),
            GroupId::from_slice(group_id),
            credential(&self.identity),
        )
        .map_err(|_| Error::Crypto)?;
        self.host_key = self.identity.public_key.clone();
        self.group = Some(group);
        Ok(())
    }

    pub fn join(
        &mut self,
        welcome: &[u8],
        group_id: &[u8],
        host_key: &[u8],
        expected: &[Identity],
    ) -> Result<()> {
        if self.group.is_some()
            || !self.package_generated
            || group_id.len() != 16
            || host_key.len() != 32
        {
            return Err(Error::State);
        }
        let welcome = match decode_message(welcome)?.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(Error::Invalid),
        };
        let group = StagedWelcome::new_from_welcome(&self.provider, &join_config(), welcome, None)
            .map_err(|_| Error::Crypto)?
            .into_group(&self.provider)
            .map_err(|_| Error::Crypto)?;
        if group.group_id().as_slice() != group_id {
            return Err(Error::Membership);
        }
        validate_roster(&group, expected)?;
        if !expected.iter().any(|i| i.public_key == host_key) {
            return Err(Error::Membership);
        }
        self.host_key = host_key.to_vec();
        self.group = Some(group);
        Ok(())
    }

    pub fn epoch(&self) -> Result<u64> {
        Ok(self.group.as_ref().ok_or(Error::State)?.epoch().as_u64())
    }

    pub fn members(&self) -> Result<Vec<Identity>> {
        Ok(self
            .group
            .as_ref()
            .ok_or(Error::State)?
            .members()
            .map(|m| member_identity(&m))
            .collect())
    }

    pub fn validate_members(&self, expected: &[Identity]) -> Result<()> {
        validate_roster(self.group.as_ref().ok_or(Error::State)?, expected)
    }

    fn require_host(&self) -> Result<()> {
        if self.host_key != self.identity.public_key {
            return Err(Error::Membership);
        }
        Ok(())
    }

    pub fn add(&mut self, package: &[u8], expected: &Identity) -> Result<Change> {
        self.require_host()?;
        if package.is_empty() || package.len() > MAX_INPUT {
            return Err(Error::Invalid);
        }
        let kp = KeyPackageIn::tls_deserialize_exact(package)
            .map_err(|_| Error::Invalid)?
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|_| Error::Crypto)?;
        if kp.ciphersuite() != CIPHERSUITE
            || kp.leaf_node().credential().serialized_content() != expected.credential
            || kp.leaf_node().signature_key().as_slice() != expected.public_key
        {
            return Err(Error::Membership);
        }
        let group = self.group.as_mut().ok_or(Error::State)?;
        if group.members().count() >= MAX_MEMBERS
            || group
                .members()
                .any(|m| m.signature_key == expected.public_key)
        {
            return Err(Error::Membership);
        }
        let (commit, welcome, _) = group
            .add_members(&self.provider, &self.signer, &[kp])
            .map_err(|_| Error::Crypto)?;
        group
            .merge_pending_commit(&self.provider)
            .map_err(|_| Error::Crypto)?;
        Ok(Change {
            commit: commit.tls_serialize_detached().map_err(|_| Error::Crypto)?,
            welcome: welcome
                .tls_serialize_detached()
                .map_err(|_| Error::Crypto)?,
            epoch: group.epoch().as_u64(),
        })
    }

    pub fn remove(&mut self, key: &[u8]) -> Result<Change> {
        self.require_host()?;
        if key == self.host_key {
            return Err(Error::Membership);
        }
        let group = self.group.as_mut().ok_or(Error::State)?;
        let index = group
            .members()
            .find(|m| m.signature_key == key)
            .ok_or(Error::Membership)?
            .index;
        let (commit, _, _) = group
            .remove_members(&self.provider, &self.signer, &[index])
            .map_err(|_| Error::Crypto)?;
        group
            .merge_pending_commit(&self.provider)
            .map_err(|_| Error::Crypto)?;
        Ok(Change {
            commit: commit.tls_serialize_detached().map_err(|_| Error::Crypto)?,
            welcome: Vec::new(),
            epoch: group.epoch().as_u64(),
        })
    }

    pub fn update(&mut self) -> Result<Change> {
        self.require_host()?;
        let group = self.group.as_mut().ok_or(Error::State)?;
        let bundle = group
            .self_update(&self.provider, &self.signer, LeafNodeParameters::default())
            .map_err(|_| Error::Crypto)?;
        let (commit, _, _) = bundle.into_contents();
        group
            .merge_pending_commit(&self.provider)
            .map_err(|_| Error::Crypto)?;
        Ok(Change {
            commit: commit.tls_serialize_detached().map_err(|_| Error::Crypto)?,
            welcome: Vec::new(),
            epoch: group.epoch().as_u64(),
        })
    }

    pub fn process_commit(&mut self, bytes: &[u8], expected: &[Identity]) -> Result<()> {
        let message = decode_message(bytes)?
            .try_into_protocol_message()
            .map_err(|_| Error::Invalid)?;
        let group = self.group.as_mut().ok_or(Error::State)?;
        let processed = group
            .process_message(&self.provider, message)
            .map_err(|_| Error::Crypto)?;
        let sender = match processed.sender() {
            Sender::Member(i) => group.members().find(|m| m.index == *i),
            _ => None,
        };
        if sender.is_none_or(|m| m.signature_key != self.host_key) {
            return Err(Error::Membership);
        }
        let commit = match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(c) => c,
            _ => return Err(Error::Invalid),
        };
        group
            .merge_staged_commit(&self.provider, *commit)
            .map_err(|_| Error::Crypto)?;
        validate_roster(group, expected)
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.is_empty()
            || plaintext.len() > MAX_PLAINTEXT
            || std::str::from_utf8(plaintext).is_err()
        {
            return Err(Error::Invalid);
        }
        self.group
            .as_mut()
            .ok_or(Error::State)?
            .create_message(&self.provider, &self.signer, plaintext)
            .map_err(|_| Error::Crypto)?
            .tls_serialize_detached()
            .map_err(|_| Error::Crypto)
    }

    pub fn decrypt(&mut self, bytes: &[u8]) -> Result<Application> {
        if bytes.len() > 16384 {
            return Err(Error::Invalid);
        }
        let message = decode_message(bytes)?
            .try_into_protocol_message()
            .map_err(|_| Error::Invalid)?;
        if message.wire_format() != WireFormat::PrivateMessage {
            return Err(Error::Invalid);
        }
        let group = self.group.as_mut().ok_or(Error::State)?;
        let processed = group
            .process_message(&self.provider, message)
            .map_err(|_| Error::Crypto)?;
        let sender = match processed.sender() {
            Sender::Member(i) => group.members().find(|m| m.index == *i),
            _ => None,
        };
        let sender = member_identity(&sender.ok_or(Error::Membership)?);
        let plaintext = match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(a) => a.into_bytes(),
            _ => return Err(Error::Invalid),
        };
        if plaintext.is_empty()
            || plaintext.len() > MAX_PLAINTEXT
            || std::str::from_utf8(&plaintext).is_err()
        {
            return Err(Error::Invalid);
        }
        Ok(Application { sender, plaintext })
    }
}

fn validate_roster(group: &MlsGroup, expected: &[Identity]) -> Result<()> {
    let actual: Vec<_> = group.members().map(|m| member_identity(&m)).collect();
    if expected.is_empty() || expected.len() > MAX_MEMBERS || actual.len() != expected.len() {
        return Err(Error::Membership);
    }
    for (index, id) in expected.iter().enumerate() {
        if id.public_key.len() != 32
            || expected[..index]
                .iter()
                .any(|i| i.public_key == id.public_key || i.credential == id.credential)
            || !actual.contains(id)
        {
            return Err(Error::Membership);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;

mod ffi;
