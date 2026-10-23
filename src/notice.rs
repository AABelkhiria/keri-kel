//! Key state notices: replies on route `/ksn/{source}` in which an actor reports an identifier's
//! key state.
//!
//! A [`Kevery`] keeps the latest notice from each source about each identifier, once:
//!
//! - its source is trusted ([`NoticeTrust`]);
//! - the reported state is not older than the local log's;
//! - a signature attached to it is the source's own, newer than the notice kept before from that
//!   source, and valid: a non-transferable source's against its key, a transferable source's
//!   against the keys of the establishment event of its own that the signature group names;
//! - at a sequence number the local log holds, the reported event is the local one.
//!
//! A notice signed by a transferable source whose establishment event is not accepted yet, or
//! whose signatures do not yet meet its threshold, waits in the reply escrow, and signatures
//! offered for it later are added to it.
//!
//! This ports keripy's `Kevery.processReplyKeyStateNotice` and `Revery.processReply`,
//! `acceptReply` and `processEscrowReply` (`src/keri/core/eventing.py`, `src/keri/core/routing.py`),
//! using keri-protocol's port of `acceptReply` for the signature decision. Replies on other routes,
//! endpoint roles, locations and watcher registrations, are the application's.
//!
//! One behaviour differs. keripy looks up the notice it kept before from a source by the reported
//! event's SAID, while it stores replies under their own SAIDs, so it never finds one: it compares
//! no dates, and keeps a notice made earlier than the one it replaces. Here the notice kept before
//! is found, and a reply not newer than it is refused, as keripy's best-available-data rule
//! intends.

use std::cell::RefCell;

use keri_cesr::crypto::signature::IndexedSignature;
use keri_cesr::sequence::SequenceNumber;
use keri_protocol::attachment::{ReceiptCouple, SignatureSeal, SignedMessageBuilder};
use keri_protocol::event::EventError;
use keri_protocol::event::key_state::KeyStateRecord;
use keri_protocol::event::reply::ReplyMessage;
use keri_protocol::event::reply::acceptance::{AcceptedReply, SignerEvents, accept};
use keri_protocol::event::reply::route::ReplyRoute;
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;
use keri_protocol::serialization::SerializedEvent;
use keri_protocol::stream::{Message, TransferableSignatureGroup};

use crate::error::{Escrow, KelError};
use crate::kevery::{Kevery, Processed};
use crate::store::{KelStore, Store, StoreError};

/// Whose key state notices a [`Kevery`] keeps.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum NoticeTrust {
    /// Any source's, keripy's `lax` mode and its `Kevery` default, as its witnesses run.
    #[default]
    AnySource,
    /// Only those of the identifier itself, one of its witnesses, or one of these watchers, keripy's
    /// strict mode, as its controllers run.
    Watchers(Vec<IdentifierPrefix>),
}

impl NoticeTrust {
    fn trusts(&self, source: &IdentifierPrefix, state: &KeyStateRecord) -> bool {
        match self {
            Self::AnySource => true,
            Self::Watchers(watchers) => {
                source == state.identifier() || state.witnesses().contains(source) || watchers.contains(source)
            }
        }
    }
}

/// A key state notice kept: the reported state, the reply that reported it, and what decides
/// whether a later reply from the same source replaces it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyStateNotice {
    state: KeyStateRecord,
    reply: SerializedEvent,
    timestamp: Timestamp,
    signed_at: Option<u128>,
}

impl KeyStateNotice {
    /// Returns the reported state.
    #[must_use]
    pub const fn state(&self) -> &KeyStateRecord {
        &self.state
    }

    /// Returns the reply that reported it.
    #[must_use]
    pub const fn reply(&self) -> &SerializedEvent {
        &self.reply
    }

    /// Returns when the reply was made.
    #[must_use]
    pub const fn timestamp(&self) -> &Timestamp {
        &self.timestamp
    }

    /// Returns, for a transferable source, the sequence number of the establishment event whose
    /// keys signed the reply.
    #[must_use]
    pub const fn signed_at(&self) -> Option<u128> {
        self.signed_at
    }
}

/// A transferable signer's signatures of a reply, with the establishment event of its own whose
/// keys made them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplySignatures {
    signer: IdentifierPrefix,
    sequence_number: u128,
    said: Said,
    signatures: Vec<IndexedSignature>,
}

impl ReplySignatures {
    fn from_group(group: &TransferableSignatureGroup) -> Self {
        Self {
            signer: group.identifier().clone(),
            sequence_number: group.sequence_number().value(),
            said: group.said(),
            signatures: group.signatures().to_vec(),
        }
    }

    fn same_source(&self, other: &Self) -> bool {
        self.signer == other.signer && self.sequence_number == other.sequence_number && self.said == other.said
    }

    /// Returns the signer.
    #[must_use]
    pub const fn signer(&self) -> &IdentifierPrefix {
        &self.signer
    }

    /// Returns the sequence number of the signer's establishment event whose keys signed.
    #[must_use]
    pub const fn sequence_number(&self) -> u128 {
        self.sequence_number
    }

    /// Returns the SAID of that establishment event.
    #[must_use]
    pub const fn said(&self) -> Said {
        self.said
    }

    /// Returns the indexed signatures.
    #[must_use]
    pub fn signatures(&self) -> &[IndexedSignature] {
        &self.signatures
    }
}

/// A reply waiting for its signer's establishment event or more signatures, with every signature
/// offered for it so far.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowedReply {
    reply: SerializedEvent,
    groups: Vec<ReplySignatures>,
    since: Timestamp,
}

impl EscrowedReply {
    /// Returns the reply.
    #[must_use]
    pub const fn reply(&self) -> &SerializedEvent {
        &self.reply
    }

    /// Returns the signature groups offered for it.
    #[must_use]
    pub fn groups(&self) -> &[ReplySignatures] {
        &self.groups
    }

    /// Returns when it was first escrowed.
    #[must_use]
    pub const fn since(&self) -> &Timestamp {
        &self.since
    }
}

/// The signers' logs, as keri-protocol's acceptance asks for them, remembering a store failure it
/// cannot report itself.
struct Signers<'a, S> {
    store: &'a S,
    failure: RefCell<Option<StoreError>>,
}

impl<S: KelStore> SignerEvents for Signers<'_, S> {
    fn event_at(&self, signer: &IdentifierPrefix, sequence_number: u128) -> Option<SerializedEvent> {
        let identifier = signer.qb64().ok()?;
        match self.store.event(&identifier, sequence_number) {
            Ok(logged) => logged.map(|logged| logged.event().clone()),
            Err(error) => {
                self.failure.replace(Some(error));
                None
            }
        }
    }
}

impl<S> Signers<'_, S> {
    fn checked(&self) -> Result<(), KelError> {
        self.failure.take().map_or(Ok(()), |error| Err(KelError::store(error)))
    }
}

/// Whether a signature established a reply, and how.
#[derive(Clone, Copy)]
enum Established {
    No,
    /// By a non-transferable source's key.
    ByKey,
    /// By a transferable source's group, from its establishment event at this sequence number.
    ByGroup(u128),
}

/// What the signatures attached to one reply decided.
struct Decision {
    established: Established,
    /// The groups the reply waits on.
    waiting: Vec<ReplySignatures>,
}

impl<S: Store> Kevery<S> {
    /// keripy's `Revery.processReply` for a key state notice.
    pub(crate) fn process_reply(&mut self, message: &Message, now: &Timestamp) -> Result<Processed, KelError> {
        let reply = ReplyMessage::from_serialized(message.event().clone()).map_err(KelError::reply)?;
        let attachments = message.attachments();
        let groups = attachments
            .transferable_signature_groups()
            .iter()
            .map(ReplySignatures::from_group)
            .collect();
        self.consider_notice(&reply, attachments.receipt_couples(), groups, now)
    }

    /// keripy's `processReplyKeyStateNotice`, with its `acceptReply`.
    fn consider_notice(
        &mut self,
        reply: &ReplyMessage,
        couples: &[ReceiptCouple],
        groups: Vec<ReplySignatures>,
        now: &Timestamp,
    ) -> Result<Processed, KelError> {
        let (source, state) = match ReplyRoute::from_reply(reply) {
            Ok(ReplyRoute::KeyStateNotice { source, state }) => (source, state),
            Ok(_) | Err(EventError::UnknownReplyRoute { .. }) => return Err(KelError::UnsupportedReplyRoute),
            Err(error) => return Err(KelError::reply(error)),
        };
        if !self.trust.trusts(&source, &state) {
            return Err(KelError::UntrustedKeyStateSource);
        }
        let identifier = qb64(state.identifier())?;
        let source_text = qb64(&source)?;
        let local = self.store.kever(&identifier).map_err(KelError::store)?;
        if local.is_some_and(|kever| state.sequence_number() < kever.sequence_number()) {
            return Err(KelError::StaleKeyState);
        }
        let prior = self
            .store
            .key_state_notice(&identifier, &source_text)
            .map_err(KelError::store)?
            .map(|notice| {
                let accepted = AcceptedReply::new(notice.timestamp.clone());
                match notice.signed_at {
                    Some(sequence_number) => accepted.signed_at(sequence_number),
                    None => accepted,
                }
            });
        let said = reply.said().qb64().map_err(KelError::said)?;
        let escrowed = self.store.escrowed_reply(&said).map_err(KelError::store)?;
        let groups = merged(groups, escrowed.as_ref().map(EscrowedReply::groups));
        let decision = self.decide(reply, &source, prior.as_ref(), couples, &groups)?;

        let signed_at = match decision.established {
            Established::No => None,
            Established::ByKey => Some(None),
            Established::ByGroup(sequence_number) => Some(Some(sequence_number)),
        };
        if let Some(signed_at) = signed_at {
            let local = self
                .store
                .event(&identifier, state.sequence_number())
                .map_err(KelError::store)?;
            let reported = state.said().qb64().map_err(KelError::said)?;
            if local.is_some_and(|logged| logged.event().said() != Some(reported.as_str())) {
                return Err(KelError::KeyStateMismatch);
            }
            let notice = KeyStateNotice {
                state: *state,
                reply: reply.serialized().clone(),
                timestamp: reply.timestamp().clone(),
                signed_at,
            };
            self.store
                .put_key_state_notice(&identifier, &source_text, notice)
                .map_err(KelError::store)?;
            self.store.remove_escrowed_reply(&said).map_err(KelError::store)?;
            return Ok(Processed::KeyStateAccepted);
        }
        if decision.waiting.is_empty() {
            return Err(KelError::UnverifiedReply);
        }
        let waiting = EscrowedReply {
            reply: reply.serialized().clone(),
            groups: decision.waiting,
            since: escrowed.map_or_else(|| now.clone(), |escrowed| escrowed.since),
        };
        self.store.put_escrowed_reply(&said, waiting).map_err(KelError::store)?;
        Ok(Processed::Escrowed(Escrow::UnverifiedReply))
    }

    /// keri-protocol's `accept`, over the couples and then each signature group in turn, as
    /// keripy's `acceptReply` checks them; a group it cannot check refuses the whole reply.
    fn decide(
        &self,
        reply: &ReplyMessage,
        source: &IdentifierPrefix,
        prior: Option<&AcceptedReply>,
        couples: &[ReceiptCouple],
        groups: &[ReplySignatures],
    ) -> Result<Decision, KelError> {
        let signers = Signers {
            store: &self.store,
            failure: RefCell::new(None),
        };
        let mut decision = Decision {
            established: Established::No,
            waiting: Vec::new(),
        };
        if !couples.is_empty() {
            let message = signed(reply, couples, None)?;
            let acceptance = accept(reply, message.attachments(), source, prior, &signers);
            signers.checked()?;
            if acceptance.map_err(KelError::reply)?.is_accepted() {
                decision.established = Established::ByKey;
            }
        }
        for group in groups.iter().filter(|group| !group.signatures.is_empty()) {
            let message = signed(reply, &[], Some(group))?;
            let acceptance = accept(reply, message.attachments(), source, prior, &signers);
            signers.checked()?;
            let acceptance = acceptance.map_err(KelError::reply)?;
            if acceptance.is_accepted() {
                decision.established = Established::ByGroup(group.sequence_number);
            } else if acceptance.is_escrowed() {
                decision.waiting.push(group.clone());
            }
        }
        Ok(decision)
    }

    /// keripy's `processEscrowReply`: offers each waiting reply again with the signatures gathered
    /// for it. A reply still short of what it needs, or still not established, keeps waiting; one
    /// refused for any other reason is dropped.
    pub(crate) fn retry_replies(&mut self, now: &Timestamp) -> Result<(), KelError> {
        let waiting = self.store.escrowed_replies().map_err(KelError::store)?;
        for (said, escrowed) in waiting {
            let outcome = ReplyMessage::from_serialized(escrowed.reply.clone())
                .map_err(KelError::reply)
                .and_then(|reply| self.consider_notice(&reply, &[], escrowed.groups.clone(), now));
            match outcome {
                Ok(_) | Err(KelError::UnverifiedReply) => {}
                Err(error @ KelError::Store { .. }) => return Err(error),
                Err(_) => self.store.remove_escrowed_reply(&said).map_err(KelError::store)?,
            }
        }
        Ok(())
    }

    /// Returns the key state notice kept from `source` about `identifier`.
    ///
    /// # Errors
    ///
    /// Returns [`KelError::Prefix`] for an identifier that cannot be written as qb64, and
    /// [`KelError::Store`] when the store fails.
    pub fn key_state_notice(
        &self,
        identifier: &IdentifierPrefix,
        source: &IdentifierPrefix,
    ) -> Result<Option<KeyStateNotice>, KelError> {
        self.store
            .key_state_notice(&qb64(identifier)?, &qb64(source)?)
            .map_err(KelError::store)
    }

    /// Returns every key state notice kept about `identifier`, with its source as qb64 text.
    ///
    /// # Errors
    ///
    /// Returns [`KelError::Prefix`] for an identifier that cannot be written as qb64, and
    /// [`KelError::Store`] when the store fails.
    pub fn key_state_notices(&self, identifier: &IdentifierPrefix) -> Result<Vec<(String, KeyStateNotice)>, KelError> {
        self.store
            .key_state_notices(&qb64(identifier)?)
            .map_err(KelError::store)
    }

    /// Returns how many replies are waiting.
    ///
    /// # Errors
    ///
    /// Returns [`KelError::Store`] when the store fails.
    pub fn escrowed_replies(&self) -> Result<usize, KelError> {
        Ok(self.store.escrowed_replies().map_err(KelError::store)?.len())
    }
}

fn qb64(identifier: &IdentifierPrefix) -> Result<String, KelError> {
    identifier.qb64().map_err(KelError::prefix)
}

/// The groups offered now, each with the signatures an earlier offer of the same reply left for
/// the same signer and establishment event, keripy's merge of its stored `ssgs`.
fn merged(groups: Vec<ReplySignatures>, earlier: Option<&[ReplySignatures]>) -> Vec<ReplySignatures> {
    let mut groups = groups;
    for earlier in earlier.unwrap_or_default() {
        match groups.iter_mut().find(|group| group.same_source(earlier)) {
            Some(group) => {
                for signature in &earlier.signatures {
                    if !group.signatures.contains(signature) {
                        group.signatures.push(signature.clone());
                    }
                }
            }
            None => groups.push(earlier.clone()),
        }
    }
    groups
}

/// The reply with only these signatures attached, as keri-protocol's acceptance reads them.
fn signed(
    reply: &ReplyMessage,
    couples: &[ReceiptCouple],
    group: Option<&ReplySignatures>,
) -> Result<Message, KelError> {
    let mut builder = SignedMessageBuilder::new(reply.serialized()).receipt_couples(couples.to_vec());
    if let Some(group) = group {
        builder = builder
            .controller_signatures(group.signatures.clone())
            .seal(SignatureSeal::Event {
                identifier: group.signer.clone(),
                sequence_number: SequenceNumber::new(group.sequence_number),
                said: group.said,
            });
    }
    let signed = builder.build().map_err(KelError::reply)?;
    Message::from_bytes(signed.as_bytes()).map_err(KelError::reply)
}
