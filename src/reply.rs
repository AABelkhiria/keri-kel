//! Replies (`rpy`): signed statements that replace an earlier one from the same signer about the
//! same thing.
//!
//! A [`Kevery`] keeps four kinds: key state notices ([`crate::notice`]), end role grants and
//! endpoint locations ([`crate::endpoint`]), and watcher registrations ([`crate::observation`]).
//! They share how a reply is verified, which this module holds:
//!
//! - the reply's authority is named by its route or attributes, and a signature attached to it must
//!   be the authority's own, newer than the reply kept before for the same thing, and valid: a
//!   non-transferable authority's against its key, a transferable authority's against the keys of
//!   the establishment event of its own that the signature group names;
//! - a reply signed by a transferable authority whose establishment event is not accepted yet, or
//!   whose signatures do not yet meet its threshold, waits in the reply escrow, and signatures
//!   offered for it later are added to it.
//!
//! This ports keripy's `Revery.processReply`, `acceptReply` and `processEscrowReply`
//! (`src/keri/core/routing.py`), using keri-protocol's port of `acceptReply` for the signature
//! decision.

use std::cell::RefCell;

use keri_cesr::crypto::signature::IndexedSignature;
use keri_cesr::sequence::SequenceNumber;
use keri_protocol::attachment::{ReceiptCouple, SignatureSeal, SignedMessageBuilder};
use keri_protocol::event::EventError;
use keri_protocol::event::reply::ReplyMessage;
use keri_protocol::event::reply::acceptance::{AcceptedReply, SignerEvents, accept};
use keri_protocol::event::reply::route::ReplyRoute;
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;
use keri_protocol::serialization::SerializedEvent;
use keri_protocol::stream::{Message, TransferableSignatureGroup};

use crate::error::KelError;
use crate::kevery::{Kevery, Processed};
use crate::store::{KelStore, Store, StoreError};

/// A reply kept, and what decides whether a later reply about the same thing replaces it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeptReply {
    pub(crate) reply: SerializedEvent,
    pub(crate) timestamp: Timestamp,
    pub(crate) signed_at: Option<u128>,
}

impl KeptReply {
    /// Returns the reply.
    #[must_use]
    pub const fn reply(&self) -> &SerializedEvent {
        &self.reply
    }

    /// Returns when the reply was made.
    #[must_use]
    pub const fn timestamp(&self) -> &Timestamp {
        &self.timestamp
    }

    /// Returns, for a transferable authority, the sequence number of the establishment event
    /// whose keys signed the reply.
    #[must_use]
    pub const fn signed_at(&self) -> Option<u128> {
        self.signed_at
    }

    /// What a reply offered now must be newer than, keripy's `osaider` and its date and signer.
    fn prior(&self, offered: &str, reoffer: Reoffer) -> Option<AcceptedReply> {
        if reoffer == Reoffer::Fresh && self.reply.said() == Some(offered) {
            return None;
        }
        let accepted = AcceptedReply::new(self.timestamp.clone());
        Some(match self.signed_at {
            Some(sequence_number) => accepted.signed_at(sequence_number),
            None => accepted,
        })
    }
}

/// How the reply kept is treated when the same reply is offered again, which keripy decides per
/// route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Reoffer {
    /// It is accepted again, as keripy's end role handler does.
    Fresh,
    /// It is not newer than itself, and is refused.
    Stale,
}

/// A reply as offered: the reply, its non-transferable couples, and its transferable signature
/// groups.
pub(crate) struct OfferedReply<'a> {
    pub(crate) reply: &'a ReplyMessage,
    pub(crate) couples: &'a [ReceiptCouple],
    pub(crate) groups: Vec<ReplySignatures>,
}

/// What became of a reply whose signatures were checked.
pub(crate) enum Verdict {
    /// A signature established it; keep it.
    Accepted(KeptReply),
    /// It waits in the reply escrow.
    Escrowed,
}

/// A transferable signer's signatures of a reply, with the establishment event of its own whose
/// keys made them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplySignatures {
    pub(crate) signer: IdentifierPrefix,
    pub(crate) sequence_number: u128,
    pub(crate) said: Said,
    pub(crate) signatures: Vec<IndexedSignature>,
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
    pub(crate) reply: SerializedEvent,
    pub(crate) groups: Vec<ReplySignatures>,
    pub(crate) since: Timestamp,
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
    /// By a non-transferable authority's key.
    ByKey,
    /// By a transferable authority's group, from its establishment event at this sequence number.
    ByGroup(u128),
}

impl<S: Store> Kevery<S> {
    /// keripy's `Revery.processReply`: dispatches a reply by its route.
    pub(crate) fn process_reply(&mut self, message: &Message, now: &Timestamp) -> Result<Processed, KelError> {
        let reply = ReplyMessage::from_serialized(message.event().clone()).map_err(KelError::reply)?;
        let attachments = message.attachments();
        let groups = attachments
            .transferable_signature_groups()
            .iter()
            .map(ReplySignatures::from_group)
            .collect();
        let offered = OfferedReply {
            reply: &reply,
            couples: attachments.receipt_couples(),
            groups,
        };
        self.consider_reply(offered, now)
    }

    fn consider_reply(&mut self, offered: OfferedReply<'_>, now: &Timestamp) -> Result<Processed, KelError> {
        match ReplyRoute::from_reply(offered.reply) {
            Ok(ReplyRoute::KeyStateNotice { source, state }) => self.consider_notice(offered, &source, *state, now),
            Ok(ReplyRoute::EndRole { action, end_role }) => self.consider_end_role(offered, action, &end_role, now),
            Ok(ReplyRoute::LocationScheme(location)) => self.consider_location(offered, &location, now),
            Ok(ReplyRoute::WatcherObservation {
                watcher,
                action,
                observation,
            }) => self.consider_observation(offered, &watcher, action, &observation, now),
            Err(EventError::UnknownReplyRoute { .. }) => Err(KelError::UnsupportedReplyRoute),
            Err(error) => Err(KelError::reply(error)),
        }
    }

    /// keripy's `acceptReply` and its escrow: decides whether a signature attached to the offered
    /// reply, or left by an earlier offer of it, establishes it on behalf of `authority` over the
    /// reply `kept` before.
    pub(crate) fn verify_reply(
        &mut self,
        offered: OfferedReply<'_>,
        authority: &IdentifierPrefix,
        kept: Option<&KeptReply>,
        reoffer: Reoffer,
        now: &Timestamp,
    ) -> Result<Verdict, KelError> {
        let reply = offered.reply;
        let said = reply.said().qb64().map_err(KelError::said)?;
        let escrowed = self.store.escrowed_reply(&said).map_err(KelError::store)?;
        let groups = merged(offered.groups, escrowed.as_ref().map(EscrowedReply::groups));
        let prior = kept.and_then(|kept| kept.prior(&said, reoffer));
        let (established, waiting) = self.decide(reply, authority, prior.as_ref(), offered.couples, &groups)?;
        let signed_at = match established {
            Established::No => None,
            Established::ByKey => Some(None),
            Established::ByGroup(sequence_number) => Some(Some(sequence_number)),
        };
        if let Some(signed_at) = signed_at {
            self.store.remove_escrowed_reply(&said).map_err(KelError::store)?;
            return Ok(Verdict::Accepted(KeptReply {
                reply: reply.serialized().clone(),
                timestamp: reply.timestamp().clone(),
                signed_at,
            }));
        }
        if waiting.is_empty() {
            return Err(KelError::UnverifiedReply);
        }
        let waiting = EscrowedReply {
            reply: reply.serialized().clone(),
            groups: waiting,
            since: escrowed.map_or_else(|| now.clone(), |escrowed| escrowed.since),
        };
        self.store.put_escrowed_reply(&said, waiting).map_err(KelError::store)?;
        Ok(Verdict::Escrowed)
    }

    /// keri-protocol's `accept`, over the couples and then each signature group in turn, as
    /// keripy's `acceptReply` checks them; a group it cannot check refuses the whole reply.
    fn decide(
        &self,
        reply: &ReplyMessage,
        authority: &IdentifierPrefix,
        prior: Option<&AcceptedReply>,
        couples: &[ReceiptCouple],
        groups: &[ReplySignatures],
    ) -> Result<(Established, Vec<ReplySignatures>), KelError> {
        let signers = Signers {
            store: &self.store,
            failure: RefCell::new(None),
        };
        let mut established = Established::No;
        let mut waiting = Vec::new();
        if !couples.is_empty() {
            let message = signed(reply, couples, None)?;
            let acceptance = accept(reply, message.attachments(), authority, prior, &signers);
            signers.checked()?;
            if acceptance.map_err(KelError::reply)?.is_accepted() {
                established = Established::ByKey;
            }
        }
        for group in groups.iter().filter(|group| !group.signatures.is_empty()) {
            let message = signed(reply, &[], Some(group))?;
            let acceptance = accept(reply, message.attachments(), authority, prior, &signers);
            signers.checked()?;
            let acceptance = acceptance.map_err(KelError::reply)?;
            if acceptance.is_accepted() {
                established = Established::ByGroup(group.sequence_number);
            } else if acceptance.is_escrowed() {
                waiting.push(group.clone());
            }
        }
        Ok((established, waiting))
    }

    /// keripy's `processEscrowReply`: offers each waiting reply again with the signatures gathered
    /// for it. A reply still short of what it needs, or still not established, keeps waiting; one
    /// refused for any other reason is dropped.
    pub(crate) fn retry_replies(&mut self, now: &Timestamp) -> Result<(), KelError> {
        let waiting = self.store.escrowed_replies().map_err(KelError::store)?;
        for (said, escrowed) in waiting {
            let outcome = ReplyMessage::from_serialized(escrowed.reply.clone())
                .map_err(KelError::reply)
                .and_then(|reply| {
                    let offered = OfferedReply {
                        reply: &reply,
                        couples: &[],
                        groups: escrowed.groups.clone(),
                    };
                    self.consider_reply(offered, now)
                });
            match outcome {
                Ok(_) | Err(KelError::UnverifiedReply) => {}
                Err(error @ KelError::Store { .. }) => return Err(error),
                Err(_) => self.store.remove_escrowed_reply(&said).map_err(KelError::store)?,
            }
        }
        Ok(())
    }

    /// Returns how many replies are waiting.
    ///
    /// # Errors
    ///
    /// Returns [`KelError::Store`] when the store fails.
    pub fn escrowed_reply_count(&self) -> Result<usize, KelError> {
        Ok(self.store.escrowed_replies().map_err(KelError::store)?.len())
    }
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
