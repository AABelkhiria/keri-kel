//! Many identifiers' logs, the receipts that arrive for them, and the events still waiting.
//!
//! A [`Kevery`] takes messages as they arrive, from any source, and routes each one:
//!
//! - an inception for an identifier it has not seen starts that identifier's log;
//! - the next event for a known identifier is validated against its key state;
//! - an event already accepted is a duplicate, and any further signatures it carries that verify
//!   are added to the stored event;
//! - a receipt (`rct`) adds witness signatures, receipt couples, or a validator's signatures to
//!   the event it names.
//!
//! A validator is a transferable identifier that receipts others' events: its receipt names one of
//! its own establishment events, and each signature is verified against that event's keys, so the
//! validator's log must be held too. Such signatures arrive in a receipt as an indexed signature
//! group, or attached to the event itself as receipt quadruples; either way they are stored with the
//! event as [`ValidatorReceipt`]s. Quadruples attached to an event never change what becomes of the
//! event: they are stored, kept until the validator's event is accepted, or dropped.
//!
//! A delegated inception, or a rotation of a delegated identifier, is accepted only once its
//! delegator's log holds an event anchoring a seal of it. The event may name that event in a seal
//! source couple; the couple is checked against the delegator's log, and the delegating event found
//! is stored with the delegated one.
//!
//! An event that cannot be decided yet is kept in an escrow with everything offered for it so far:
//!
//! - out of order, when it comes before the events it follows, including any event but an
//!   inception for an identifier not seen yet; it is kept unverified, since nothing can be
//!   verified before the key state it needs;
//! - partially signed, partially witnessed or partially delegated, when it is short of controller
//!   signatures, witness signatures or its delegator's approval;
//! - likely duplicitous, when it contradicts an event already accepted at its sequence number. It
//!   is never accepted; it is kept as evidence until it expires.
//!
//! A receipt for an event not yet accepted is kept too. [`Kevery::process_escrows`] retries all of
//! them in keripy's order: out-of-order events, then waiting receipts, then partially delegated,
//! partially witnessed and partially signed events, then likely-duplicitous ones; within each
//! escrow, by identifier, sequence number and arrival. An event retried may move to another escrow:
//! an out-of-order event whose predecessors arrived may still be short of signatures. On a retry, a
//! delegated event naming no delegating event is looked for in its delegator's whole log, as keripy
//! does only when retrying, and an out-of-order event is retried without the seal source couple it
//! arrived with, as keripy does.
//!
//! This ports keripy's `Kevery` (`src/keri/core/eventing.py`): `processEvent`, `processReceipt`,
//! `processAttachedReceiptCouples`, `Kever.validateDelegation`, and the out-of-order, partially
//! signed, partially witnessed, partially delegated, likely-duplicitous and unverified receipt
//! escrows with their processors.
//!
//! A recovery rotation supersedes interactions accepted since the latest establishment event: it
//! is accepted at the sequence number of the first one it supersedes, and the superseded events are
//! kept apart ([`Kevery::superseded`]), as keripy keeps them in its log. A delegated rotation may
//! also supersede the latest delegated rotation, signed with the keys that rotation committed to,
//! when its delegating event is later in the delegator's log than the superseded rotation's; and
//! the latest event, when that is an interaction at its sequence number. keripy refuses every other
//! delegated supersession, and so does this port ([`KelError::SupersedingDelegationNotLater`],
//! [`KelError::SupersededWithoutDelegation`]).
//!
//! One behaviour differs. When a witness's receipt couple is attached to an event, keripy's
//! `processAttachedReceiptCouples` compares the couple's key, a string, against a list of prefix
//! objects, which never matches, so the witness's signature is stored as a plain receipt and never
//! counts toward the witness threshold. It is stored as the witness signature it is here, as
//! keripy's `processReceipt` does for the same couple arriving in a receipt message.
//!
//! Escrowed items keep the time they were first escrowed. keripy drops out-of-order events after
//! twenty minutes and everything else after an hour; [`Kevery::expire_escrows`] drops everything
//! escrowed before a cutoff the caller chooses, since this crate reads no clock.

use keri_cesr::crypto::signature::IndexedSignature;
use keri_cesr::crypto::verifier::VerificationKey;
use keri_cesr::indexer::IndexerCode;
use keri_cesr::sequence::SequenceNumber;
use keri_protocol::attachment::{AttachmentFraming, ReceiptCouple, SealSourceCouple, SignedMessageBuilder};
use keri_protocol::event::kind::EventKind;
use keri_protocol::event::receipt::ReceiptMessage;
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;
use keri_protocol::serialization::SerializedEvent;
use keri_protocol::stream::{FirstSeenReplayCouple, Message, ReceiptQuadruple, TransferableSignatureGroup};

use crate::error::{Escrow, KelError};
use crate::event::{EventSeal, KeyEventFields};
use crate::kever::{Delegations, Kever, Offer, Verified, verified, witness_keys};
use crate::notice::NoticeTrust;
use crate::query::Answered;
use crate::store::{MemoryStore, Store};

/// What became of one processed message.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Processed {
    /// The event was accepted into its log.
    Accepted,
    /// The event was already accepted; any further verified signatures were added to it.
    Duplicate,
    /// The receipt's signatures were added to the event it names.
    Receipted,
    /// The key state notice was kept, replacing any earlier one from the same source.
    KeyStateAccepted,
    /// The end role grant or withdrawal was kept, replacing any earlier one for the same role.
    EndRoleAccepted,
    /// The location was kept, replacing any earlier one for the same scheme.
    LocationAccepted,
    /// The watcher registration was kept, replacing any earlier one for the same observation.
    ObservationAccepted,
    /// The query was answered; the answer waits in [`Kevery::take_answers`].
    Answered,
    /// The message was kept for later, for the reason given.
    Escrowed(Escrow),
}

/// An accepted event, with the signatures stored for it and the keys and witnesses in force at it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoggedEvent {
    pub(crate) event: SerializedEvent,
    pub(crate) signatures: Vec<IndexedSignature>,
    pub(crate) witness_signatures: Vec<IndexedSignature>,
    pub(crate) receipts: Vec<ReceiptCouple>,
    pub(crate) validator_receipts: Vec<ValidatorReceipt>,
    pub(crate) keys: Vec<VerificationKey>,
    pub(crate) witnesses: Vec<IdentifierPrefix>,
    pub(crate) delegation: Option<SealSourceCouple>,
    pub(crate) event_seals: Vec<EventSeal>,
    pub(crate) first_seen: u128,
    pub(crate) first_seen_at: Timestamp,
}

impl LoggedEvent {
    /// Returns the event.
    #[must_use]
    pub const fn event(&self) -> &SerializedEvent {
        &self.event
    }

    /// Returns the verified controller signatures stored for it.
    #[must_use]
    pub fn signatures(&self) -> &[IndexedSignature] {
        &self.signatures
    }

    /// Returns the verified witness signatures stored for it, attached or receipted.
    #[must_use]
    pub fn witness_signatures(&self) -> &[IndexedSignature] {
        &self.witness_signatures
    }

    /// Returns the verified signatures of validators stored for it.
    #[must_use]
    pub fn validator_receipts(&self) -> &[ValidatorReceipt] {
        &self.validator_receipts
    }

    /// Returns the verified receipt couples from non-witnesses stored for it.
    #[must_use]
    pub fn receipts(&self) -> &[ReceiptCouple] {
        &self.receipts
    }

    /// Returns the signing keys in force at the event.
    #[must_use]
    pub fn keys(&self) -> &[VerificationKey] {
        &self.keys
    }

    /// Returns the witnesses in force at the event.
    #[must_use]
    pub fn witnesses(&self) -> &[IdentifierPrefix] {
        &self.witnesses
    }

    /// Returns, for a delegated event, the delegator's event that anchors it.
    #[must_use]
    pub const fn delegation(&self) -> Option<&SealSourceCouple> {
        self.delegation.as_ref()
    }

    /// Returns the event's first-seen ordinal: how many events of its identifier were accepted
    /// before it, superseded ones included, keripy's `fn`.
    #[must_use]
    pub const fn first_seen(&self) -> u128 {
        self.first_seen
    }

    /// Writes the event as a log replay carries it, keripy's `cloneEvtMsg`: the event, then one
    /// pipelined group holding its controller signatures, witness signatures, delegating event,
    /// validator receipts and receipt couples, each in qb64 order as keripy's database returns
    /// them, and its first-seen ordinal and time.
    ///
    /// # Errors
    ///
    /// Returns [`KelError::Attachment`] when the attachments cannot be encoded.
    pub fn replay(&self) -> Result<Vec<u8>, KelError> {
        let text = |signature: &IndexedSignature| signature.qb64().map_err(KelError::attachment);
        let signatures = sorted(&self.signatures, text)?;
        let witness_signatures = sorted(&self.witness_signatures, text)?;
        let quadruples = self
            .validator_receipts
            .iter()
            .map(|receipt| {
                ReceiptQuadruple::new(
                    receipt.validator().clone(),
                    SequenceNumber::new(receipt.sequence_number()),
                    receipt.said(),
                    receipt.signature().clone(),
                )
            })
            .collect::<Vec<_>>();
        let quadruples = sorted(&quadruples, |quadruple| {
            Ok(format!(
                "{}{}{}{}",
                quadruple.identifier().qb64().map_err(KelError::prefix)?,
                quadruple.sequence_number().qb64().map_err(KelError::cesr)?,
                quadruple.said().qb64().map_err(KelError::said)?,
                quadruple.signature().qb64().map_err(KelError::attachment)?,
            ))
        })?;
        let couples = sorted(&self.receipts, |couple| {
            Ok(format!(
                "{}{}",
                couple.verifier().qb64().map_err(KelError::attachment)?,
                couple.signature().qb64().map_err(KelError::attachment)?,
            ))
        })?;
        let first_seen = FirstSeenReplayCouple::new(SequenceNumber::new(self.first_seen), self.first_seen_at.clone());
        let mut builder = SignedMessageBuilder::new(&self.event)
            .controller_signatures(signatures)
            .witness_signatures(witness_signatures)
            .receipt_quadruples(quadruples)
            .receipt_couples(couples)
            .first_seen(first_seen)
            .framing(AttachmentFraming::Pipelined);
        if let Some(source) = self.delegation {
            builder = builder.source(source);
        }
        Ok(builder.build().map_err(KelError::attachment)?.into_bytes())
    }

    /// Returns whether one of the event's anchors is `seal`.
    #[must_use]
    pub fn anchors(&self, seal: &EventSeal) -> bool {
        self.event_seals.contains(seal)
    }

    /// Returns when the event was first seen.
    #[must_use]
    pub const fn first_seen_at(&self) -> &Timestamp {
        &self.first_seen_at
    }
}

/// An event waiting to be decided, with everything offered for it so far.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowedEvent {
    pub(crate) reason: Escrow,
    /// When it entered its current escrow, relative to every other entry: keripy retries entries at
    /// the same identifier and sequence number in that order.
    pub(crate) arrival: u64,
    pub(crate) sequence_number: u128,
    pub(crate) event: SerializedEvent,
    pub(crate) signatures: Vec<IndexedSignature>,
    pub(crate) witness_signatures: Vec<IndexedSignature>,
    pub(crate) source: Option<SealSourceCouple>,
    pub(crate) since: Timestamp,
}

impl EscrowedEvent {
    /// Returns why the event waits.
    #[must_use]
    pub const fn reason(&self) -> Escrow {
        self.reason
    }

    /// Returns when the event entered its current escrow, relative to every other entry.
    #[must_use]
    pub const fn arrival(&self) -> u64 {
        self.arrival
    }

    /// Returns the event's sequence number.
    #[must_use]
    pub const fn sequence_number(&self) -> u128 {
        self.sequence_number
    }

    /// Returns the event.
    #[must_use]
    pub const fn event(&self) -> &SerializedEvent {
        &self.event
    }

    /// Returns the controller signatures offered for it, unverified.
    #[must_use]
    pub fn signatures(&self) -> &[IndexedSignature] {
        &self.signatures
    }

    /// Returns the witness signatures offered for it, unverified.
    #[must_use]
    pub fn witness_signatures(&self) -> &[IndexedSignature] {
        &self.witness_signatures
    }

    /// Returns the seal source couple naming its delegating event, when one is kept.
    #[must_use]
    pub const fn source(&self) -> Option<&SealSourceCouple> {
        self.source.as_ref()
    }

    /// Returns when the event was first escrowed.
    #[must_use]
    pub const fn since(&self) -> &Timestamp {
        &self.since
    }
}

/// A validator's signature of an event: the validator, the establishment event of its own whose
/// keys signed, and the indexed signature. keripy stores it as a quadruple in its `vrcs` table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatorReceipt {
    pub(crate) validator: IdentifierPrefix,
    pub(crate) sequence_number: u128,
    pub(crate) said: Said,
    pub(crate) signature: IndexedSignature,
}

impl ValidatorReceipt {
    fn from_group(group: &TransferableSignatureGroup, signature: &IndexedSignature) -> Self {
        Self {
            validator: group.identifier().clone(),
            sequence_number: group.sequence_number().value(),
            said: group.said(),
            signature: signature.clone(),
        }
    }

    fn from_quadruple(quadruple: &ReceiptQuadruple) -> Self {
        Self {
            validator: quadruple.identifier().clone(),
            sequence_number: quadruple.sequence_number().value(),
            said: quadruple.said(),
            signature: quadruple.signature().clone(),
        }
    }

    /// Returns the validator's identifier.
    #[must_use]
    pub const fn validator(&self) -> &IdentifierPrefix {
        &self.validator
    }

    /// Returns the sequence number of the validator's establishment event whose keys signed.
    #[must_use]
    pub const fn sequence_number(&self) -> u128 {
        self.sequence_number
    }

    /// Returns the SAID of that establishment event.
    #[must_use]
    pub const fn said(&self) -> Said {
        self.said
    }

    /// Returns the validator's indexed signature.
    #[must_use]
    pub const fn signature(&self) -> &IndexedSignature {
        &self.signature
    }
}

/// What checking a validator's signature against the validator's log found.
enum Check {
    Verified,
    BadSignature,
    /// The validator's event it names is not accepted yet.
    Waiting,
    Refused(KelError),
}

/// A receipt signature waiting for the event it names.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WaitingSignature {
    /// A witness's indexed signature.
    Witness(IndexedSignature),
    /// A non-transferable receiptor's key and signature.
    Couple(ReceiptCouple),
    /// A validator's signature.
    Validator(ValidatorReceipt),
}

/// A receipt signature waiting for the event it names: that event's identifier, sequence number
/// and SAID, the signature, and when it was received.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WaitingReceipt {
    pub(crate) identifier: IdentifierPrefix,
    pub(crate) sequence_number: u128,
    pub(crate) said: Said,
    pub(crate) signature: WaitingSignature,
    pub(crate) received_at: Timestamp,
}

impl WaitingReceipt {
    /// Returns the receipted event's identifier.
    #[must_use]
    pub const fn identifier(&self) -> &IdentifierPrefix {
        &self.identifier
    }

    /// Returns the receipted event's sequence number.
    #[must_use]
    pub const fn sequence_number(&self) -> u128 {
        self.sequence_number
    }

    /// Returns the receipted event's SAID.
    #[must_use]
    pub const fn said(&self) -> Said {
        self.said
    }

    /// Returns the waiting signature.
    #[must_use]
    pub const fn signature(&self) -> &WaitingSignature {
        &self.signature
    }

    /// Returns when the signature was received.
    #[must_use]
    pub const fn received_at(&self) -> &Timestamp {
        &self.received_at
    }
}

/// Many identifiers' key event logs, keripy's `Kevery`, kept in a [`Store`].
#[derive(Clone, Debug, Default)]
pub struct Kevery<S = MemoryStore> {
    pub(crate) store: S,
    pub(crate) trust: NoticeTrust,
    pub(crate) answers: Vec<Answered>,
}

impl Kevery {
    /// An empty set of logs, kept in memory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl<S: Store> Kevery<S> {
    /// Logs kept in `store`, which may already hold some.
    pub fn with_store(store: S) -> Self {
        Self {
            store,
            trust: NoticeTrust::default(),
            answers: Vec::new(),
        }
    }

    /// Keeps key state notices only from the sources `trust` allows. The policy is configuration,
    /// not stored state: a `Kevery` made over an existing store starts trusting any source.
    #[must_use]
    pub fn trusting(mut self, trust: NoticeTrust) -> Self {
        self.trust = trust;
        self
    }

    /// Returns whose key state notices are kept.
    #[must_use]
    pub const fn trust(&self) -> &NoticeTrust {
        &self.trust
    }

    /// Returns the store.
    #[must_use]
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// Returns the store, giving up the logs' processor.
    #[must_use]
    pub fn into_store(self) -> S {
        self.store
    }

    /// Processes one message, first seen at `now`.
    ///
    /// # Errors
    ///
    /// Returns [`KelError::UnsupportedKind`] for a message that is neither a key event nor a
    /// receipt; [`KelError::StaleReceipt`] for a receipt naming an event
    /// other than the one accepted at its sequence number;
    /// [`KelError::ReceiptorEventMismatch`], [`KelError::ReceiptorEventHasNoKeys`] and
    /// [`KelError::ReceiptSignatureIndexOutOfRange`] for a validator's receipt keripy refuses;
    /// [`KelError::DelegationForbidden`] and [`KelError::DelegationSourceAtInception`] for a
    /// delegated event its delegator will never approve; the validation errors of [`Kever`] for
    /// an event that will never be accepted; and [`KelError::Store`] when the store fails.
    pub fn process(&mut self, message: &Message, now: &Timestamp) -> Result<Processed, KelError> {
        let kind = message
            .event()
            .event_kind()
            .map_err(KelError::serialization)?
            .ok_or(KelError::UnexpectedFieldShape { label: "t" })?;
        if kind == EventKind::Reply {
            return self.process_reply(message, now);
        }
        if kind == EventKind::Query {
            return self.process_query(message, now);
        }
        let attachments = message.attachments();
        if kind == EventKind::Receipt {
            return self.process_receipt(
                message.event(),
                attachments.witness_signatures(),
                attachments.receipt_couples(),
                attachments.transferable_signature_groups(),
                now,
            );
        }
        let offer = Offer {
            raw: message.event(),
            signatures: attachments.controller_signatures(),
            witness_signatures: attachments.witness_signatures(),
            // keripy's parser takes the last seal source couple when there are several.
            source: attachments.seal_source_couples().last().copied(),
            first_seen_at: now.clone(),
        };
        let processed = self.process_event(&offer, false)?;
        if matches!(processed, Processed::Accepted | Processed::Duplicate) {
            if !attachments.receipt_couples().is_empty() {
                self.attach_couples(message.event(), attachments.receipt_couples())?;
            }
            self.attach_quadruples(message.event(), attachments.receipt_quadruples(), now)?;
        }
        Ok(processed)
    }

    /// keripy's `processEvent`. `eager` is keripy's flag of the same name: set when retrying an
    /// escrowed event, it lets a delegated event naming no delegating event be looked for in the
    /// delegator's whole log.
    fn process_event(&mut self, offer: &Offer<'_>, eager: bool) -> Result<Processed, KelError> {
        let raw = offer.raw;
        let event = KeyEventFields::read(raw)?;
        let identifier = qb64(event.identifier())?;
        let Some(kever) = self.store.kever(&identifier).map_err(KelError::store)? else {
            if !event.is_inception() {
                let error = KelError::OutOfOrder {
                    expected: 0,
                    found: event.sequence_number(),
                };
                return self.escrow_or_refuse(error, offer, &identifier);
            }
            let incepted = Kever::incept_offered(
                offer,
                &Delegators {
                    store: &self.store,
                    eager,
                },
            );
            return match incepted {
                Ok((kever, verified)) => {
                    let logged = logged(raw, &event, verified, &kever, &offer.first_seen_at);
                    self.store
                        .accept(&identifier, kever, 0, logged)
                        .map_err(KelError::store)?;
                    self.unescrow(&identifier, event.said())?;
                    Ok(Processed::Accepted)
                }
                Err(error) => self.escrow_or_refuse(error, offer, &identifier),
            };
        };

        let next = kever.sequence_number().saturating_add(1);
        let found = event.sequence_number();
        let last_establishment = kever.last_establishment_sequence();
        // keripy offers a rotation superseding an accepted event to the key state even when it is
        // not the next event: a recovery. A delegated rotation may supersede the latest
        // establishment event itself.
        let recovery = found < next
            && match event.kind() {
                EventKind::Rotation => found > last_establishment,
                EventKind::DelegatedRotation => found >= last_establishment,
                _ => false,
            };
        if !recovery && (event.is_inception() || found < next) {
            // Not the next event: a duplicate of the accepted one, or a contradiction of it.
            let said = said_text(&event)?;
            let stored = self
                .store
                .event(&identifier, found)
                .map_err(KelError::store)?
                .filter(|stored| stored.event.said() == Some(said.as_str()));
            let Some(mut stored) = stored else {
                return self.escrow_or_refuse(KelError::LikelyDuplicitous, offer, &identifier);
            };
            let (_, signatures) = verified(offer.signatures, &stored.keys, raw.raw());
            let (_, witness_signatures) =
                verified(offer.witness_signatures, &witness_keys(&stored.witnesses), raw.raw());
            merge(&mut stored.signatures, signatures);
            merge(&mut stored.witness_signatures, witness_signatures);
            self.store
                .update_event(&identifier, found, stored)
                .map_err(KelError::store)?;
            return Ok(Processed::Duplicate);
        }
        if found > next {
            return self.escrow_or_refuse(KelError::OutOfOrder { expected: next, found }, offer, &identifier);
        }
        let mut kever = kever;
        let updated = kever.update_offered(
            offer,
            &Delegators {
                store: &self.store,
                eager,
            },
        );
        match updated {
            Ok(verified) => {
                let logged = logged(raw, &event, verified, &kever, &offer.first_seen_at);
                // A recovery rotation supersedes the event at its sequence number and every one
                // after it; the store moves them aside.
                self.store
                    .accept(&identifier, kever, found, logged)
                    .map_err(KelError::store)?;
                self.unescrow(&identifier, event.said())?;
                Ok(Processed::Accepted)
            }
            Err(error) => self.escrow_or_refuse(error, offer, &identifier),
        }
    }

    /// Keeps an event that cannot be decided yet, merging what was offered with what an earlier
    /// offer left: keripy's `escrowOOEvent`, `escrowPSEvent`, `escrowPWEvent`, `escrowPDEvent` and
    /// `escrowLDEvent`.
    fn escrow_or_refuse(
        &mut self,
        error: KelError,
        offer: &Offer<'_>,
        identifier: &str,
    ) -> Result<Processed, KelError> {
        let Some(reason) = error.escrow() else {
            return Err(error);
        };
        let said = offer.raw.said().ok_or(KelError::UnexpectedFieldShape { label: "d" })?;
        let sequence_number = offer
            .raw
            .sequence_number()
            .map_err(KelError::serialization)?
            .ok_or(KelError::UnexpectedFieldShape { label: "s" })?
            .value();
        let existing = self.store.escrowed(identifier, said).map_err(KelError::store)?;
        let entering = existing.as_ref().is_none_or(|existing| existing.reason != reason);
        let mut entry = existing.unwrap_or_else(|| EscrowedEvent {
            reason,
            arrival: 0,
            sequence_number,
            event: offer.raw.clone(),
            signatures: Vec::new(),
            witness_signatures: Vec::new(),
            source: None,
            since: offer.first_seen_at.clone(),
        });
        if entering {
            entry.reason = reason;
            entry.arrival = self.store.next_arrival().map_err(KelError::store)?;
        }
        merge(&mut entry.signatures, offer.signatures.to_vec());
        match reason {
            // keripy keeps only the controller signatures of a likely-duplicitous event.
            Escrow::LikelyDuplicitous => {}
            // keripy replaces the stored seal source couple with the one just offered, and discards
            // it when it names an event that does not anchor this one, so a retry looks afresh.
            Escrow::PartiallyDelegated => {
                merge(&mut entry.witness_signatures, offer.witness_signatures.to_vec());
                entry.source = match error {
                    KelError::DelegationNotAnchored => None,
                    _ => offer.source,
                };
            }
            _ => {
                merge(&mut entry.witness_signatures, offer.witness_signatures.to_vec());
                if entry.source.is_none() {
                    entry.source = offer.source;
                }
            }
        }
        self.store
            .put_escrowed(identifier, said, entry)
            .map_err(KelError::store)?;
        Ok(Processed::Escrowed(reason))
    }

    fn unescrow(&mut self, identifier: &str, said: Said) -> Result<(), KelError> {
        let said = said.qb64().map_err(KelError::said)?;
        self.store.remove_escrowed(identifier, &said).map_err(KelError::store)
    }

    fn hold(&mut self, receipts: Vec<WaitingReceipt>) -> Result<(), KelError> {
        for receipt in receipts {
            self.store.hold_receipt(receipt).map_err(KelError::store)?;
        }
        Ok(())
    }

    /// keripy's `processReceipt`: witness signatures, non-transferable receipt couples, and
    /// validators' signature groups.
    fn process_receipt(
        &mut self,
        raw: &SerializedEvent,
        witness_signatures: &[IndexedSignature],
        couples: &[ReceiptCouple],
        groups: &[TransferableSignatureGroup],
        now: &Timestamp,
    ) -> Result<Processed, KelError> {
        let receipt = ReceiptMessage::from_serialized(raw.clone()).map_err(KelError::event)?;
        let identifier = qb64(receipt.identifier())?;
        let sequence_number = receipt.sequence_number();
        let waiting = |signature| WaitingReceipt {
            identifier: receipt.identifier().clone(),
            sequence_number,
            said: receipt.said(),
            signature,
            received_at: now.clone(),
        };
        let validators = |group: &TransferableSignatureGroup| -> Vec<WaitingReceipt> {
            group
                .signatures()
                .iter()
                .map(|signature| {
                    waiting(WaitingSignature::Validator(ValidatorReceipt::from_group(
                        group, signature,
                    )))
                })
                .collect()
        };
        let receipted = self
            .store
            .event(&identifier, sequence_number)
            .map_err(KelError::store)?;
        let Some(mut receipted) = receipted else {
            let mut held: Vec<WaitingReceipt> = Vec::new();
            held.extend(
                witness_signatures
                    .iter()
                    .map(|signature| waiting(WaitingSignature::Witness(signature.clone()))),
            );
            held.extend(
                couples
                    .iter()
                    .map(|couple| waiting(WaitingSignature::Couple(couple.clone()))),
            );
            for group in groups {
                held.extend(validators(group));
            }
            self.hold(held)?;
            return Ok(Processed::Escrowed(Escrow::UnverifiedReceipt));
        };
        if receipted.event.said() != Some(receipt.said().qb64().map_err(KelError::said)?.as_str()) {
            return Err(KelError::StaleReceipt);
        }
        // keripy stores couples, then each validator group, then witness signatures, and stops at
        // the first group it cannot verify yet or refuses, keeping what it stored before.
        apply_couples(&mut receipted, couples);
        let mut stopped = None;
        'groups: for group in groups {
            for signature in group.signatures() {
                let validator = ValidatorReceipt::from_group(group, signature);
                match self.check_validator(&validator, receipted.event.raw())? {
                    Check::Verified => {
                        if !receipted.validator_receipts.contains(&validator) {
                            receipted.validator_receipts.push(validator);
                        }
                    }
                    Check::BadSignature => {}
                    Check::Waiting => {
                        stopped = Some(Ok(validators(group)));
                        break 'groups;
                    }
                    Check::Refused(error) => {
                        stopped = Some(Err(error));
                        break 'groups;
                    }
                }
            }
        }
        if stopped.is_none() {
            let keys = witness_keys(&receipted.witnesses);
            let (_, verified) = verified(witness_signatures, &keys, receipted.event.raw());
            merge(&mut receipted.witness_signatures, verified);
        }
        self.store
            .update_event(&identifier, sequence_number, receipted)
            .map_err(KelError::store)?;
        match stopped {
            Some(Ok(held)) => {
                self.hold(held)?;
                Ok(Processed::Escrowed(Escrow::UnverifiedTransferableReceipt))
            }
            Some(Err(error)) => Err(error),
            None => Ok(Processed::Receipted),
        }
    }

    /// keripy's checks of a validator's signature: the validator's accepted event at the named
    /// sequence number must be the one named and list keys, and the signature's index must name
    /// one of them.
    fn check_validator(&self, validator: &ValidatorReceipt, message: &[u8]) -> Result<Check, KelError> {
        let named = self
            .store
            .event(&qb64(&validator.validator)?, validator.sequence_number)
            .map_err(KelError::store)?;
        let Some(named) = named else {
            return Ok(Check::Waiting);
        };
        if validator.said.qb64().ok().as_deref() != named.event.said() {
            return Ok(Check::Refused(KelError::ReceiptorEventMismatch));
        }
        let establishment = !matches!(named.event.event_kind(), Ok(Some(EventKind::Interaction)));
        let keys: &[VerificationKey] = if establishment { &named.keys } else { &[] };
        if keys.is_empty() {
            return Ok(Check::Refused(KelError::ReceiptorEventHasNoKeys));
        }
        let Some(key) = usize::try_from(validator.signature.index())
            .ok()
            .and_then(|index| keys.get(index))
        else {
            return Ok(Check::Refused(KelError::ReceiptSignatureIndexOutOfRange));
        };
        Ok(if key.verify(validator.signature.raw(), message).is_ok() {
            Check::Verified
        } else {
            Check::BadSignature
        })
    }

    /// keripy's `processAttachedReceiptQuadruples`, for an event just accepted or offered again:
    /// stores each quadruple that verifies, and stops at the first that waits for its validator's
    /// event, which is kept, or that fails.
    fn attach_quadruples(
        &mut self,
        raw: &SerializedEvent,
        quadruples: &[ReceiptQuadruple],
        now: &Timestamp,
    ) -> Result<(), KelError> {
        if quadruples.is_empty() {
            return Ok(());
        }
        let event = KeyEventFields::read(raw)?;
        let identifier = qb64(event.identifier())?;
        let sequence_number = event.sequence_number();
        let Some(mut stored) = self
            .store
            .event(&identifier, sequence_number)
            .map_err(KelError::store)?
        else {
            return Ok(());
        };
        let mut held = None;
        for quadruple in quadruples {
            let validator = ValidatorReceipt::from_quadruple(quadruple);
            match self.check_validator(&validator, raw.raw())? {
                Check::Verified => {
                    if !stored.validator_receipts.contains(&validator) {
                        stored.validator_receipts.push(validator);
                    }
                }
                Check::Waiting => {
                    held = Some(WaitingReceipt {
                        identifier: event.identifier().clone(),
                        sequence_number,
                        said: event.said(),
                        signature: WaitingSignature::Validator(validator),
                        received_at: now.clone(),
                    });
                    break;
                }
                // keripy refuses a quadruple whose signature fails, and the rest with it.
                Check::BadSignature | Check::Refused(_) => break,
            }
        }
        self.store
            .update_event(&identifier, sequence_number, stored)
            .map_err(KelError::store)?;
        self.hold(held.into_iter().collect())
    }

    /// keripy's `processAttachedReceiptCouples`, without its prefix-comparison defect.
    fn attach_couples(&mut self, raw: &SerializedEvent, couples: &[ReceiptCouple]) -> Result<(), KelError> {
        let event = KeyEventFields::read(raw)?;
        let identifier = qb64(event.identifier())?;
        let stored = self
            .store
            .event(&identifier, event.sequence_number())
            .map_err(KelError::store)?;
        if let Some(mut stored) = stored {
            if stored.event.said() != raw.said() {
                return Err(KelError::StaleReceipt);
            }
            apply_couples(&mut stored, couples);
            self.store
                .update_event(&identifier, event.sequence_number(), stored)
                .map_err(KelError::store)?;
        }
        Ok(())
    }

    /// Retries everything waiting, in keripy's order: out-of-order events, then receipts waiting
    /// for an escrowed event, then partially delegated, partially witnessed and partially signed
    /// events, then likely-duplicitous ones, and last waiting replies. An event accepted now is
    /// first seen at `now`. Returns
    /// how many events were accepted.
    ///
    /// # Errors
    ///
    /// Returns [`KelError::Store`] when the store fails; an escrowed event refused on retry is
    /// dropped, not returned.
    pub fn process_escrows(&mut self, now: &Timestamp) -> Result<usize, KelError> {
        let mut accepted = self.retry(Escrow::OutOfOrder, now)?;
        self.match_waiting_receipts()?;
        for reason in [
            Escrow::PartiallyDelegated,
            Escrow::PartiallyWitnessed,
            Escrow::PartiallySigned,
            Escrow::LikelyDuplicitous,
        ] {
            accepted += self.retry(reason, now)?;
        }
        self.retry_replies(now)?;
        self.retry_queries()?;
        Ok(accepted)
    }

    /// Offers every event in one escrow again, by identifier, sequence number and arrival, as
    /// keripy's escrow processor for it does, and returns how many were accepted.
    fn retry(&mut self, reason: Escrow, now: &Timestamp) -> Result<usize, KelError> {
        let mut entries = self.store.escrowed_for(reason).map_err(KelError::store)?;
        entries.sort_by(|(left, _, first), (right, _, second)| {
            (left, first.sequence_number, first.arrival).cmp(&(right, second.sequence_number, second.arrival))
        });
        let mut accepted = 0;
        for (identifier, said, _) in entries {
            let escrowed = self
                .store
                .escrowed(&identifier, &said)
                .map_err(KelError::store)?
                .filter(|escrowed| escrowed.reason == reason);
            let Some(escrowed) = escrowed else {
                continue;
            };
            // keripy drops an escrowed event with no controller signature to offer.
            if escrowed.signatures.is_empty() {
                self.store
                    .remove_escrowed(&identifier, &said)
                    .map_err(KelError::store)?;
                continue;
            }
            // keripy retries an out-of-order event without its seal source couple, and a
            // likely-duplicitous one with its controller signatures alone; only the partial escrows
            // look through a delegator's whole log.
            let (witness_signatures, source, eager) = match reason {
                Escrow::OutOfOrder => (escrowed.witness_signatures.as_slice(), None, false),
                Escrow::LikelyDuplicitous => (&[][..], None, false),
                _ => (escrowed.witness_signatures.as_slice(), escrowed.source, true),
            };
            let offer = Offer {
                raw: &escrowed.event,
                signatures: &escrowed.signatures,
                witness_signatures,
                source,
                first_seen_at: now.clone(),
            };
            match self.process_event(&offer, eager) {
                Ok(Processed::Accepted | Processed::Duplicate) => {
                    self.store
                        .remove_escrowed(&identifier, &said)
                        .map_err(KelError::store)?;
                    accepted += 1;
                }
                Ok(
                    Processed::Escrowed(_)
                    | Processed::Receipted
                    | Processed::KeyStateAccepted
                    | Processed::EndRoleAccepted
                    | Processed::LocationAccepted
                    | Processed::ObservationAccepted
                    | Processed::Answered,
                ) => {}
                Err(error @ KelError::Store { .. }) => return Err(error),
                Err(_) => {
                    self.store
                        .remove_escrowed(&identifier, &said)
                        .map_err(KelError::store)?;
                }
            }
        }
        Ok(accepted)
    }

    /// keripy's `processEscrowUnverWitness`, `processEscrowUnverNonTrans` and
    /// `processEscrowUnverTrans`.
    fn match_waiting_receipts(&mut self) -> Result<(), KelError> {
        let waiting = self.store.take_receipts().map_err(KelError::store)?;
        for receipt in waiting {
            match self.match_receipt(&receipt)? {
                Matched::Kept => self.store.hold_receipt(receipt).map_err(KelError::store)?,
                Matched::Applied | Matched::Dropped => {}
            }
        }
        Ok(())
    }

    fn match_receipt(&mut self, receipt: &WaitingReceipt) -> Result<Matched, KelError> {
        let said = receipt.said.qb64().map_err(KelError::said)?;
        if let WaitingSignature::Validator(validator) = &receipt.signature {
            return self.match_validator(receipt, validator, &said);
        }
        let identifier = qb64(&receipt.identifier)?;
        let current = self
            .store
            .kever(&identifier)
            .map_err(KelError::store)?
            .map(|kever| kever.witnesses().to_vec());
        let escrowed = self
            .store
            .escrowed(&identifier, &said)
            .map_err(KelError::store)?
            .filter(|escrowed| {
                escrowed.reason == Escrow::PartiallyWitnessed && escrowed.sequence_number == receipt.sequence_number
            });
        let Some(mut escrowed) = escrowed else {
            return match receipt.signature {
                WaitingSignature::Witness(_) | WaitingSignature::Validator(_) => Ok(Matched::Kept),
                WaitingSignature::Couple(_) => self.apply_to_accepted(receipt, &said),
            };
        };
        let Some(witnesses) = escrowed_witnesses(&escrowed.event, current.as_deref()) else {
            return Ok(Matched::Dropped);
        };
        let keys = witness_keys(&witnesses);
        let signature = match &receipt.signature {
            WaitingSignature::Witness(signature) => {
                if usize::try_from(signature.index()).map_or(true, |index| index >= keys.len()) {
                    return Ok(Matched::Dropped);
                }
                signature.clone()
            }
            WaitingSignature::Couple(couple) => {
                let Some(index) = witnesses.iter().position(|witness| is_key(witness, couple.verifier())) else {
                    return self.apply_to_accepted(receipt, &said);
                };
                match promote(couple, index) {
                    Some(signature) => signature,
                    None => return Ok(Matched::Dropped),
                }
            }
            // Matched above, before any partially witnessed event is consulted.
            WaitingSignature::Validator(_) => return Ok(Matched::Kept),
        };
        let (_, verified) = verified(std::slice::from_ref(&signature), &keys, escrowed.event.raw());
        if verified.is_empty() {
            return Ok(Matched::Dropped);
        }
        merge(&mut escrowed.witness_signatures, verified);
        self.store
            .put_escrowed(&identifier, &said, escrowed)
            .map_err(KelError::store)?;
        Ok(Matched::Applied)
    }

    /// keripy's `processEscrowUnverTrans`: a validator's signature waits until both the receipted
    /// event and the validator's named event are accepted, and is dropped when either is another
    /// event or the signature fails.
    fn match_validator(
        &mut self,
        receipt: &WaitingReceipt,
        validator: &ValidatorReceipt,
        said: &str,
    ) -> Result<Matched, KelError> {
        let identifier = qb64(&receipt.identifier)?;
        let receipted = self
            .store
            .event(&identifier, receipt.sequence_number)
            .map_err(KelError::store)?;
        let Some(mut receipted) = receipted else {
            return Ok(Matched::Kept);
        };
        if receipted.event.said() != Some(said) {
            return Ok(Matched::Dropped);
        }
        match self.check_validator(validator, receipted.event.raw())? {
            Check::Waiting => Ok(Matched::Kept),
            Check::BadSignature | Check::Refused(_) => Ok(Matched::Dropped),
            Check::Verified => {
                if !receipted.validator_receipts.contains(validator) {
                    receipted.validator_receipts.push(validator.clone());
                }
                self.store
                    .update_event(&identifier, receipt.sequence_number, receipted)
                    .map_err(KelError::store)?;
                Ok(Matched::Applied)
            }
        }
    }

    /// The rest of keripy's `processEscrowUnverNonTrans`: a couple whose event has since been
    /// accepted is applied to it.
    fn apply_to_accepted(&mut self, receipt: &WaitingReceipt, said: &str) -> Result<Matched, KelError> {
        let WaitingSignature::Couple(couple) = &receipt.signature else {
            return Ok(Matched::Kept);
        };
        let identifier = qb64(&receipt.identifier)?;
        let Some(kever) = self.store.kever(&identifier).map_err(KelError::store)? else {
            return Ok(Matched::Kept);
        };
        let Some(mut stored) = self
            .store
            .event(&identifier, receipt.sequence_number)
            .map_err(KelError::store)?
        else {
            return Ok(Matched::Kept);
        };
        if stored.event.said() != Some(said)
            || couple
                .verifier()
                .verify(couple.signature().raw(), stored.event.raw())
                .is_err()
        {
            return Ok(Matched::Dropped);
        }
        // keripy promotes against the witnesses in force now, not at the receipted event.
        match kever
            .witnesses()
            .iter()
            .position(|witness| is_key(witness, couple.verifier()))
        {
            Some(index) => {
                if let Some(signature) = promote(couple, index) {
                    merge(&mut stored.witness_signatures, vec![signature]);
                }
            }
            None => {
                if !stored.receipts.contains(couple) {
                    stored.receipts.push(couple.clone());
                }
            }
        }
        self.store
            .update_event(&identifier, receipt.sequence_number, stored)
            .map_err(KelError::store)?;
        Ok(Matched::Applied)
    }

    /// Drops every escrowed event, waiting receipt and waiting reply first seen before `cutoff`, and returns how
    /// many were dropped. Timestamps compare as text, which orders them correctly when they share
    /// a UTC offset, as every timestamp this crate writes does.
    ///
    /// # Errors
    ///
    /// Returns [`KelError::Store`] when the store fails.
    pub fn expire_escrows(&mut self, cutoff: &Timestamp) -> Result<usize, KelError> {
        let events = self.store.expire_escrowed(cutoff).map_err(KelError::store)?;
        let receipts = self.store.expire_receipts(cutoff).map_err(KelError::store)?;
        let replies = self.store.expire_escrowed_replies(cutoff).map_err(KelError::store)?;
        let queries = self.store.expire_escrowed_queries(cutoff).map_err(KelError::store)?;
        Ok(events
            .saturating_add(receipts)
            .saturating_add(replies)
            .saturating_add(queries))
    }

    /// Returns an identifier's key state, when its inception has been accepted.
    ///
    /// # Errors
    ///
    /// Returns [`KelError::Prefix`] for an identifier that cannot be written as qb64, and
    /// [`KelError::Store`] when the store fails.
    pub fn kever(&self, identifier: &IdentifierPrefix) -> Result<Option<Kever>, KelError> {
        self.store.kever(&qb64(identifier)?).map_err(KelError::store)
    }

    /// Returns an identifier's accepted event at `sequence_number`.
    ///
    /// # Errors
    ///
    /// Returns [`KelError::Prefix`] for an identifier that cannot be written as qb64, and
    /// [`KelError::Store`] when the store fails.
    pub fn logged(
        &self,
        identifier: &IdentifierPrefix,
        sequence_number: u128,
    ) -> Result<Option<LoggedEvent>, KelError> {
        self.store
            .event(&qb64(identifier)?, sequence_number)
            .map_err(KelError::store)
    }

    /// Returns the events of an identifier that recovery rotations superseded, in the order they
    /// were superseded.
    ///
    /// # Errors
    ///
    /// Returns [`KelError::Prefix`] for an identifier that cannot be written as qb64, and
    /// [`KelError::Store`] when the store fails.
    pub fn superseded(&self, identifier: &IdentifierPrefix) -> Result<Vec<LoggedEvent>, KelError> {
        self.store.superseded(&qb64(identifier)?).map_err(KelError::store)
    }

    /// Returns how many events are waiting in escrow, for any reason.
    ///
    /// # Errors
    ///
    /// Returns [`KelError::Store`] when the store fails.
    pub fn escrowed_events(&self) -> Result<usize, KelError> {
        self.store.escrowed_count().map_err(KelError::store)
    }

    /// Returns how many receipt signatures are waiting for their event.
    ///
    /// # Errors
    ///
    /// Returns [`KelError::Store`] when the store fails.
    pub fn waiting_receipts(&self) -> Result<usize, KelError> {
        self.store.receipt_count().map_err(KelError::store)
    }
}

enum Matched {
    Applied,
    Kept,
    Dropped,
}

fn qb64(identifier: &IdentifierPrefix) -> Result<String, KelError> {
    identifier.qb64().map_err(KelError::prefix)
}

fn said_text(event: &KeyEventFields) -> Result<String, KelError> {
    event.said().qb64().map_err(KelError::said)
}

fn logged(
    raw: &SerializedEvent,
    event: &KeyEventFields,
    verified: Verified,
    kever: &Kever,
    now: &Timestamp,
) -> LoggedEvent {
    LoggedEvent {
        event: raw.clone(),
        signatures: verified.signatures,
        witness_signatures: verified.witness_signatures,
        receipts: Vec::new(),
        validator_receipts: Vec::new(),
        keys: kever.keys().to_vec(),
        witnesses: kever.witnesses().to_vec(),
        delegation: verified.delegation,
        event_seals: event.event_seals().to_vec(),
        first_seen: kever.first_seen(),
        first_seen_at: now.clone(),
    }
}

/// The delegators' logs, consulted to approve a delegated event.
struct Delegators<'a, S> {
    store: &'a S,
    eager: bool,
}

impl<S: Store> Delegations for Delegators<'_, S> {
    fn approve(
        &self,
        delegator: &IdentifierPrefix,
        event: &KeyEventFields,
        source: Option<SealSourceCouple>,
    ) -> Result<SealSourceCouple, KelError> {
        let delegator = qb64(delegator)?;
        let state = self
            .store
            .kever(&delegator)
            .map_err(KelError::store)?
            .ok_or(KelError::DelegatorUnknown)?;
        if state.does_not_delegate() {
            return Err(KelError::DelegationForbidden);
        }
        let anchors = |logged: &LoggedEvent| logged.event_seals.iter().any(|seal| seal.names(event));
        let sequence_number = if let Some(source) = source {
            let sequence_number = source.sequence_number().value();
            if sequence_number == 0 {
                return Err(KelError::DelegationSourceAtInception);
            }
            // keripy reads the delegator's event at the couple's sequence number and ignores the
            // couple's SAID, storing the found event's instead.
            let logged = self
                .store
                .event(&delegator, sequence_number)
                .map_err(KelError::store)?
                .ok_or(KelError::DelegatingEventUnknown)?;
            if !anchors(&logged) {
                return Err(KelError::DelegationNotAnchored);
            }
            sequence_number
        } else if self.eager {
            self.anchoring(&delegator, &state, anchors)?
                .ok_or(KelError::DelegationNotAnchored)?
        } else {
            return Err(KelError::DelegationNotAnchored);
        };
        self.check_superseding(&delegator, &state, event, sequence_number)?;
        let logged = self
            .store
            .event(&delegator, sequence_number)
            .map_err(KelError::store)?
            .ok_or(KelError::DelegatingEventUnknown)?;
        couple(sequence_number, &logged)
    }
}

impl<S: Store> Delegators<'_, S> {
    /// keripy's `fetchLastSealingEventByEventSeal`: the sequence number of the delegator's earliest
    /// accepted event that `anchors` and is fully witnessed against its witness threshold in force
    /// now.
    fn anchoring(
        &self,
        delegator: &str,
        state: &Kever,
        anchors: impl Fn(&LoggedEvent) -> bool,
    ) -> Result<Option<u128>, KelError> {
        let threshold = usize::try_from(state.witness_threshold()).unwrap_or(usize::MAX);
        let found = self
            .store
            .find_event(delegator, &mut |logged| {
                anchors(logged) && logged.witness_signatures.len() >= threshold
            })
            .map_err(KelError::store)?;
        Ok(found.map(|(sequence_number, _)| sequence_number))
    }

    /// The superseding part of keripy's `validateDelegation`, for a delegated event anchored at
    /// `anchored_at` in the delegator's log.
    ///
    /// A delegated inception, or a rotation following the latest event, supersedes nothing; nor
    /// does a delegated rotation superseding the latest event when that is an interaction at its
    /// sequence number. Otherwise keripy compares the new delegating event with the delegating
    /// event of the delegate's latest event, and accepts only a later one.
    fn check_superseding(
        &self,
        delegator: &str,
        state: &Kever,
        event: &KeyEventFields,
        anchored_at: u128,
    ) -> Result<(), KelError> {
        if event.is_inception() {
            return Ok(());
        }
        let identifier = qb64(event.identifier())?;
        let Some(delegate) = self.store.kever(&identifier).map_err(KelError::store)? else {
            return Ok(());
        };
        let latest = delegate.sequence_number();
        let found = event.sequence_number();
        let over_interaction = found == latest
            && delegate.latest_kind() == EventKind::Interaction
            && event.kind() == EventKind::DelegatedRotation;
        if found == latest.saturating_add(1) || over_interaction {
            return Ok(());
        }
        let Some(superseded) = self.store.event(&identifier, latest).map_err(KelError::store)? else {
            return Ok(());
        };
        let original = match superseded.delegation {
            // keripy's `fetchDelegatingEvent` accepts the stored delegating event when the
            // delegator accepted it at some point, even if a recovery has superseded it since.
            Some(couple) => {
                let said = couple.said().qb64().map_err(KelError::said)?;
                let names = |logged: &LoggedEvent| logged.event.said() == Some(said.as_str());
                let accepted = self
                    .store
                    .find_event(delegator, &mut |logged| names(logged))
                    .map_err(KelError::store)?
                    .map(|(_, logged)| logged);
                let found = match accepted {
                    Some(logged) => Some(logged),
                    None => self
                        .store
                        .superseded(delegator)
                        .map_err(KelError::store)?
                        .into_iter()
                        .find(names),
                };
                found
                    .and_then(|logged| logged.event.sequence_number().ok().flatten())
                    .ok_or(KelError::DelegatingEventUnknown)?
                    .value()
            }
            // Without a stored delegating event keripy waits, then searches the delegator's log
            // when retrying, and refuses when no event there anchors the superseded one.
            None if self.eager => {
                let said = superseded.event.said().unwrap_or_default();
                self.anchoring(delegator, state, |logged| {
                    logged
                        .event_seals
                        .iter()
                        .any(|seal| seal.names_parts(&identifier, latest, said))
                })?
                .ok_or(KelError::SupersededWithoutDelegation)?
            }
            None => return Err(KelError::DelegatingEventUnknown),
        };
        if anchored_at > original {
            Ok(())
        } else {
            Err(KelError::SupersedingDelegationNotLater)
        }
    }
}

/// A seal source couple naming a logged event.
fn couple(sequence_number: u128, logged: &LoggedEvent) -> Result<SealSourceCouple, KelError> {
    let said = Said::from_qb64(logged.event.said().unwrap_or_default()).map_err(KelError::said)?;
    Ok(SealSourceCouple::new(SequenceNumber::new(sequence_number), said))
}

/// `items` in the order of `key`, keripy's sorted duplicates.
fn sorted<T: Clone>(items: &[T], key: impl Fn(&T) -> Result<String, KelError>) -> Result<Vec<T>, KelError> {
    let mut keyed = items
        .iter()
        .map(|item| Ok((key(item)?, item.clone())))
        .collect::<Result<Vec<_>, KelError>>()?;
    keyed.sort_by(|(left, _), (right, _)| left.cmp(right));
    Ok(keyed.into_iter().map(|(_, item)| item).collect())
}

/// Adds each signature not already stored, keripy's set semantics for stored signatures.
fn merge(stored: &mut Vec<IndexedSignature>, added: Vec<IndexedSignature>) {
    for signature in added {
        if !stored.contains(&signature) {
            stored.push(signature);
        }
    }
}

/// Stores verified couples: a witness's as a witness signature at its index, anyone else's as a
/// receipt.
fn apply_couples(stored: &mut LoggedEvent, couples: &[ReceiptCouple]) {
    for couple in couples {
        if couple
            .verifier()
            .verify(couple.signature().raw(), stored.event.raw())
            .is_err()
        {
            continue;
        }
        match stored
            .witnesses
            .iter()
            .position(|witness| is_key(witness, couple.verifier()))
        {
            Some(index) => {
                if let Some(signature) = promote(couple, index) {
                    merge(&mut stored.witness_signatures, vec![signature]);
                }
            }
            None => {
                if !stored.receipts.contains(couple) {
                    stored.receipts.push(couple.clone());
                }
            }
        }
    }
}

fn is_key(witness: &IdentifierPrefix, key: &VerificationKey) -> bool {
    matches!(witness, IdentifierPrefix::Basic(basic) if basic.key() == key)
}

/// Turns a witness's receipt couple into the indexed signature it stands for, with keripy's default
/// indexed-signature code, which names the same position in both key lists.
fn promote(couple: &ReceiptCouple, index: usize) -> Option<IndexedSignature> {
    let index = u32::try_from(index).ok()?;
    IndexedSignature::from_raw(IndexerCode::ED25519, index, Some(index), couple.signature().raw()).ok()
}

/// The witnesses an escrowed event would put in force, keripy's `_processEscrowFindUnver`.
fn escrowed_witnesses(raw: &SerializedEvent, current: Option<&[IdentifierPrefix]>) -> Option<Vec<IdentifierPrefix>> {
    let event = KeyEventFields::read(raw).ok()?;
    match event.kind() {
        EventKind::Inception | EventKind::DelegatedInception => Some(event.witnesses().to_vec()),
        EventKind::Rotation | EventKind::DelegatedRotation => {
            let current = current?;
            Some(
                current
                    .iter()
                    .filter(|witness| !event.cuts().contains(witness))
                    .chain(event.adds())
                    .cloned()
                    .collect(),
            )
        }
        _ => current.map(<[IdentifierPrefix]>::to_vec),
    }
}
