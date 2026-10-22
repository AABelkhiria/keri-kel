//! Many identifiers' logs, the receipts that arrive for them, and the events still waiting.
//!
//! A [`Kevery`] takes messages as they arrive, from any source, and routes each one:
//!
//! - an inception for an identifier it has not seen starts that identifier's log;
//! - the next event for a known identifier is validated against its key state;
//! - an event already accepted is a duplicate, and any further signatures it carries that verify
//!   are added to the stored event;
//! - a receipt (`rct`) adds witness signatures, or receipt couples, to the event it names.
//!
//! A delegated inception, or a rotation of a delegated identifier, is accepted only once its
//! delegator's log holds an event anchoring a seal of it. The event may name that event in a seal
//! source couple; the couple is checked against the delegator's log, and the delegating event found
//! is stored with the delegated one.
//!
//! An event refused only for want of signatures or of its delegator's approval is kept in an
//! escrow, partially signed, partially witnessed or partially delegated, with everything offered for
//! it so far. A receipt for an event not yet accepted is kept too. [`Kevery::process_escrows`]
//! retries all of them: receipts are matched to the events they name, and each escrowed event is
//! offered again with everything gathered for it. On a retry, a delegated event naming no delegating
//! event is looked for in its delegator's whole log, as keripy does only when retrying.
//!
//! This ports keripy's `Kevery` (`src/keri/core/eventing.py`): `processEvent`, `processReceipt`,
//! `processAttachedReceiptCouples`, `Kever.validateDelegation`, and the partially signed, partially
//! witnessed, partially delegated and unverified receipt escrows with their processors. A rotation
//! superseding an accepted one, which a delegated identifier may use to recover, is refused with
//! [`KelError::RecoveryUnsupported`]. Events that arrive out of order and events that
//! contradict an accepted one are refused here, with [`KelError::OutOfOrder`] and
//! [`KelError::LikelyDuplicitous`]; keripy escrows both, and so will this port once they are ported
//! with their own fixtures.
//!
//! One behaviour differs. When a witness's receipt couple is attached to an event, keripy's
//! `processAttachedReceiptCouples` compares the couple's key, a string, against a list of prefix
//! objects, which never matches, so the witness's signature is stored as a plain receipt and never
//! counts toward the witness threshold. It is stored as the witness signature it is here, as
//! keripy's `processReceipt` does for the same couple arriving in a receipt message.
//!
//! Escrowed items keep the time they were first escrowed. keripy drops them after an hour;
//! [`Kevery::expire_escrows`] drops everything escrowed before a cutoff the caller chooses, since
//! this crate reads no clock.

use std::collections::BTreeMap;

use keri_cesr::crypto::signature::IndexedSignature;
use keri_cesr::crypto::verifier::VerificationKey;
use keri_cesr::indexer::IndexerCode;
use keri_cesr::sequence::SequenceNumber;
use keri_protocol::attachment::{ReceiptCouple, SealSourceCouple};
use keri_protocol::event::kind::EventKind;
use keri_protocol::event::receipt::ReceiptMessage;
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;
use keri_protocol::serialization::SerializedEvent;
use keri_protocol::stream::Message;

use crate::error::{Escrow, KelError};
use crate::event::{EventSeal, KeyEventFields};
use crate::kever::{Delegations, Kever, Offer, Verified, verified, witness_keys};

/// What became of one processed message.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Processed {
    /// The event was accepted into its log.
    Accepted,
    /// The event was already accepted; any further verified signatures were added to it.
    Duplicate,
    /// The receipt's signatures were added to the event it names.
    Receipted,
    /// The message was kept for later, for the reason given.
    Escrowed(Escrow),
}

/// An accepted event, with the signatures stored for it and the keys and witnesses in force at it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoggedEvent {
    event: SerializedEvent,
    signatures: Vec<IndexedSignature>,
    witness_signatures: Vec<IndexedSignature>,
    receipts: Vec<ReceiptCouple>,
    keys: Vec<VerificationKey>,
    witnesses: Vec<IdentifierPrefix>,
    delegation: Option<SealSourceCouple>,
    event_seals: Vec<EventSeal>,
    first_seen_at: Timestamp,
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

    /// Returns when the event was first seen.
    #[must_use]
    pub const fn first_seen_at(&self) -> &Timestamp {
        &self.first_seen_at
    }
}

/// One identifier's key state and accepted events.
#[derive(Clone, Debug)]
struct Log {
    kever: Kever,
    events: BTreeMap<u128, LoggedEvent>,
}

/// An event waiting for signatures or its delegator's approval, with everything offered for it so
/// far.
#[derive(Clone, Debug)]
struct Escrowed {
    reason: Escrow,
    event: SerializedEvent,
    signatures: Vec<IndexedSignature>,
    witness_signatures: Vec<IndexedSignature>,
    source: Option<SealSourceCouple>,
    since: Timestamp,
}

/// A receipt signature waiting for the event it names.
#[derive(Clone, Debug)]
enum WaitingSignature {
    Witness(IndexedSignature),
    Couple(ReceiptCouple),
}

#[derive(Clone, Debug)]
struct WaitingReceipt {
    identifier: String,
    sequence_number: u128,
    said: Said,
    signature: WaitingSignature,
    received_at: Timestamp,
}

/// Many identifiers' key event logs, keripy's `Kevery`.
#[derive(Clone, Debug, Default)]
pub struct Kevery {
    logs: BTreeMap<String, Log>,
    escrowed: BTreeMap<(String, String), Escrowed>,
    receipts: Vec<WaitingReceipt>,
}

impl Kevery {
    /// An empty set of logs.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Processes one message, first seen at `now`.
    ///
    /// # Errors
    ///
    /// Returns [`KelError::UnsupportedKind`] for a message that is neither a key event nor a
    /// receipt; [`KelError::OutOfOrder`] for an event beyond the next one, or any non-inception
    /// event for an unknown identifier; [`KelError::LikelyDuplicitous`] for an event that
    /// contradicts one already accepted; [`KelError::StaleReceipt`] for a receipt naming an event
    /// other than the one accepted at its sequence number;
    /// [`KelError::TransferableReceiptsUnsupported`] for a receipt from a transferable identifier;
    /// [`KelError::DelegationForbidden`] and [`KelError::DelegationSourceAtInception`] for a
    /// delegated event its delegator will never approve; and the validation errors of [`Kever`] for
    /// an event that will never be accepted.
    pub fn process(&mut self, message: &Message, now: &Timestamp) -> Result<Processed, KelError> {
        let kind = message
            .event()
            .event_kind()
            .map_err(KelError::serialization)?
            .ok_or(KelError::UnexpectedFieldShape { label: "t" })?;
        let attachments = message.attachments();
        if kind == EventKind::Receipt {
            if !attachments.transferable_signature_groups().is_empty() || !attachments.receipt_quadruples().is_empty() {
                return Err(KelError::TransferableReceiptsUnsupported);
            }
            return self.process_receipt(
                message.event(),
                attachments.witness_signatures(),
                attachments.receipt_couples(),
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
        if !attachments.receipt_couples().is_empty() && matches!(processed, Processed::Accepted | Processed::Duplicate)
        {
            self.attach_couples(message.event(), attachments.receipt_couples())?;
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
        let delegations = Delegators {
            logs: &self.logs,
            eager,
        };
        let Some(log) = self.logs.get(&identifier) else {
            if !event.is_inception() {
                return Err(KelError::OutOfOrder {
                    expected: 0,
                    found: event.sequence_number(),
                });
            }
            return match Kever::incept_offered(offer, &delegations) {
                Ok((kever, verified)) => {
                    let logged = logged(raw, &event, verified, &kever, &offer.first_seen_at);
                    self.logs.insert(
                        identifier.clone(),
                        Log {
                            kever,
                            events: BTreeMap::from([(0, logged)]),
                        },
                    );
                    self.unescrow(&identifier, event.said());
                    Ok(Processed::Accepted)
                }
                Err(error) => self.escrow_or_refuse(error, offer, &identifier),
            };
        };

        let next = log.kever.sequence_number().saturating_add(1);
        let found = event.sequence_number();
        let last_establishment = log.kever.last_establishment_sequence();
        // keripy offers a rotation superseding an accepted event to the key state even when it is
        // not the next event: a recovery, which the key state refuses until it is ported. A
        // delegated rotation may supersede the latest establishment event itself.
        let recovery = found < next
            && match event.kind() {
                EventKind::Rotation => found > last_establishment,
                EventKind::DelegatedRotation => found >= last_establishment,
                _ => false,
            };
        if !recovery && (event.is_inception() || found < next) {
            // Not the next event: a duplicate of the accepted one, or a contradiction of it.
            let said = said_text(&event)?;
            let Some(stored) = self
                .logs
                .get_mut(&identifier)
                .and_then(|log| log.events.get_mut(&found))
            else {
                return Err(KelError::LikelyDuplicitous);
            };
            if stored.event.said() != Some(said.as_str()) {
                return Err(KelError::LikelyDuplicitous);
            }
            let (_, signatures) = verified(offer.signatures, &stored.keys, raw.raw());
            let (_, witness_signatures) =
                verified(offer.witness_signatures, &witness_keys(&stored.witnesses), raw.raw());
            merge(&mut stored.signatures, signatures);
            merge(&mut stored.witness_signatures, witness_signatures);
            return Ok(Processed::Duplicate);
        }
        if found > next {
            return Err(KelError::OutOfOrder { expected: next, found });
        }
        // The key state is updated on a copy: validating a delegation reads the other logs.
        let mut kever = log.kever.clone();
        match kever.update_offered(offer, &delegations) {
            Ok(verified) => {
                let logged = logged(raw, &event, verified, &kever, &offer.first_seen_at);
                if let Some(log) = self.logs.get_mut(&identifier) {
                    log.kever = kever;
                    log.events.insert(found, logged);
                }
                self.unescrow(&identifier, event.said());
                Ok(Processed::Accepted)
            }
            Err(error) => self.escrow_or_refuse(error, offer, &identifier),
        }
    }

    /// Keeps an event refused only for want of signatures or of its delegator's approval, merging
    /// what was offered with what an earlier offer left: keripy's `escrowPSEvent`,
    /// `escrowPWEvent` and `escrowPDEvent`.
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
        let entry = self
            .escrowed
            .entry((identifier.to_owned(), said.to_owned()))
            .or_insert_with(|| Escrowed {
                reason,
                event: offer.raw.clone(),
                signatures: Vec::new(),
                witness_signatures: Vec::new(),
                source: None,
                since: offer.first_seen_at.clone(),
            });
        entry.reason = reason;
        merge(&mut entry.signatures, offer.signatures.to_vec());
        merge(&mut entry.witness_signatures, offer.witness_signatures.to_vec());
        if reason == Escrow::PartiallyDelegated {
            // keripy replaces the stored seal source couple with the one just offered, and discards
            // it when it names an event that does not anchor this one, so a retry looks afresh.
            entry.source = match error {
                KelError::DelegationNotAnchored => None,
                _ => offer.source,
            };
        } else if entry.source.is_none() {
            entry.source = offer.source;
        }
        Ok(Processed::Escrowed(reason))
    }

    fn unescrow(&mut self, identifier: &str, said: Said) {
        if let Ok(said) = said.qb64() {
            self.escrowed.remove(&(identifier.to_owned(), said));
        }
    }

    /// keripy's `processReceipt` for witness signatures and non-transferable receipt couples.
    fn process_receipt(
        &mut self,
        raw: &SerializedEvent,
        witness_signatures: &[IndexedSignature],
        couples: &[ReceiptCouple],
        now: &Timestamp,
    ) -> Result<Processed, KelError> {
        let receipt = ReceiptMessage::from_serialized(raw.clone()).map_err(KelError::event)?;
        let identifier = qb64(receipt.identifier())?;
        let stored = self
            .logs
            .get_mut(&identifier)
            .and_then(|log| log.events.get_mut(&receipt.sequence_number()));
        let Some(stored) = stored else {
            for signature in witness_signatures {
                self.receipts.push(WaitingReceipt {
                    identifier: identifier.clone(),
                    sequence_number: receipt.sequence_number(),
                    said: receipt.said(),
                    signature: WaitingSignature::Witness(signature.clone()),
                    received_at: now.clone(),
                });
            }
            for couple in couples {
                self.receipts.push(WaitingReceipt {
                    identifier: identifier.clone(),
                    sequence_number: receipt.sequence_number(),
                    said: receipt.said(),
                    signature: WaitingSignature::Couple(couple.clone()),
                    received_at: now.clone(),
                });
            }
            return Ok(Processed::Escrowed(Escrow::UnverifiedReceipt));
        };
        if stored.event.said() != Some(receipt.said().qb64().map_err(KelError::said)?.as_str()) {
            return Err(KelError::StaleReceipt);
        }
        apply_couples(stored, couples);
        let keys = witness_keys(&stored.witnesses);
        let (_, verified) = verified(witness_signatures, &keys, stored.event.raw());
        merge(&mut stored.witness_signatures, verified);
        Ok(Processed::Receipted)
    }

    /// keripy's `processAttachedReceiptCouples`, without its prefix-comparison defect.
    fn attach_couples(&mut self, raw: &SerializedEvent, couples: &[ReceiptCouple]) -> Result<(), KelError> {
        let event = KeyEventFields::read(raw)?;
        let identifier = qb64(event.identifier())?;
        if let Some(stored) = self
            .logs
            .get_mut(&identifier)
            .and_then(|log| log.events.get_mut(&event.sequence_number()))
        {
            if stored.event.said() != raw.said() {
                return Err(KelError::StaleReceipt);
            }
            apply_couples(stored, couples);
        }
        Ok(())
    }

    /// Retries everything waiting, in keripy's order: receipts waiting for an escrowed event, then
    /// partially delegated events, then partially witnessed ones, then partially signed ones. An
    /// event accepted now is first seen at `now`. Returns how many events were accepted.
    pub fn process_escrows(&mut self, now: &Timestamp) -> usize {
        self.match_waiting_receipts();
        let mut accepted = 0;
        for reason in [
            Escrow::PartiallyDelegated,
            Escrow::PartiallyWitnessed,
            Escrow::PartiallySigned,
        ] {
            let keys: Vec<(String, String)> = self
                .escrowed
                .iter()
                .filter(|(_, escrowed)| escrowed.reason == reason)
                .map(|(key, _)| key.clone())
                .collect();
            for key in keys {
                let Some(escrowed) = self.escrowed.get(&key).cloned() else {
                    continue;
                };
                let offer = Offer {
                    raw: &escrowed.event,
                    signatures: &escrowed.signatures,
                    witness_signatures: &escrowed.witness_signatures,
                    source: escrowed.source,
                    first_seen_at: now.clone(),
                };
                match self.process_event(&offer, true) {
                    Ok(Processed::Accepted | Processed::Duplicate) => {
                        self.escrowed.remove(&key);
                        accepted += 1;
                    }
                    Ok(Processed::Escrowed(_) | Processed::Receipted) => {}
                    Err(_) => {
                        self.escrowed.remove(&key);
                    }
                }
            }
        }
        accepted
    }

    /// keripy's `processEscrowUnverWitness` and `processEscrowUnverNonTrans`.
    fn match_waiting_receipts(&mut self) {
        let waiting = std::mem::take(&mut self.receipts);
        for receipt in waiting {
            match self.match_receipt(&receipt) {
                Matched::Kept => self.receipts.push(receipt),
                Matched::Applied | Matched::Dropped => {}
            }
        }
    }

    fn match_receipt(&mut self, receipt: &WaitingReceipt) -> Matched {
        let Ok(said) = receipt.said.qb64() else {
            return Matched::Dropped;
        };
        let current = self
            .logs
            .get(&receipt.identifier)
            .map(|log| log.kever.witnesses().to_vec());
        if let Some(escrowed) = self.escrowed.get_mut(&(receipt.identifier.clone(), said.clone()))
            && escrowed.reason == Escrow::PartiallyWitnessed
            && KeyEventFields::read(&escrowed.event)
                .is_ok_and(|event| event.sequence_number() == receipt.sequence_number)
        {
            let Some(witnesses) = escrowed_witnesses(&escrowed.event, current.as_deref()) else {
                return Matched::Dropped;
            };
            let keys = witness_keys(&witnesses);
            let signature = match &receipt.signature {
                WaitingSignature::Witness(signature) => {
                    if usize::try_from(signature.index()).map_or(true, |index| index >= keys.len()) {
                        return Matched::Dropped;
                    }
                    signature.clone()
                }
                WaitingSignature::Couple(couple) => {
                    let Some(index) = witnesses.iter().position(|witness| is_key(witness, couple.verifier())) else {
                        return self.apply_to_accepted(receipt, &said);
                    };
                    match promote(couple, index) {
                        Some(signature) => signature,
                        None => return Matched::Dropped,
                    }
                }
            };
            let (_, verified) = verified(std::slice::from_ref(&signature), &keys, escrowed.event.raw());
            if verified.is_empty() {
                return Matched::Dropped;
            }
            merge(&mut escrowed.witness_signatures, verified);
            return Matched::Applied;
        }
        match receipt.signature {
            WaitingSignature::Witness(_) => Matched::Kept,
            WaitingSignature::Couple(_) => self.apply_to_accepted(receipt, &said),
        }
    }

    /// The rest of keripy's `processEscrowUnverNonTrans`: a couple whose event has since been
    /// accepted is applied to it.
    fn apply_to_accepted(&mut self, receipt: &WaitingReceipt, said: &str) -> Matched {
        let WaitingSignature::Couple(couple) = &receipt.signature else {
            return Matched::Kept;
        };
        let Some(log) = self.logs.get_mut(&receipt.identifier) else {
            return Matched::Kept;
        };
        let current = log.kever.witnesses().to_vec();
        let Some(stored) = log.events.get_mut(&receipt.sequence_number) else {
            return Matched::Kept;
        };
        if stored.event.said() != Some(said)
            || couple
                .verifier()
                .verify(couple.signature().raw(), stored.event.raw())
                .is_err()
        {
            return Matched::Dropped;
        }
        // keripy promotes against the witnesses in force now, not at the receipted event.
        match current.iter().position(|witness| is_key(witness, couple.verifier())) {
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
        Matched::Applied
    }

    /// Drops every escrowed event and waiting receipt first seen before `cutoff`, and returns how
    /// many were dropped. Timestamps compare as text, which orders them correctly when they share
    /// a UTC offset, as every timestamp this crate writes does.
    pub fn expire_escrows(&mut self, cutoff: &Timestamp) -> usize {
        let before = self.escrowed.len() + self.receipts.len();
        self.escrowed.retain(|_, escrowed| &escrowed.since >= cutoff);
        self.receipts.retain(|receipt| &receipt.received_at >= cutoff);
        before - self.escrowed.len() - self.receipts.len()
    }

    /// Returns an identifier's key state, when its inception has been accepted.
    #[must_use]
    pub fn kever(&self, identifier: &IdentifierPrefix) -> Option<&Kever> {
        let identifier = identifier.qb64().ok()?;
        self.logs.get(&identifier).map(|log| &log.kever)
    }

    /// Returns an identifier's accepted event at `sequence_number`.
    #[must_use]
    pub fn logged(&self, identifier: &IdentifierPrefix, sequence_number: u128) -> Option<&LoggedEvent> {
        let identifier = identifier.qb64().ok()?;
        self.logs.get(&identifier)?.events.get(&sequence_number)
    }

    /// Returns how many events are waiting in escrow, for any reason.
    #[must_use]
    pub fn escrowed_events(&self) -> usize {
        self.escrowed.len()
    }

    /// Returns how many receipt signatures are waiting for their event.
    #[must_use]
    pub fn waiting_receipts(&self) -> usize {
        self.receipts.len()
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
        keys: kever.keys().to_vec(),
        witnesses: kever.witnesses().to_vec(),
        delegation: verified.delegation,
        event_seals: event.event_seals().to_vec(),
        first_seen_at: now.clone(),
    }
}

/// The delegators' logs, consulted to approve a delegated event.
struct Delegators<'a> {
    logs: &'a BTreeMap<String, Log>,
    eager: bool,
}

impl Delegations for Delegators<'_> {
    fn approve(
        &self,
        delegator: &IdentifierPrefix,
        event: &KeyEventFields,
        source: Option<SealSourceCouple>,
    ) -> Result<SealSourceCouple, KelError> {
        let log = self.logs.get(&qb64(delegator)?).ok_or(KelError::DelegatorUnknown)?;
        if log.kever.does_not_delegate() {
            return Err(KelError::DelegationForbidden);
        }
        let anchors = |logged: &LoggedEvent| logged.event_seals.iter().any(|seal| seal.names(event));
        let Some(source) = source else {
            if !self.eager {
                return Err(KelError::DelegationNotAnchored);
            }
            // keripy's `fetchLastSealingEventByEventSeal`: the earliest anchoring event that is
            // fully witnessed against the delegator's witness threshold in force now.
            let threshold = usize::try_from(log.kever.witness_threshold()).unwrap_or(usize::MAX);
            return log
                .events
                .iter()
                .find(|(_, logged)| anchors(logged) && logged.witness_signatures.len() >= threshold)
                .map(|(sequence_number, logged)| couple(*sequence_number, logged))
                .ok_or(KelError::DelegationNotAnchored)?;
        };
        let sequence_number = source.sequence_number().value();
        if sequence_number == 0 {
            return Err(KelError::DelegationSourceAtInception);
        }
        // keripy reads the delegator's event at the couple's sequence number and ignores the
        // couple's SAID, storing the found event's instead.
        let logged = log
            .events
            .get(&sequence_number)
            .ok_or(KelError::DelegatingEventUnknown)?;
        if !anchors(logged) {
            return Err(KelError::DelegationNotAnchored);
        }
        couple(sequence_number, logged)
    }
}

/// A seal source couple naming a logged event.
fn couple(sequence_number: u128, logged: &LoggedEvent) -> Result<SealSourceCouple, KelError> {
    let said = Said::from_qb64(logged.event.said().unwrap_or_default()).map_err(KelError::said)?;
    Ok(SealSourceCouple::new(SequenceNumber::new(sequence_number), said))
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
