//! One identifier's key state, and the rules that extend it.
//!
//! A [`Kever`] is created from a signed inception and extended by signed rotations and
//! interactions, one sequence number at a time. Each event is accepted only when:
//!
//! - it belongs to the identifier and follows the latest event: its sequence number is the next
//!   one and its prior digest is the latest event's SAID;
//! - its establishment fields are coherent: the signing threshold fits the keys, the witness list
//!   holds no duplicates and the witness threshold fits it, a rotation's cuts and adds are
//!   consistent with the current witnesses;
//! - its controller signatures, verified against the keys in force (the event's own keys for an
//!   establishment event, the current keys for an interaction), meet the signing threshold;
//! - for a rotation, the same signatures also expose enough of the keys the prior establishment
//!   event committed to as next keys, to meet the prior next-key threshold;
//! - a rotation may also land on a sequence number already taken by an interaction accepted since
//!   the latest establishment event, following the event before it: a recovery rotation, which
//!   supersedes that interaction and every event after it;
//! - its witness signatures, verified against the witness list in force, meet the witness
//!   threshold;
//! - for a delegated inception, or a rotation of a delegated identifier, its delegator has
//!   accepted an event anchoring a seal of it.
//!
//! This ports keripy's `Kever.incept`, `update`, `rotate`, `deriveBacks`, `valSigsWigsDel` and
//! `exposeds` (`src/keri/core/eventing.py`) for events that carry their witness signatures. The
//! order of the checks, and therefore which error a doubly-bad event gets, follows keripy's.
//!
//! A `Kever` holds one log, so it cannot see a delegator's: [`Kever::incept`] and
//! [`Kever::update`] refuse a delegated event with [`KelError::DelegatorUnknown`]. A
//! [`Kevery`](crate::Kevery) holds the delegator's log as well and validates the delegation.

use keri_cesr::crypto::digest::Digest;
use keri_cesr::crypto::signature::IndexedSignature;
use keri_cesr::crypto::verifier::VerificationKey;
use keri_protocol::attachment::SealSourceCouple;
use keri_protocol::event::config::ConfigurationTrait;
use keri_protocol::event::key_state::{KeyStateBuilder, KeyStateRecord, LatestEstablishment};
use keri_protocol::event::kind::EventKind;
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;
use keri_protocol::serialization::SerializedEvent;
use keri_protocol::stream::Message;
use keri_protocol::threshold::SigningThreshold;

use crate::error::KelError;
use crate::event::KeyEventFields;

/// One identifier's key state at its latest accepted event, keripy's `Kever`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Kever {
    pub(crate) identifier: IdentifierPrefix,
    pub(crate) sequence_number: u128,
    pub(crate) said: Said,
    pub(crate) prior: Option<Said>,
    pub(crate) latest_kind: EventKind,
    pub(crate) keys: Vec<VerificationKey>,
    pub(crate) signing_threshold: SigningThreshold,
    pub(crate) next_digests: Vec<Digest>,
    pub(crate) next_threshold: SigningThreshold,
    pub(crate) witnesses: Vec<IdentifierPrefix>,
    pub(crate) witness_threshold: u32,
    pub(crate) cuts: Vec<IdentifierPrefix>,
    pub(crate) adds: Vec<IdentifierPrefix>,
    pub(crate) last_establishment: (u128, Said),
    /// The SAIDs of the latest establishment event and every event since, which a recovery
    /// rotation may follow.
    pub(crate) since_establishment: Vec<Said>,
    /// The latest establishment event's prior, which a delegated rotation superseding it follows.
    pub(crate) establishment_prior: Option<Said>,
    pub(crate) establishment_only: bool,
    pub(crate) do_not_delegate: bool,
    pub(crate) delegator: Option<IdentifierPrefix>,
    pub(crate) first_seen: u128,
    pub(crate) first_seen_at: Timestamp,
}

/// The signatures an accepted event carried that verified, and for a delegated event the
/// delegator's event that approved it, which a log stores with it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Verified {
    pub(crate) signatures: Vec<IndexedSignature>,
    pub(crate) witness_signatures: Vec<IndexedSignature>,
    pub(crate) delegation: Option<SealSourceCouple>,
}

/// An event offered for validation: its serialization, everything attached to it, and when it is
/// first seen if accepted.
pub(crate) struct Offer<'a> {
    pub(crate) raw: &'a SerializedEvent,
    pub(crate) signatures: &'a [IndexedSignature],
    pub(crate) witness_signatures: &'a [IndexedSignature],
    pub(crate) source: Option<SealSourceCouple>,
    pub(crate) first_seen_at: Timestamp,
}

impl<'a> Offer<'a> {
    fn of(message: &'a Message, first_seen_at: Timestamp) -> Self {
        let attachments = message.attachments();
        Self {
            raw: message.event(),
            signatures: attachments.controller_signatures(),
            witness_signatures: attachments.witness_signatures(),
            // keripy's parser takes the last seal source couple when there are several.
            source: attachments.seal_source_couples().last().copied(),
            first_seen_at,
        }
    }
}

/// Where a delegated event's approval is looked up: the delegator's log, which a `Kever` does not
/// hold.
pub(crate) trait Delegations {
    /// keripy's `validateDelegation`: returns the delegator's event anchoring a seal of `event`,
    /// starting from the seal source couple the event named, if any.
    fn approve(
        &self,
        delegator: &IdentifierPrefix,
        event: &KeyEventFields,
        source: Option<SealSourceCouple>,
    ) -> Result<SealSourceCouple, KelError>;
}

/// No delegator's log at all, for a `Kever` used on its own.
struct NoDelegators;

impl Delegations for NoDelegators {
    fn approve(
        &self,
        _: &IdentifierPrefix,
        _: &KeyEventFields,
        _: Option<SealSourceCouple>,
    ) -> Result<SealSourceCouple, KelError> {
        Err(KelError::DelegatorUnknown)
    }
}

/// The establishment fields a validated rotation would put in force.
struct Rotation {
    signing_threshold: SigningThreshold,
    witness_threshold: u32,
    witnesses: Vec<IdentifierPrefix>,
    cuts: Vec<IdentifierPrefix>,
    adds: Vec<IdentifierPrefix>,
}

impl Kever {
    /// Starts a log from a signed inception, first seen at `first_seen_at`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`KeyEventFields::read`]; [`KelError::UnsupportedKind`] for anything
    /// but an inception; [`KelError::DelegatorUnknown`] for a delegated inception, whose delegator's
    /// log only a [`Kevery`](crate::Kevery) can consult; [`KelError::NonZeroInception`]; [`KelError::ThresholdExceedsKeys`];
    /// [`KelError::NonTransferableInception`]; [`KelError::DuplicateWitness`] and
    /// [`KelError::InvalidWitnessThreshold`]; [`KelError::NoVerifiedSignatures`]; and, when waiting
    /// for more signatures could help, [`KelError::NotFullySigned`] or
    /// [`KelError::NotFullyWitnessed`].
    pub fn incept(message: &Message, first_seen_at: Timestamp) -> Result<Self, KelError> {
        Self::incept_offered(&Offer::of(message, first_seen_at), &NoDelegators).map(|(kever, _)| kever)
    }

    /// [`Self::incept`] over an event and its attachments held apart, with delegators to consult,
    /// returning what verified, which is what a log stores.
    pub(crate) fn incept_offered(
        offer: &Offer<'_>,
        delegations: &dyn Delegations,
    ) -> Result<(Self, Verified), KelError> {
        let raw = offer.raw;
        let event = KeyEventFields::read(raw)?;
        if !event.is_inception() {
            return Err(KelError::UnsupportedKind {
                kind: event.kind().as_str(),
            });
        }
        if event.sequence_number() != 0 {
            return Err(KelError::NonZeroInception);
        }
        let signing_threshold = established_threshold(&event)?;
        check_threshold_fits(&signing_threshold, event.keys().len())?;
        let transferable = event.identifier().is_transferable();
        if !transferable {
            for (label, empty) in [
                ("n", event.next_digests().is_empty()),
                ("b", event.witnesses().is_empty()),
                ("a", event.anchors() == 0),
            ] {
                if !empty {
                    return Err(KelError::NonTransferableInception { label });
                }
            }
        }
        check_distinct(event.witnesses(), "b")?;
        check_witness_threshold(event.witness_threshold(), event.witnesses().len())?;

        let (indices, signatures) = verified(offer.signatures, event.keys(), raw.raw());
        if indices.is_empty() {
            return Err(KelError::NoVerifiedSignatures);
        }
        if !signing_threshold
            .is_satisfied_by(&indices)
            .map_err(KelError::threshold)?
        {
            return Err(KelError::NotFullySigned);
        }
        let witness_signatures = check_witnessed(
            raw,
            offer.witness_signatures,
            event.witnesses(),
            event.witness_threshold(),
        )?;
        let delegation = match event.delegator() {
            Some(delegator) => Some(delegations.approve(delegator, &event, offer.source)?),
            None => None,
        };

        let kever = Self {
            identifier: event.identifier().clone(),
            sequence_number: 0,
            said: event.said(),
            prior: None,
            latest_kind: event.kind(),
            keys: event.keys().to_vec(),
            signing_threshold,
            next_digests: event.next_digests().to_vec(),
            next_threshold: next_threshold(&event)?,
            witnesses: event.witnesses().to_vec(),
            witness_threshold: event.witness_threshold(),
            cuts: Vec::new(),
            adds: Vec::new(),
            last_establishment: (0, event.said()),
            since_establishment: vec![event.said()],
            establishment_prior: None,
            establishment_only: event.establishment_only(),
            do_not_delegate: event.do_not_delegate(),
            delegator: event.delegator().cloned(),
            first_seen: 0,
            first_seen_at: offer.first_seen_at.clone(),
        };
        Ok((
            kever,
            Verified {
                signatures,
                witness_signatures,
                delegation,
            },
        ))
    }

    /// Extends the log with a signed rotation or interaction, first seen at `first_seen_at`.
    ///
    /// The state is left unchanged when the event is not accepted.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`KeyEventFields::read`]; [`KelError::NotTransferable`];
    /// [`KelError::IdentifierMismatch`]; [`KelError::UnsupportedKind`] for an inception;
    /// [`KelError::UndelegatedRotation`] for a plain rotation of a delegated identifier, and
    /// [`KelError::DelegatorUnknown`] for its delegated rotation, whose delegator's log only a
    /// [`Kevery`](crate::Kevery) can consult;
    /// [`KelError::OutOfOrder`] or [`KelError::Stale`] when the
    /// event does not follow the latest one; [`KelError::PriorMismatch`];
    /// [`KelError::EstablishmentOnly`]; the establishment checks of [`Self::incept`] and, for a
    /// rotation, [`KelError::CutNotAWitness`] and [`KelError::ConflictingWitnessLists`];
    /// [`KelError::NoVerifiedSignatures`]; and, when waiting for more signatures could help,
    /// [`KelError::NotFullySigned`], [`KelError::PriorNextNotSatisfied`] or
    /// [`KelError::NotFullyWitnessed`].
    pub fn update(&mut self, message: &Message, first_seen_at: Timestamp) -> Result<(), KelError> {
        self.update_offered(&Offer::of(message, first_seen_at), &NoDelegators)
            .map(|_| ())
    }

    /// [`Self::update`] over an event and its attachments held apart, with delegators to consult,
    /// returning what verified, which is what a log stores.
    pub(crate) fn update_offered(
        &mut self,
        offer: &Offer<'_>,
        delegations: &dyn Delegations,
    ) -> Result<Verified, KelError> {
        let event = KeyEventFields::read(offer.raw)?;
        if !self.is_transferable() {
            return Err(KelError::NotTransferable);
        }
        if event.identifier() != &self.identifier {
            return Err(KelError::IdentifierMismatch);
        }
        match event.kind() {
            EventKind::Rotation if self.delegator.is_some() => Err(KelError::UndelegatedRotation),
            EventKind::Rotation | EventKind::DelegatedRotation => self.rotate(offer, &event, delegations),
            EventKind::Interaction => self.interact(offer, &event),
            other => Err(KelError::UnsupportedKind { kind: other.as_str() }),
        }
    }

    fn rotate(
        &mut self,
        offer: &Offer<'_>,
        event: &KeyEventFields,
        delegations: &dyn Delegations,
    ) -> Result<Verified, KelError> {
        let raw = offer.raw;
        let rotation = self.validate_rotation(event)?;

        let (indices, signatures) = verified(offer.signatures, event.keys(), raw.raw());
        if indices.is_empty() {
            return Err(KelError::NoVerifiedSignatures);
        }
        if !rotation
            .signing_threshold
            .is_satisfied_by(&indices)
            .map_err(KelError::threshold)?
        {
            return Err(KelError::NotFullySigned);
        }
        let exposed = self.exposed_indices(offer.signatures, event.keys(), raw.raw());
        if !self
            .next_threshold
            .is_satisfied_by(&exposed)
            .map_err(KelError::threshold)?
        {
            return Err(KelError::PriorNextNotSatisfied);
        }
        let witness_signatures = check_witnessed(
            raw,
            offer.witness_signatures,
            &rotation.witnesses,
            rotation.witness_threshold,
        )?;
        // keripy validates a delegation only for an identifier with a delegator, so a delegated
        // rotation of an undelegated identifier is accepted as an ordinary one.
        let delegation = match &self.delegator {
            Some(delegator) => Some(delegations.approve(delegator, event, offer.source)?),
            None => None,
        };

        self.sequence_number = event.sequence_number();
        self.prior = event.prior();
        self.said = event.said();
        self.latest_kind = event.kind();
        self.keys = event.keys().to_vec();
        self.signing_threshold = rotation.signing_threshold;
        self.next_digests = event.next_digests().to_vec();
        self.next_threshold = next_threshold(event)?;
        self.witnesses = rotation.witnesses;
        self.witness_threshold = rotation.witness_threshold;
        self.cuts = rotation.cuts;
        self.adds = rotation.adds;
        self.last_establishment = (event.sequence_number(), event.said());
        self.since_establishment = vec![event.said()];
        self.establishment_prior = event.prior();
        self.first_seen = self.first_seen.saturating_add(1);
        self.first_seen_at = offer.first_seen_at.clone();
        Ok(Verified {
            signatures,
            witness_signatures,
            delegation,
        })
    }

    /// keripy's `rotate` and `deriveBacks`: ordering, prior digest and witness changes.
    fn validate_rotation(&self, event: &KeyEventFields) -> Result<Rotation, KelError> {
        let next = self.sequence_number.saturating_add(1);
        let found = event.sequence_number();
        if found > next {
            return Err(KelError::OutOfOrder { expected: next, found });
        }
        let recovery = found < next;
        if recovery {
            // A delegated rotation may also supersede the latest establishment event itself.
            let stale = if event.kind() == EventKind::DelegatedRotation {
                found < self.last_establishment.0
            } else {
                found <= self.last_establishment.0
            };
            if stale {
                return Err(KelError::Stale { expected: next, found });
            }
        }
        // A recovery rotation follows the event before the one it supersedes: the latest
        // establishment event's prior when it supersedes that event, otherwise that event or an
        // interaction accepted since.
        let prior = if !recovery {
            Some(self.said)
        } else if found == self.last_establishment.0 {
            self.establishment_prior
        } else {
            usize::try_from(found - 1 - self.last_establishment.0)
                .ok()
                .and_then(|position| self.since_establishment.get(position))
                .copied()
        };
        if event.prior() != prior {
            return Err(KelError::PriorMismatch);
        }
        if self.next_digests.is_empty() {
            return Err(KelError::NotTransferable);
        }
        let signing_threshold = established_threshold(event)?;
        check_threshold_fits(&signing_threshold, event.keys().len())?;

        if recovery {
            // keripy's `deriveBacks` derives no witness changes for a rotation at or below the
            // latest sequence number: the witnesses, and the latest changes to them, stay as they
            // are, whatever the rotation lists.
            check_witness_threshold(event.witness_threshold(), self.witnesses.len())?;
            return Ok(Rotation {
                signing_threshold,
                witness_threshold: event.witness_threshold(),
                witnesses: self.witnesses.clone(),
                cuts: self.cuts.clone(),
                adds: self.adds.clone(),
            });
        }
        check_distinct(event.cuts(), "br")?;
        if event.cuts().iter().any(|cut| !self.witnesses.contains(cut)) {
            return Err(KelError::CutNotAWitness);
        }
        check_distinct(event.adds(), "ba")?;
        if event.adds().iter().any(|add| event.cuts().contains(add)) {
            return Err(KelError::ConflictingWitnessLists {
                first: "br",
                second: "ba",
            });
        }
        if event.adds().iter().any(|add| self.witnesses.contains(add)) {
            return Err(KelError::ConflictingWitnessLists {
                first: "b",
                second: "ba",
            });
        }
        // keripy's ordered-set arithmetic: the current witnesses less the cuts, then the adds.
        let witnesses: Vec<IdentifierPrefix> = self
            .witnesses
            .iter()
            .filter(|witness| !event.cuts().contains(witness))
            .chain(event.adds())
            .cloned()
            .collect();
        check_witness_threshold(event.witness_threshold(), witnesses.len())?;
        Ok(Rotation {
            signing_threshold,
            witness_threshold: event.witness_threshold(),
            witnesses,
            cuts: event.cuts().to_vec(),
            adds: event.adds().to_vec(),
        })
    }

    fn interact(&mut self, offer: &Offer<'_>, event: &KeyEventFields) -> Result<Verified, KelError> {
        let raw = offer.raw;
        if self.establishment_only {
            return Err(KelError::EstablishmentOnly);
        }
        let next = self.sequence_number.saturating_add(1);
        if event.sequence_number() != next {
            // keripy refuses an interaction out of sequence without distinguishing the direction.
            return Err(if event.sequence_number() > next {
                KelError::OutOfOrder {
                    expected: next,
                    found: event.sequence_number(),
                }
            } else {
                KelError::Stale {
                    expected: next,
                    found: event.sequence_number(),
                }
            });
        }
        if event.prior() != Some(self.said) {
            return Err(KelError::PriorMismatch);
        }
        check_threshold_fits(&self.signing_threshold, self.keys.len())?;
        let (indices, signatures) = verified(offer.signatures, &self.keys, raw.raw());
        if indices.is_empty() {
            return Err(KelError::NoVerifiedSignatures);
        }
        if !self
            .signing_threshold
            .is_satisfied_by(&indices)
            .map_err(KelError::threshold)?
        {
            return Err(KelError::NotFullySigned);
        }
        let witness_signatures =
            check_witnessed(raw, offer.witness_signatures, &self.witnesses, self.witness_threshold)?;

        self.sequence_number = event.sequence_number();
        self.prior = event.prior();
        self.said = event.said();
        self.latest_kind = EventKind::Interaction;
        self.since_establishment.push(event.said());
        self.first_seen = self.first_seen.saturating_add(1);
        self.first_seen_at = offer.first_seen_at.clone();
        Ok(Verified {
            signatures,
            witness_signatures,
            delegation: None,
        })
    }

    /// keripy's `exposeds`: the prior next-key positions whose committed digest matches the key a
    /// verified signature was made with, read from each signature's other index.
    fn exposed_indices(&self, signatures: &[IndexedSignature], keys: &[VerificationKey], message: &[u8]) -> Vec<usize> {
        let mut exposed = Vec::new();
        for signature in unique(signatures) {
            let (Ok(index), Some(Ok(other))) = (
                usize::try_from(signature.index()),
                signature.other_index().map(usize::try_from),
            ) else {
                continue;
            };
            let (Some(key), Some(digest)) = (keys.get(index), self.next_digests.get(other)) else {
                continue;
            };
            if key.verify(signature.raw(), message).is_err() {
                continue;
            }
            if key.qb64_bytes().is_ok_and(|bytes| digest.verify(&bytes)) {
                exposed.push(other);
            }
        }
        exposed
    }

    /// Returns whether the identifier can take further events: a transferable prefix with a
    /// non-empty next-key commitment.
    #[must_use]
    pub fn is_transferable(&self) -> bool {
        self.identifier.is_transferable() && !self.next_digests.is_empty()
    }

    /// Returns the identifier.
    #[must_use]
    pub const fn identifier(&self) -> &IdentifierPrefix {
        &self.identifier
    }

    /// Returns the latest accepted event's sequence number.
    #[must_use]
    pub const fn sequence_number(&self) -> u128 {
        self.sequence_number
    }

    /// Returns the latest accepted event's SAID.
    #[must_use]
    pub const fn said(&self) -> Said {
        self.said
    }

    /// Returns the first-seen ordinal of the latest accepted event: how many events of this
    /// identifier were accepted before it, superseded ones included, keripy's `fn`.
    #[must_use]
    pub const fn first_seen(&self) -> u128 {
        self.first_seen
    }

    /// Returns the latest accepted event's kind.
    pub(crate) const fn latest_kind(&self) -> EventKind {
        self.latest_kind
    }

    /// Returns the sequence number of the latest establishment event.
    pub(crate) const fn last_establishment_sequence(&self) -> u128 {
        self.last_establishment.0
    }

    /// Returns the keys in force.
    #[must_use]
    pub fn keys(&self) -> &[VerificationKey] {
        &self.keys
    }

    /// Returns the witnesses in force.
    #[must_use]
    pub fn witnesses(&self) -> &[IdentifierPrefix] {
        &self.witnesses
    }

    /// Returns the witness threshold in force.
    #[must_use]
    pub const fn witness_threshold(&self) -> u32 {
        self.witness_threshold
    }

    /// Returns the delegator, for a delegated identifier.
    #[must_use]
    pub const fn delegator(&self) -> Option<&IdentifierPrefix> {
        self.delegator.as_ref()
    }

    /// Returns whether the inception configured do-not-delegate (`DND`).
    #[must_use]
    pub const fn do_not_delegate(&self) -> bool {
        self.do_not_delegate
    }

    /// Writes the state as the key state record a `ksn` reply carries.
    ///
    /// # Errors
    ///
    /// Returns [`KelError::Event`] if the state cannot form a valid record, which a state built
    /// by this type cannot reach.
    pub fn state(&self) -> Result<KeyStateRecord, KelError> {
        let mut configuration = Vec::new();
        if self.establishment_only {
            configuration.push(ConfigurationTrait::EstablishmentOnly);
        }
        if self.do_not_delegate {
            configuration.push(ConfigurationTrait::DoNotDelegate);
        }
        let establishment = LatestEstablishment::new(self.last_establishment.0, self.last_establishment.1)
            .removed(self.cuts.clone())
            .added(self.adds.clone());
        let mut builder = KeyStateBuilder::new(
            self.identifier.clone(),
            self.sequence_number,
            self.said,
            self.latest_kind,
            self.first_seen_at.clone(),
            self.keys.clone(),
            establishment,
        )
        .first_seen(self.first_seen)
        .signing_threshold(self.signing_threshold.clone())
        .next_digests(self.next_digests.clone())
        .next_threshold(self.next_threshold.clone())
        .witnesses(self.witnesses.clone())
        .witness_threshold(self.witness_threshold)
        .configuration(configuration);
        if let Some(prior) = self.prior {
            builder = builder.prior(prior);
        }
        if let Some(delegator) = &self.delegator {
            builder = builder.delegator(delegator.clone());
        }
        builder.build().map_err(KelError::event)
    }
}

fn established_threshold(event: &KeyEventFields) -> Result<SigningThreshold, KelError> {
    event
        .signing_threshold()
        .cloned()
        .ok_or(KelError::UnexpectedFieldShape { label: "kt" })
}

fn next_threshold(event: &KeyEventFields) -> Result<SigningThreshold, KelError> {
    event
        .next_threshold()
        .cloned()
        .ok_or(KelError::UnexpectedFieldShape { label: "nt" })
}

fn check_threshold_fits(threshold: &SigningThreshold, keys: usize) -> Result<(), KelError> {
    let available = u128::try_from(keys).unwrap_or(u128::MAX);
    if threshold.size() > available {
        return Err(KelError::ThresholdExceedsKeys {
            required: threshold.size(),
            keys,
        });
    }
    Ok(())
}

fn check_distinct(prefixes: &[IdentifierPrefix], label: &'static str) -> Result<(), KelError> {
    for (position, prefix) in prefixes.iter().enumerate() {
        if prefixes.iter().take(position).any(|earlier| earlier == prefix) {
            return Err(KelError::DuplicateWitness { label });
        }
    }
    Ok(())
}

fn check_witness_threshold(threshold: u32, witnesses: usize) -> Result<(), KelError> {
    let count = u32::try_from(witnesses).unwrap_or(u32::MAX);
    let fits = if count == 0 {
        threshold == 0
    } else {
        (1..=count).contains(&threshold)
    };
    if fits {
        Ok(())
    } else {
        Err(KelError::InvalidWitnessThreshold { threshold, witnesses })
    }
}

/// Verifies witness signatures against `witnesses`, requires `threshold` of them, and returns the
/// ones that verified.
fn check_witnessed(
    raw: &SerializedEvent,
    offered: &[IndexedSignature],
    witnesses: &[IdentifierPrefix],
    threshold: u32,
) -> Result<Vec<IndexedSignature>, KelError> {
    if witnesses.is_empty() {
        return Ok(Vec::new());
    }
    let (indices, verified) = verified(offered, &witness_keys(witnesses), raw.raw());
    if u32::try_from(indices.len()).unwrap_or(u32::MAX) < threshold {
        return Err(KelError::NotFullyWitnessed);
    }
    Ok(verified)
}

/// The witnesses' keys; [`KeyEventFields::read`] admits only basic witness prefixes.
pub(crate) fn witness_keys(witnesses: &[IdentifierPrefix]) -> Vec<VerificationKey> {
    witnesses
        .iter()
        .filter_map(|witness| match witness {
            IdentifierPrefix::Basic(basic) => Some(basic.key().clone()),
            IdentifierPrefix::SelfAddressing(_) => None,
        })
        .collect()
}

/// keripy's `verifySigs`: drops repeated signatures, then keeps every signature that verifies
/// against the key at its index, with that index. keripy raises `IndexError` for an index past
/// the end; it is skipped here.
pub(crate) fn verified(
    signatures: &[IndexedSignature],
    keys: &[VerificationKey],
    message: &[u8],
) -> (Vec<usize>, Vec<IndexedSignature>) {
    unique(signatures)
        .filter_map(|signature| {
            let index = usize::try_from(signature.index()).ok()?;
            let key = keys.get(index)?;
            key.verify(signature.raw(), message)
                .is_ok()
                .then(|| (index, signature.clone()))
        })
        .unzip()
}

fn unique(signatures: &[IndexedSignature]) -> impl Iterator<Item = &IndexedSignature> {
    signatures
        .iter()
        .enumerate()
        .filter(|(position, signature)| !signatures.iter().take(*position).any(|earlier| earlier == *signature))
        .map(|(_, signature)| signature)
}
