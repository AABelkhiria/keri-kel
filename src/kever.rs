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
//! - its witness signatures, verified against the witness list in force, meet the witness
//!   threshold.
//!
//! This ports keripy's `Kever.incept`, `update`, `rotate`, `deriveBacks`, `valSigsWigsDel` and
//! `exposeds` (`src/keri/core/eventing.py`) for undelegated identifiers whose events carry their
//! witness signatures. The order of the checks, and therefore which error a doubly-bad event gets,
//! follows keripy's.

use keri_cesr::crypto::digest::Digest;
use keri_cesr::crypto::signature::IndexedSignature;
use keri_cesr::crypto::verifier::VerificationKey;
use keri_protocol::event::config::ConfigurationTrait;
use keri_protocol::event::key_state::{KeyStateBuilder, KeyStateRecord, LatestEstablishment};
use keri_protocol::event::kind::EventKind;
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;
use keri_protocol::stream::Message;
use keri_protocol::threshold::SigningThreshold;

use crate::error::KelError;
use crate::event::KeyEventFields;

/// One identifier's key state at its latest accepted event, keripy's `Kever`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Kever {
    identifier: IdentifierPrefix,
    sequence_number: u128,
    said: Said,
    prior: Option<Said>,
    latest_kind: EventKind,
    keys: Vec<VerificationKey>,
    signing_threshold: SigningThreshold,
    next_digests: Vec<Digest>,
    next_threshold: SigningThreshold,
    witnesses: Vec<IdentifierPrefix>,
    witness_threshold: u32,
    cuts: Vec<IdentifierPrefix>,
    adds: Vec<IdentifierPrefix>,
    last_establishment: (u128, Said),
    establishment_only: bool,
    do_not_delegate: bool,
    first_seen: u128,
    first_seen_at: Timestamp,
}

/// The establishment fields a validated rotation would put in force.
struct Rotation {
    signing_threshold: SigningThreshold,
    witness_threshold: u32,
    witnesses: Vec<IdentifierPrefix>,
}

impl Kever {
    /// Starts a log from a signed inception, first seen at `first_seen_at`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`KeyEventFields::read`]; [`KelError::UnsupportedKind`] for anything
    /// but an inception; [`KelError::NonZeroInception`]; [`KelError::ThresholdExceedsKeys`];
    /// [`KelError::NonTransferableInception`]; [`KelError::DuplicateWitness`] and
    /// [`KelError::InvalidWitnessThreshold`]; [`KelError::NoVerifiedSignatures`]; and, when waiting
    /// for more signatures could help, [`KelError::NotFullySigned`] or
    /// [`KelError::NotFullyWitnessed`].
    pub fn incept(message: &Message, first_seen_at: Timestamp) -> Result<Self, KelError> {
        let event = KeyEventFields::read(message.event())?;
        if event.kind() != EventKind::Inception {
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

        let signatures = message.attachments().controller_signatures();
        let indices = verified_indices(signatures, event.keys(), message.event().raw());
        if indices.is_empty() {
            return Err(KelError::NoVerifiedSignatures);
        }
        if !signing_threshold
            .is_satisfied_by(&indices)
            .map_err(KelError::threshold)?
        {
            return Err(KelError::NotFullySigned);
        }
        check_witnessed(message, event.witnesses(), event.witness_threshold())?;

        Ok(Self {
            identifier: event.identifier().clone(),
            sequence_number: 0,
            said: event.said(),
            prior: None,
            latest_kind: EventKind::Inception,
            keys: event.keys().to_vec(),
            signing_threshold,
            next_digests: event.next_digests().to_vec(),
            next_threshold: next_threshold(&event)?,
            witnesses: event.witnesses().to_vec(),
            witness_threshold: event.witness_threshold(),
            cuts: Vec::new(),
            adds: Vec::new(),
            last_establishment: (0, event.said()),
            establishment_only: event.establishment_only(),
            do_not_delegate: event.do_not_delegate(),
            first_seen: 0,
            first_seen_at,
        })
    }

    /// Extends the log with a signed rotation or interaction, first seen at `first_seen_at`.
    ///
    /// The state is left unchanged when the event is not accepted.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`KeyEventFields::read`]; [`KelError::NotTransferable`];
    /// [`KelError::IdentifierMismatch`]; [`KelError::UnsupportedKind`] for an inception;
    /// [`KelError::OutOfOrder`], [`KelError::Stale`] or [`KelError::RecoveryUnsupported`] when the
    /// event does not follow the latest one; [`KelError::PriorMismatch`];
    /// [`KelError::EstablishmentOnly`]; the establishment checks of [`Self::incept`] and, for a
    /// rotation, [`KelError::CutNotAWitness`] and [`KelError::ConflictingWitnessLists`];
    /// [`KelError::NoVerifiedSignatures`]; and, when waiting for more signatures could help,
    /// [`KelError::NotFullySigned`], [`KelError::PriorNextNotSatisfied`] or
    /// [`KelError::NotFullyWitnessed`].
    pub fn update(&mut self, message: &Message, first_seen_at: Timestamp) -> Result<(), KelError> {
        let event = KeyEventFields::read(message.event())?;
        if !self.is_transferable() {
            return Err(KelError::NotTransferable);
        }
        if event.identifier() != &self.identifier {
            return Err(KelError::IdentifierMismatch);
        }
        match event.kind() {
            EventKind::Rotation => self.rotate(message, &event, first_seen_at),
            EventKind::Interaction => self.interact(message, &event, first_seen_at),
            other => Err(KelError::UnsupportedKind { kind: other.as_str() }),
        }
    }

    fn rotate(&mut self, message: &Message, event: &KeyEventFields, first_seen_at: Timestamp) -> Result<(), KelError> {
        let rotation = self.validate_rotation(event)?;

        let signatures = message.attachments().controller_signatures();
        let indices = verified_indices(signatures, event.keys(), message.event().raw());
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
        let exposed = self.exposed_indices(signatures, event.keys(), message.event().raw());
        if !self
            .next_threshold
            .is_satisfied_by(&exposed)
            .map_err(KelError::threshold)?
        {
            return Err(KelError::PriorNextNotSatisfied);
        }
        check_witnessed(message, &rotation.witnesses, rotation.witness_threshold)?;

        self.sequence_number = event.sequence_number();
        self.prior = event.prior();
        self.said = event.said();
        self.latest_kind = EventKind::Rotation;
        self.keys = event.keys().to_vec();
        self.signing_threshold = rotation.signing_threshold;
        self.next_digests = event.next_digests().to_vec();
        self.next_threshold = next_threshold(event)?;
        self.witnesses = rotation.witnesses;
        self.witness_threshold = rotation.witness_threshold;
        self.cuts = event.cuts().to_vec();
        self.adds = event.adds().to_vec();
        self.last_establishment = (event.sequence_number(), event.said());
        self.first_seen = self.first_seen.saturating_add(1);
        self.first_seen_at = first_seen_at;
        Ok(())
    }

    /// keripy's `rotate` and `deriveBacks`: ordering, prior digest and witness changes.
    fn validate_rotation(&self, event: &KeyEventFields) -> Result<Rotation, KelError> {
        let next = self.sequence_number.saturating_add(1);
        let found = event.sequence_number();
        if found > next {
            return Err(KelError::OutOfOrder { expected: next, found });
        }
        if found < next {
            if found <= self.last_establishment.0 {
                return Err(KelError::Stale { expected: next, found });
            }
            // keripy accepts a rotation here when it replaces an interaction: a recovery.
            return Err(KelError::RecoveryUnsupported);
        }
        if event.prior() != Some(self.said) {
            return Err(KelError::PriorMismatch);
        }
        if self.next_digests.is_empty() {
            return Err(KelError::NotTransferable);
        }
        let signing_threshold = established_threshold(event)?;
        check_threshold_fits(&signing_threshold, event.keys().len())?;

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
        })
    }

    fn interact(
        &mut self,
        message: &Message,
        event: &KeyEventFields,
        first_seen_at: Timestamp,
    ) -> Result<(), KelError> {
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
        let signatures = message.attachments().controller_signatures();
        let indices = verified_indices(signatures, &self.keys, message.event().raw());
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
        check_witnessed(message, &self.witnesses, self.witness_threshold)?;

        self.sequence_number = event.sequence_number();
        self.prior = event.prior();
        self.said = event.said();
        self.latest_kind = EventKind::Interaction;
        self.first_seen = self.first_seen.saturating_add(1);
        self.first_seen_at = first_seen_at;
        Ok(())
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

/// Verifies the attached witness signatures against `witnesses` and requires `threshold` of them.
fn check_witnessed(message: &Message, witnesses: &[IdentifierPrefix], threshold: u32) -> Result<(), KelError> {
    if witnesses.is_empty() {
        return Ok(());
    }
    let keys: Vec<VerificationKey> = witnesses
        .iter()
        .filter_map(|witness| match witness {
            IdentifierPrefix::Basic(basic) => Some(basic.key().clone()),
            IdentifierPrefix::SelfAddressing(_) => None,
        })
        .collect();
    let indices = verified_indices(message.attachments().witness_signatures(), &keys, message.event().raw());
    if u32::try_from(indices.len()).unwrap_or(u32::MAX) < threshold {
        return Err(KelError::NotFullyWitnessed);
    }
    Ok(())
}

/// keripy's `verifySigs`: drops repeated signatures, then keeps the index of every signature that
/// verifies against the key at its index. keripy raises `IndexError` for an index past the end; it
/// is skipped here.
fn verified_indices(signatures: &[IndexedSignature], keys: &[VerificationKey], message: &[u8]) -> Vec<usize> {
    unique(signatures)
        .filter_map(|signature| {
            let index = usize::try_from(signature.index()).ok()?;
            let key = keys.get(index)?;
            key.verify(signature.raw(), message).is_ok().then_some(index)
        })
        .collect()
}

fn unique(signatures: &[IndexedSignature]) -> impl Iterator<Item = &IndexedSignature> {
    signatures
        .iter()
        .enumerate()
        .filter(|(position, signature)| !signatures.iter().take(*position).any(|earlier| earlier == *signature))
        .map(|(_, signature)| signature)
}
