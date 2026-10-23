//! Key events read off the wire.
//!
//! [`KeyEventFields::read`] takes a parsed message and returns the fields a validator needs, after
//! checking what the event commits to on its own: its SAID always, and for an inception, delegated
//! or not, the derivation of its identifier prefix, which for a self-addressing prefix is the SAID
//! itself. keripy makes the same two checks when it deserializes an event, before any key state is
//! consulted.

use keri_cesr::crypto::digest::Digest;
use keri_cesr::crypto::verifier::VerificationKey;
use keri_cesr::number::CesrNumber;
use keri_protocol::event::config::ConfigurationTrait;
use keri_protocol::event::kind::EventKind;
use keri_protocol::prefix::{IdentifierPrefix, PrefixVerification};
use keri_protocol::said::{DEFAULT_SAID_LABEL, Said, SaidVerification};
use keri_protocol::serialization::{Sad, SadValue, SerializedEvent};
use keri_protocol::threshold::SigningThreshold;
use serde_json::Value;

use crate::error::KelError;

/// The fields of one key event a validator reads.
///
/// An interaction carries only the identity, sequence and prior fields; the establishment fields
/// are empty for it. A rotation's witnesses are its cuts and adds; an inception's are its full list.
/// A delegated inception (`dip`) reads like an inception and names its delegator; a delegated
/// rotation (`drt`) reads like a rotation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyEventFields {
    kind: EventKind,
    identifier: IdentifierPrefix,
    sequence_number: u128,
    said: Said,
    prior: Option<Said>,
    keys: Vec<VerificationKey>,
    signing_threshold: Option<SigningThreshold>,
    next_digests: Vec<Digest>,
    next_threshold: Option<SigningThreshold>,
    witness_threshold: u32,
    witnesses: Vec<IdentifierPrefix>,
    cuts: Vec<IdentifierPrefix>,
    adds: Vec<IdentifierPrefix>,
    establishment_only: bool,
    do_not_delegate: bool,
    delegator: Option<IdentifierPrefix>,
    anchors: usize,
    event_seals: Vec<EventSeal>,
}

/// An event seal anchored in an event's data: an identifier, a sequence number as lowercase
/// hexadecimal text, and an event SAID, keripy's `SealEvent`.
///
/// A delegator approves a delegated event by anchoring a seal of it. keripy recognises a seal only
/// when its fields are exactly `i`, `s` and `d`, in that order, and compares their text, so the
/// text is kept as written.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventSeal {
    identifier: String,
    sequence_number: String,
    said: String,
}

impl EventSeal {
    /// Returns whether this seal names `event`: its identifier, its sequence number written as
    /// keripy writes it, and its SAID.
    #[must_use]
    pub fn names(&self, event: &KeyEventFields) -> bool {
        event.identifier().qb64().is_ok_and(|identifier| {
            event
                .said()
                .qb64()
                .is_ok_and(|said| self.names_parts(&identifier, event.sequence_number(), &said))
        })
    }

    /// Returns whether this seal names the event with this identifier, sequence number and SAID,
    /// each as qb64 text.
    #[must_use]
    pub fn names_parts(&self, identifier: &str, sequence_number: u128, said: &str) -> bool {
        identifier == self.identifier && format!("{sequence_number:x}") == self.sequence_number && said == self.said
    }
}

impl KeyEventFields {
    /// Reads a key event, verifying its SAID and, for an inception, its prefix derivation.
    ///
    /// # Errors
    ///
    /// Returns [`KelError::UnsupportedKind`] for a message that is not `icp`, `dip`, `rot`, `drt`
    /// or `ixn`, [`KelError::UnexpectedFieldShape`] for a missing or misshapen field, including a
    /// delegated inception's empty delegator, and layered SAID, prefix, threshold, key or CESR
    /// failures.
    pub fn read(event: &SerializedEvent) -> Result<Self, KelError> {
        let kind = event
            .event_kind()
            .map_err(KelError::serialization)?
            .ok_or(KelError::UnexpectedFieldShape { label: "t" })?;
        match kind {
            EventKind::Inception
            | EventKind::DelegatedInception
            | EventKind::Rotation
            | EventKind::DelegatedRotation
            | EventKind::Interaction => {}
            other => return Err(KelError::UnsupportedKind { kind: other.as_str() }),
        }
        let inceptive = matches!(kind, EventKind::Inception | EventKind::DelegatedInception);

        let map = event.sad();
        let said = Said::from_qb64(event.said().ok_or(KelError::UnexpectedFieldShape { label: "d" })?)
            .map_err(KelError::said)?;
        let identifier = IdentifierPrefix::from_qb64(
            event
                .identifier_prefix()
                .ok_or(KelError::UnexpectedFieldShape { label: "i" })?,
        )
        .map_err(KelError::prefix)?;
        verify_commitments(&identifier, said, map, inceptive)?;
        let sequence_number = event
            .sequence_number()
            .map_err(KelError::serialization)?
            .ok_or(KelError::UnexpectedFieldShape { label: "s" })?
            .value();
        let prior = match map.get_text("p") {
            Some(text) => Some(Said::from_qb64(text).map_err(KelError::said)?),
            None if inceptive => None,
            None => return Err(KelError::UnexpectedFieldShape { label: "p" }),
        };
        let anchored = map.get("a").and_then(SadValue::as_array).unwrap_or_default();
        let delegator = if kind == EventKind::DelegatedInception {
            Some(delegator(map)?)
        } else {
            None
        };

        let mut fields = Self {
            kind,
            identifier,
            sequence_number,
            said,
            prior,
            keys: Vec::new(),
            signing_threshold: None,
            next_digests: Vec::new(),
            next_threshold: None,
            witness_threshold: 0,
            witnesses: Vec::new(),
            cuts: Vec::new(),
            adds: Vec::new(),
            establishment_only: false,
            do_not_delegate: false,
            delegator,
            anchors: anchored.len(),
            event_seals: anchored.iter().filter_map(event_seal).collect(),
        };
        if kind == EventKind::Interaction {
            return Ok(fields);
        }

        fields.keys = event.verification_keys().map_err(KelError::serialization)?;
        fields.signing_threshold = Some(threshold(map.get("kt"), "kt")?);
        fields.next_digests = event.next_key_digests().map_err(KelError::serialization)?;
        fields.next_threshold = Some(threshold(map.get("nt"), "nt")?);
        fields.witness_threshold = witness_threshold(map.get("bt"))?;
        if inceptive {
            fields.witnesses = prefixes(map.get("b"), "b")?;
            for entry in texts(map.get("c"), "c")? {
                match entry.parse::<ConfigurationTrait>() {
                    Ok(ConfigurationTrait::EstablishmentOnly) => fields.establishment_only = true,
                    Ok(ConfigurationTrait::DoNotDelegate) => fields.do_not_delegate = true,
                    // keripy keeps only these two traits in key state and ignores the rest.
                    Ok(_) | Err(_) => {}
                }
            }
        } else {
            fields.cuts = prefixes(map.get("br"), "br")?;
            fields.adds = prefixes(map.get("ba"), "ba")?;
        }
        Ok(fields)
    }

    /// Returns the event kind.
    #[must_use]
    pub const fn kind(&self) -> EventKind {
        self.kind
    }

    /// Returns the identifier the event belongs to.
    #[must_use]
    pub const fn identifier(&self) -> &IdentifierPrefix {
        &self.identifier
    }

    /// Returns the event's sequence number.
    #[must_use]
    pub const fn sequence_number(&self) -> u128 {
        self.sequence_number
    }

    /// Returns the event's SAID.
    #[must_use]
    pub const fn said(&self) -> Said {
        self.said
    }

    /// Returns the prior event's SAID; `None` for an inception.
    #[must_use]
    pub const fn prior(&self) -> Option<Said> {
        self.prior
    }

    /// Returns the signing keys an establishment event lists.
    #[must_use]
    pub fn keys(&self) -> &[VerificationKey] {
        &self.keys
    }

    /// Returns the signing threshold an establishment event sets.
    #[must_use]
    pub const fn signing_threshold(&self) -> Option<&SigningThreshold> {
        self.signing_threshold.as_ref()
    }

    /// Returns the next-key digests an establishment event commits to.
    #[must_use]
    pub fn next_digests(&self) -> &[Digest] {
        &self.next_digests
    }

    /// Returns the next-key threshold an establishment event commits to.
    #[must_use]
    pub const fn next_threshold(&self) -> Option<&SigningThreshold> {
        self.next_threshold.as_ref()
    }

    /// Returns the witness threshold an establishment event sets.
    #[must_use]
    pub const fn witness_threshold(&self) -> u32 {
        self.witness_threshold
    }

    /// Returns an inception's witnesses.
    #[must_use]
    pub fn witnesses(&self) -> &[IdentifierPrefix] {
        &self.witnesses
    }

    /// Returns the witnesses a rotation removes.
    #[must_use]
    pub fn cuts(&self) -> &[IdentifierPrefix] {
        &self.cuts
    }

    /// Returns the witnesses a rotation adds.
    #[must_use]
    pub fn adds(&self) -> &[IdentifierPrefix] {
        &self.adds
    }

    /// Returns whether an inception configures establishment events only (`EO`).
    #[must_use]
    pub const fn establishment_only(&self) -> bool {
        self.establishment_only
    }

    /// Returns whether an inception forbids delegation (`DND`).
    #[must_use]
    pub const fn do_not_delegate(&self) -> bool {
        self.do_not_delegate
    }

    /// Returns a delegated inception's delegator; `None` for every other event, since a delegated
    /// rotation's delegator is the one in the key state.
    #[must_use]
    pub const fn delegator(&self) -> Option<&IdentifierPrefix> {
        self.delegator.as_ref()
    }

    /// Returns how many anchors the event carries.
    #[must_use]
    pub const fn anchors(&self) -> usize {
        self.anchors
    }

    /// Returns the event seals among the anchors, in order.
    #[must_use]
    pub fn event_seals(&self) -> &[EventSeal] {
        &self.event_seals
    }

    /// Returns whether the event is an inception, delegated or not.
    #[must_use]
    pub const fn is_inception(&self) -> bool {
        matches!(self.kind, EventKind::Inception | EventKind::DelegatedInception)
    }

    /// Returns whether the event is a rotation, delegated or not.
    #[must_use]
    pub const fn is_rotation(&self) -> bool {
        matches!(self.kind, EventKind::Rotation | EventKind::DelegatedRotation)
    }
}

/// Verifies what an event commits to on its own: its SAID, and for an inception its prefix.
fn verify_commitments(identifier: &IdentifierPrefix, said: Said, map: &Sad, inceptive: bool) -> Result<(), KelError> {
    match (identifier, inceptive) {
        // A self-addressing inception computes one digest with both `d` and `i` blanked, and
        // writes it to both: deriving the prefix verifies the SAID too.
        (IdentifierPrefix::SelfAddressing(prefix), true) => {
            identifier
                .verify(map, PrefixVerification::Strict)
                .map_err(KelError::prefix)?;
            if *prefix != said {
                return Err(KelError::SaidNotPrefix);
            }
        }
        (IdentifierPrefix::Basic(_), true) => {
            identifier
                .verify(map, PrefixVerification::Strict)
                .map_err(KelError::prefix)?;
            said.verify(map, DEFAULT_SAID_LABEL, SaidVerification::strict())
                .map_err(KelError::said)?;
        }
        _ => said
            .verify(map, DEFAULT_SAID_LABEL, SaidVerification::strict())
            .map_err(KelError::said)?,
    }
    Ok(())
}

/// Reads a delegated inception's delegator, which must be present and not empty.
fn delegator(map: &Sad) -> Result<IdentifierPrefix, KelError> {
    let label = "di";
    match map.get_text(label) {
        Some(text) if !text.is_empty() => IdentifierPrefix::from_qb64(text).map_err(KelError::prefix),
        _ => Err(KelError::UnexpectedFieldShape { label }),
    }
}

/// Reads an anchor as an event seal when its fields are exactly `i`, `s` and `d`, in order, each
/// text.
fn event_seal(anchor: &SadValue) -> Option<EventSeal> {
    let mut entries = anchor.as_map()?.entries();
    let mut field = |label: &str| match entries.next() {
        Some((found, SadValue::Text(text))) if found == label => Some(text.clone()),
        _ => None,
    };
    let seal = EventSeal {
        identifier: field("i")?,
        sequence_number: field("s")?,
        said: field("d")?,
    };
    entries.next().is_none().then_some(seal)
}

/// Reads a threshold written as hexadecimal text, weight arrays, or a JSON number; key events may
/// carry any of the three.
fn threshold(value: Option<&SadValue>, label: &'static str) -> Result<SigningThreshold, KelError> {
    match value.ok_or(KelError::UnexpectedFieldShape { label })? {
        SadValue::Integer(number) => {
            let number = u128::try_from(*number).map_err(|_| KelError::UnexpectedFieldShape { label })?;
            Ok(SigningThreshold::numeric(number))
        }
        other => {
            let json = threshold_json(other).ok_or(KelError::UnexpectedFieldShape { label })?;
            SigningThreshold::from_json(&json.to_string()).map_err(KelError::threshold)
        }
    }
}

fn threshold_json(value: &SadValue) -> Option<Value> {
    match value {
        SadValue::Text(text) => Some(Value::String(text.clone())),
        SadValue::Array(items) => items
            .iter()
            .map(threshold_json)
            .collect::<Option<Vec<_>>>()
            .map(Value::Array),
        _ => None,
    }
}

fn witness_threshold(value: Option<&SadValue>) -> Result<u32, KelError> {
    let label = "bt";
    let number = match value.ok_or(KelError::UnexpectedFieldShape { label })? {
        SadValue::Integer(number) => u128::try_from(*number).map_err(|_| KelError::UnexpectedFieldShape { label })?,
        SadValue::Text(text) => CesrNumber::from_hex(text).map_err(KelError::cesr)?.value(),
        _ => return Err(KelError::UnexpectedFieldShape { label }),
    };
    u32::try_from(number).map_err(|_| KelError::UnexpectedFieldShape { label })
}

fn texts<'a>(value: Option<&'a SadValue>, label: &'static str) -> Result<Vec<&'a str>, KelError> {
    value
        .and_then(SadValue::as_array)
        .ok_or(KelError::UnexpectedFieldShape { label })?
        .iter()
        .map(|item| item.as_text().ok_or(KelError::UnexpectedFieldShape { label }))
        .collect()
}

fn prefixes(value: Option<&SadValue>, label: &'static str) -> Result<Vec<IdentifierPrefix>, KelError> {
    texts(value, label)?
        .into_iter()
        .map(|text| IdentifierPrefix::from_qb64(text).map_err(KelError::prefix))
        .collect()
}
