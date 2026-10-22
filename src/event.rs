//! Key events read off the wire.
//!
//! [`KeyEventFields::read`] takes a parsed message and returns the fields a validator needs, after
//! checking what the event commits to on its own: its SAID always, and for an inception the
//! derivation of its identifier prefix, which for a self-addressing prefix is the SAID itself. keripy makes the same two checks when it deserializes an
//! event, before any key state is consulted.

use keri_cesr::crypto::digest::Digest;
use keri_cesr::crypto::verifier::VerificationKey;
use keri_cesr::number::CesrNumber;
use keri_protocol::event::config::ConfigurationTrait;
use keri_protocol::event::kind::EventKind;
use keri_protocol::prefix::{IdentifierPrefix, PrefixVerification};
use keri_protocol::said::{DEFAULT_SAID_LABEL, Said, SaidVerification};
use keri_protocol::serialization::{SadValue, SerializedEvent};
use keri_protocol::threshold::SigningThreshold;
use serde_json::Value;

use crate::error::KelError;

/// The fields of one key event a validator reads.
///
/// An interaction carries only the identity, sequence and prior fields; the establishment fields
/// are empty for it. A rotation's witnesses are its cuts and adds; an inception's are its full list.
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
    anchors: usize,
}

impl KeyEventFields {
    /// Reads a key event, verifying its SAID and, for an inception, its prefix derivation.
    ///
    /// # Errors
    ///
    /// Returns [`KelError::UnsupportedKind`] for a message that is not `icp`, `rot` or `ixn`,
    /// [`KelError::DelegationUnsupported`] for `dip` and `drt`, [`KelError::UnexpectedFieldShape`]
    /// for a missing or misshapen field, and layered SAID, prefix, threshold, key or CESR failures.
    pub fn read(event: &SerializedEvent) -> Result<Self, KelError> {
        let kind = event
            .event_kind()
            .map_err(KelError::serialization)?
            .ok_or(KelError::UnexpectedFieldShape { label: "t" })?;
        match kind {
            EventKind::Inception | EventKind::Rotation | EventKind::Interaction => {}
            EventKind::DelegatedInception | EventKind::DelegatedRotation => {
                return Err(KelError::DelegationUnsupported);
            }
            other => return Err(KelError::UnsupportedKind { kind: other.as_str() }),
        }

        let map = event.sad();
        let said = Said::from_qb64(event.said().ok_or(KelError::UnexpectedFieldShape { label: "d" })?)
            .map_err(KelError::said)?;
        let identifier = IdentifierPrefix::from_qb64(
            event
                .identifier_prefix()
                .ok_or(KelError::UnexpectedFieldShape { label: "i" })?,
        )
        .map_err(KelError::prefix)?;
        match (&identifier, kind) {
            // A self-addressing inception computes one digest with both `d` and `i` blanked, and
            // writes it to both: deriving the prefix verifies the SAID too.
            (IdentifierPrefix::SelfAddressing(prefix), EventKind::Inception) => {
                identifier
                    .verify(map, PrefixVerification::Strict)
                    .map_err(KelError::prefix)?;
                if *prefix != said {
                    return Err(KelError::SaidNotPrefix);
                }
            }
            (IdentifierPrefix::Basic(_), EventKind::Inception) => {
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
        let sequence_number = event
            .sequence_number()
            .map_err(KelError::serialization)?
            .ok_or(KelError::UnexpectedFieldShape { label: "s" })?
            .value();
        let prior = match map.get_text("p") {
            Some(text) => Some(Said::from_qb64(text).map_err(KelError::said)?),
            None if kind == EventKind::Inception => None,
            None => return Err(KelError::UnexpectedFieldShape { label: "p" }),
        };
        let anchors = map.get("a").and_then(SadValue::as_array).map_or(0, <[SadValue]>::len);

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
            anchors,
        };
        if kind == EventKind::Interaction {
            return Ok(fields);
        }

        fields.keys = event.verification_keys().map_err(KelError::serialization)?;
        fields.signing_threshold = Some(threshold(map.get("kt"), "kt")?);
        fields.next_digests = event.next_key_digests().map_err(KelError::serialization)?;
        fields.next_threshold = Some(threshold(map.get("nt"), "nt")?);
        fields.witness_threshold = witness_threshold(map.get("bt"))?;
        if kind == EventKind::Inception {
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

    /// Returns how many anchors the event carries.
    #[must_use]
    pub const fn anchors(&self) -> usize {
        self.anchors
    }
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
