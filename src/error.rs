//! Failures raised while validating key events.

use core::fmt;
use std::error::Error;

use keri_cesr::CesrError;
use keri_protocol::event::EventError;
use keri_protocol::prefix::PrefixError;
use keri_protocol::said::SaidError;
use keri_protocol::serialization::SerializationError;
use keri_protocol::threshold::ThresholdError;

use crate::store::StoreError;

/// Why an event that is not accepted yet might be accepted later.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Escrow {
    /// Its verified controller signatures do not yet meet the current signing threshold; keripy's
    /// partially signed escrow.
    PartiallySigned,
    /// Its verified witness signatures do not yet meet the witness threshold; keripy's partially
    /// witnessed escrow.
    PartiallyWitnessed,
    /// A receipt names an event not yet accepted; keripy's unverified receipt escrows.
    UnverifiedReceipt,
    /// A validator's receipt names an event of the validator not yet accepted; keripy's unverified
    /// transferable receipt escrow.
    UnverifiedTransferableReceipt,
    /// A delegated event is fully signed and witnessed, but its delegator's approval has not been
    /// found yet; keripy's partially delegated escrow.
    PartiallyDelegated,
    /// An event comes before the events it follows; keripy's out-of-order escrow. Nothing about it
    /// can be verified until they are accepted.
    OutOfOrder,
    /// An event contradicts one already accepted at its sequence number; keripy's
    /// likely-duplicitous escrow, which holds it aside as evidence and never accepts it.
    LikelyDuplicitous,
}

/// Stable key event validation failures.
#[derive(Debug)]
#[non_exhaustive]
pub enum KelError {
    /// The message is not a key event this validator accepts.
    UnsupportedKind {
        /// The kind found.
        kind: &'static str,
    },
    /// An inception's sequence number is not zero.
    NonZeroInception,
    /// A non-transferable identifier's inception carries next keys, witnesses or anchors.
    NonTransferableInception {
        /// Label of the field that must be empty.
        label: &'static str,
    },
    /// The signing threshold needs more keys than the event lists.
    ThresholdExceedsKeys {
        /// Key positions the threshold requires.
        required: u128,
        /// Keys the event lists.
        keys: usize,
    },
    /// A witness list holds the same witness twice.
    DuplicateWitness {
        /// Label of the list.
        label: &'static str,
    },
    /// A rotation removes a witness that is not a current witness.
    CutNotAWitness,
    /// A rotation lists a witness in two lists that must not overlap.
    ConflictingWitnessLists {
        /// First list label.
        first: &'static str,
        /// Second list label.
        second: &'static str,
    },
    /// The witness threshold does not fit the witness set.
    InvalidWitnessThreshold {
        /// The threshold.
        threshold: u32,
        /// Witnesses in the set.
        witnesses: usize,
    },
    /// The event belongs to another identifier than the log.
    IdentifierMismatch,
    /// The identifier cannot take further events: it is non-transferable or was abandoned by a
    /// rotation committing to no next keys.
    NotTransferable,
    /// The event's sequence number is past the next one.
    OutOfOrder {
        /// The next sequence number.
        expected: u128,
        /// The sequence number found.
        found: u128,
    },
    /// The event's sequence number is not past the latest one, and it is not a recovery.
    Stale {
        /// The next sequence number.
        expected: u128,
        /// The sequence number found.
        found: u128,
    },
    /// The event's prior digest is not the latest event's SAID.
    PriorMismatch,
    /// An interaction was offered to an identifier configured for establishment events only.
    EstablishmentOnly,
    /// Not one controller signature verifies.
    NoVerifiedSignatures,
    /// The verified controller signatures do not meet the signing threshold.
    NotFullySigned,
    /// A rotation's verified signatures do not expose enough of the prior next keys.
    PriorNextNotSatisfied,
    /// The verified witness signatures do not meet the witness threshold.
    NotFullyWitnessed,
    /// A delegated identifier rotated with a plain rotation (`rot`); its rotations must be
    /// delegated (`drt`), so that its delegator approves them.
    UndelegatedRotation,
    /// The delegator's inception has not been accepted yet.
    DelegatorUnknown,
    /// The delegator's inception configures do-not-delegate (`DND`).
    DelegationForbidden,
    /// The event's seal source couple names the delegator's inception, which cannot anchor a
    /// delegated event.
    DelegationSourceAtInception,
    /// The delegator has not accepted an event at the sequence number the seal source couple
    /// names yet.
    DelegatingEventUnknown,
    /// No event of the delegator anchors a seal of this event yet, or the one the seal source
    /// couple names does not.
    DelegationNotAnchored,
    /// A delegated rotation would supersede a delegated rotation, but its delegating event is not
    /// later in the delegator's log than the superseded rotation's.
    ///
    /// keripy documents two more ways to supersede: a later seal in the same delegating event, and
    /// a delegating rotation superseding a delegating interaction at the same sequence number. Its
    /// code raises `AttributeError` before reaching either rule and refuses the rotation, and so
    /// does this validator, so that both agree on which events a log holds.
    SupersedingDelegationNotLater,
    /// A delegated rotation would supersede an interaction that is not the latest event. keripy
    /// compares against the delegating event of the latest event, which an interaction does not
    /// have, and refuses the rotation once its delegator's log holds no seal of that interaction.
    SupersededWithoutDelegation,
    /// An event contradicts one already accepted at its sequence number.
    LikelyDuplicitous,
    /// A receipt names an event other than the one accepted at its sequence number.
    StaleReceipt,
    /// A validator's receipt names an event other than the validator's accepted event at the
    /// named sequence number.
    ReceiptorEventMismatch,
    /// A validator's receipt names an interaction, which lists no keys to verify it with.
    ReceiptorEventHasNoKeys,
    /// A validator's signature names a key position past the keys of the event it names.
    ReceiptSignatureIndexOutOfRange,
    /// A field holds a different shape than a key event defines.
    UnexpectedFieldShape {
        /// Label of the field.
        label: &'static str,
    },
    /// The message could not be parsed.
    Serialization {
        /// Underlying serialization failure.
        source: Box<SerializationError>,
    },
    /// A self-addressing inception's SAID is not its prefix.
    SaidNotPrefix,
    /// The event's SAID does not verify.
    Said {
        /// Underlying SAID failure.
        source: Box<SaidError>,
    },
    /// The inception's prefix does not derive from it, or a prefix is malformed.
    Prefix {
        /// Underlying prefix failure.
        source: Box<PrefixError>,
    },
    /// A threshold is malformed.
    Threshold {
        /// Underlying threshold failure.
        source: Box<ThresholdError>,
    },
    /// CESR material is malformed.
    Cesr {
        /// Underlying CESR failure.
        source: Box<CesrError>,
    },
    /// The store could not read or write.
    Store {
        /// Underlying store failure.
        source: Box<StoreError>,
    },
    /// The key state could not be written.
    Event {
        /// Underlying event failure.
        source: Box<EventError>,
    },
}

impl KelError {
    /// Returns why waiting could get the event accepted, or `None` when it never will be.
    #[must_use]
    pub const fn escrow(&self) -> Option<Escrow> {
        match self {
            Self::NotFullySigned | Self::PriorNextNotSatisfied => Some(Escrow::PartiallySigned),
            Self::NotFullyWitnessed => Some(Escrow::PartiallyWitnessed),
            Self::DelegatorUnknown | Self::DelegatingEventUnknown | Self::DelegationNotAnchored => {
                Some(Escrow::PartiallyDelegated)
            }
            Self::OutOfOrder { .. } => Some(Escrow::OutOfOrder),
            Self::LikelyDuplicitous => Some(Escrow::LikelyDuplicitous),
            _ => None,
        }
    }

    pub(crate) fn serialization(source: SerializationError) -> Self {
        Self::Serialization {
            source: Box::new(source),
        }
    }

    pub(crate) fn said(source: SaidError) -> Self {
        Self::Said {
            source: Box::new(source),
        }
    }

    pub(crate) fn prefix(source: PrefixError) -> Self {
        Self::Prefix {
            source: Box::new(source),
        }
    }

    pub(crate) fn threshold(source: ThresholdError) -> Self {
        Self::Threshold {
            source: Box::new(source),
        }
    }

    pub(crate) fn cesr(source: CesrError) -> Self {
        Self::Cesr {
            source: Box::new(source),
        }
    }

    pub(crate) fn store(source: StoreError) -> Self {
        Self::Store {
            source: Box::new(source),
        }
    }

    pub(crate) fn event(source: EventError) -> Self {
        Self::Event {
            source: Box::new(source),
        }
    }
}

impl fmt::Display for KelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedKind { kind } => write!(formatter, "message kind {kind} is not a key event"),
            Self::NonZeroInception => formatter.write_str("inception sequence number is not zero"),
            Self::NonTransferableInception { label } => {
                write!(formatter, "non-transferable inception carries a non-empty {label:?}")
            }
            Self::ThresholdExceedsKeys { required, keys } => {
                write!(
                    formatter,
                    "signing threshold needs {required} keys but the event lists {keys}"
                )
            }
            Self::DuplicateWitness { label } => write!(formatter, "witness list {label:?} holds a duplicate"),
            Self::CutNotAWitness => formatter.write_str("rotation removes a witness that is not current"),
            Self::ConflictingWitnessLists { first, second } => {
                write!(formatter, "witness lists {first:?} and {second:?} overlap")
            }
            Self::InvalidWitnessThreshold { threshold, witnesses } => {
                write!(
                    formatter,
                    "witness threshold {threshold} does not fit {witnesses} witnesses"
                )
            }
            Self::IdentifierMismatch => formatter.write_str("event belongs to another identifier"),
            Self::NotTransferable => formatter.write_str("identifier takes no further events"),
            Self::OutOfOrder { expected, found } => {
                write!(
                    formatter,
                    "sequence number {found} is out of order, expected {expected}"
                )
            }
            Self::Stale { expected, found } => {
                write!(formatter, "sequence number {found} is stale, expected {expected}")
            }
            Self::PriorMismatch => formatter.write_str("prior digest is not the latest event's SAID"),
            Self::EstablishmentOnly => formatter.write_str("identifier accepts establishment events only"),
            Self::NoVerifiedSignatures => formatter.write_str("no controller signature verifies"),
            Self::NotFullySigned => formatter.write_str("controller signatures do not meet the signing threshold"),
            Self::PriorNextNotSatisfied => {
                formatter.write_str("rotation signatures do not satisfy the prior next-key threshold")
            }
            Self::NotFullyWitnessed => formatter.write_str("witness signatures do not meet the witness threshold"),
            Self::UndelegatedRotation => formatter.write_str("delegated identifier rotated without delegation"),
            Self::DelegatorUnknown => formatter.write_str("delegator's log is not known"),
            Self::DelegationForbidden => formatter.write_str("delegator does not allow delegation"),
            Self::DelegationSourceAtInception => {
                formatter.write_str("seal source couple names the delegator's inception")
            }
            Self::DelegatingEventUnknown => formatter.write_str("delegating event is not accepted yet"),
            Self::DelegationNotAnchored => formatter.write_str("no delegator event anchors this event"),
            Self::SupersedingDelegationNotLater => {
                formatter.write_str("superseding delegation is not later than the superseded one")
            }
            Self::SupersededWithoutDelegation => {
                formatter.write_str("superseded event has no delegating event to compare with")
            }
            Self::LikelyDuplicitous => formatter.write_str("event contradicts one already accepted"),
            Self::StaleReceipt => formatter.write_str("receipt names an event other than the accepted one"),
            Self::ReceiptorEventMismatch => {
                formatter.write_str("validator receipt names an event the validator did not accept")
            }
            Self::ReceiptorEventHasNoKeys => formatter.write_str("validator receipt names an event without keys"),
            Self::ReceiptSignatureIndexOutOfRange => {
                formatter.write_str("validator signature index is past the validator's keys")
            }
            Self::UnexpectedFieldShape { label } => write!(formatter, "field {label:?} has an unexpected shape"),
            Self::Serialization { .. } => formatter.write_str("message could not be parsed"),
            Self::SaidNotPrefix => formatter.write_str("self-addressing inception's SAID is not its prefix"),
            Self::Said { .. } => formatter.write_str("event SAID does not verify"),
            Self::Prefix { .. } => formatter.write_str("identifier prefix is invalid"),
            Self::Threshold { .. } => formatter.write_str("threshold is invalid"),
            Self::Cesr { .. } => formatter.write_str("CESR material is invalid"),
            Self::Store { .. } => formatter.write_str("store could not read or write"),
            Self::Event { .. } => formatter.write_str("key state could not be written"),
        }
    }
}

impl Error for KelError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Serialization { source } => Some(source.as_ref()),
            Self::Said { source } => Some(source.as_ref()),
            Self::Prefix { source } => Some(source.as_ref()),
            Self::Threshold { source } => Some(source.as_ref()),
            Self::Cesr { source } => Some(source.as_ref()),
            Self::Store { source } => Some(source.as_ref()),
            Self::Event { source } => Some(source.as_ref()),
            _ => None,
        }
    }
}
