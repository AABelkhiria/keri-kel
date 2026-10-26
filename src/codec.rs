//! The records a store keeps, as bytes.
//!
//! A [`Store`](crate::Store) that lives in a database keeps each record as bytes; [`Record`] turns a
//! record into bytes and back. The encoding is JSON, so a dump of the database can be read: every
//! primitive is its qb64 text, every timestamp its text, every threshold its canonical JSON, every
//! sequence number lowercase hexadecimal text as KERI writes it, and every event its exact bytes,
//! which for the JSON events this crate handles are text. Decoding checks each primitive as it reads
//! it, so a damaged record is refused rather than half read.

use core::str::FromStr;
use std::error::Error;

use keri_cesr::crypto::digest::Digest;
use keri_cesr::crypto::signature::{IndexedSignature, UnindexedSignature};
use keri_cesr::crypto::verifier::VerificationKey;
use keri_cesr::sequence::SequenceNumber;
use keri_protocol::attachment::{ReceiptCouple, SealSourceCouple};
use keri_protocol::event::key_state::KeyStateRecord;
use keri_protocol::event::kind::EventKind;
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;
use keri_protocol::serialization::{Sad, SerializedEvent};
use keri_protocol::threshold::SigningThreshold;
use serde::{Deserialize, Serialize};

use crate::endpoint::{EndRoleRecord, LocationRecord};
use crate::error::{Escrow, KelError};
use crate::event::EventSeal;
use crate::kever::Kever;
use crate::kevery::{EscrowedEvent, LoggedEvent, ValidatorReceipt, WaitingReceipt, WaitingSignature};
use crate::notice::KeyStateNotice;
use crate::observation::ObservationRecord;
use crate::query::EscrowedQuery;
use crate::reply::{EscrowedReply, KeptReply, ReplySignatures};

/// A record a store keeps, written as bytes and read back.
pub trait Record: Sized {
    /// Writes the record as bytes.
    ///
    /// # Errors
    ///
    /// Returns [`KelError::Record`] when a primitive cannot be written.
    fn to_bytes(&self) -> Result<Vec<u8>, KelError>;

    /// Reads a record written by [`Record::to_bytes`].
    ///
    /// # Errors
    ///
    /// Returns [`KelError::Record`] when the bytes are not such a record.
    fn from_bytes(bytes: &[u8]) -> Result<Self, KelError>;
}

/// Implements [`Record`] for a type through its serialized mirror.
macro_rules! record {
    ($type:ty, $mirror:ty) => {
        impl Record for $type {
            fn to_bytes(&self) -> Result<Vec<u8>, KelError> {
                serde_json::to_vec(&<$mirror>::write(self)?).map_err(KelError::record)
            }

            fn from_bytes(bytes: &[u8]) -> Result<Self, KelError> {
                serde_json::from_slice::<$mirror>(bytes)
                    .map_err(KelError::record)?
                    .read()
            }
        }
    };
}

fn fail<E: Into<Box<dyn Error + Send + Sync>>>(error: E) -> KelError {
    KelError::record(error)
}

fn hex(number: u128) -> String {
    format!("{number:x}")
}

fn number(text: &str) -> Result<u128, KelError> {
    u128::from_str_radix(text, 16).map_err(fail)
}

fn prefix_text(prefix: &IdentifierPrefix) -> Result<String, KelError> {
    prefix.qb64().map_err(fail)
}

fn prefix(text: &str) -> Result<IdentifierPrefix, KelError> {
    IdentifierPrefix::from_qb64(text).map_err(fail)
}

fn prefixes_text(prefixes: &[IdentifierPrefix]) -> Result<Vec<String>, KelError> {
    prefixes.iter().map(prefix_text).collect()
}

fn prefixes(texts: &[String]) -> Result<Vec<IdentifierPrefix>, KelError> {
    texts.iter().map(|text| prefix(text)).collect()
}

fn said_text(said: Said) -> Result<String, KelError> {
    said.qb64().map_err(fail)
}

fn said(text: &str) -> Result<Said, KelError> {
    Said::from_qb64(text).map_err(fail)
}

fn signatures_text(signatures: &[IndexedSignature]) -> Result<Vec<String>, KelError> {
    signatures
        .iter()
        .map(|signature| signature.qb64().map_err(fail))
        .collect()
}

fn signatures(texts: &[String]) -> Result<Vec<IndexedSignature>, KelError> {
    texts
        .iter()
        .map(|text| IndexedSignature::from_qb64(text).map_err(fail))
        .collect()
}

fn event_text(event: &SerializedEvent) -> Result<String, KelError> {
    String::from_utf8(event.raw().to_vec()).map_err(fail)
}

fn event(text: &str) -> Result<SerializedEvent, KelError> {
    SerializedEvent::parse(text.as_bytes()).map_err(fail)
}

fn timestamp(text: &str) -> Result<Timestamp, KelError> {
    Timestamp::parse(text).map_err(fail)
}

fn threshold(text: &str) -> Result<SigningThreshold, KelError> {
    SigningThreshold::from_json(text).map_err(fail)
}

/// A seal source couple: the sequence number and SAID of the event it names.
#[derive(Serialize, Deserialize)]
struct SourceMirror {
    s: String,
    d: String,
}

impl SourceMirror {
    fn write(source: &SealSourceCouple) -> Result<Self, KelError> {
        Ok(Self {
            s: hex(source.sequence_number().value()),
            d: said_text(source.said())?,
        })
    }

    fn read(&self) -> Result<SealSourceCouple, KelError> {
        Ok(SealSourceCouple::new(
            SequenceNumber::new(number(&self.s)?),
            said(&self.d)?,
        ))
    }
}

/// A receipt couple: the receiptor's key and its signature.
#[derive(Serialize, Deserialize)]
struct CoupleMirror {
    key: String,
    signature: String,
}

impl CoupleMirror {
    fn write(couple: &ReceiptCouple) -> Result<Self, KelError> {
        Ok(Self {
            key: couple.verifier().qb64().map_err(fail)?,
            signature: couple.signature().qb64().map_err(fail)?,
        })
    }

    fn read(&self) -> Result<ReceiptCouple, KelError> {
        ReceiptCouple::new(
            VerificationKey::from_qb64(&self.key).map_err(fail)?,
            UnindexedSignature::from_qb64(&self.signature).map_err(fail)?,
        )
        .map_err(fail)
    }
}

/// A validator's receipt: the validator, its establishment event, and its signature.
#[derive(Serialize, Deserialize)]
struct ValidatorMirror {
    validator: String,
    s: String,
    d: String,
    signature: String,
}

impl ValidatorMirror {
    fn write(receipt: &ValidatorReceipt) -> Result<Self, KelError> {
        Ok(Self {
            validator: prefix_text(&receipt.validator)?,
            s: hex(receipt.sequence_number),
            d: said_text(receipt.said)?,
            signature: receipt.signature.qb64().map_err(fail)?,
        })
    }

    fn read(&self) -> Result<ValidatorReceipt, KelError> {
        Ok(ValidatorReceipt {
            validator: prefix(&self.validator)?,
            sequence_number: number(&self.s)?,
            said: said(&self.d)?,
            signature: IndexedSignature::from_qb64(&self.signature).map_err(fail)?,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct SealMirror {
    i: String,
    s: String,
    d: String,
}

impl SealMirror {
    fn write(seal: &EventSeal) -> Self {
        Self {
            i: seal.identifier.clone(),
            s: seal.sequence_number.clone(),
            d: seal.said.clone(),
        }
    }

    fn read(&self) -> EventSeal {
        EventSeal {
            identifier: self.i.clone(),
            sequence_number: self.s.clone(),
            said: self.d.clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct KeverMirror {
    identifier: String,
    s: String,
    d: String,
    prior: Option<String>,
    kind: String,
    keys: Vec<String>,
    signing_threshold: String,
    next_digests: Vec<String>,
    next_threshold: String,
    witnesses: Vec<String>,
    witness_threshold: u32,
    cuts: Vec<String>,
    adds: Vec<String>,
    establishment_s: String,
    establishment_d: String,
    since_establishment: Vec<String>,
    establishment_prior: Option<String>,
    establishment_only: bool,
    do_not_delegate: bool,
    delegator: Option<String>,
    first_seen: String,
    first_seen_at: String,
}

impl KeverMirror {
    fn write(kever: &Kever) -> Result<Self, KelError> {
        Ok(Self {
            identifier: prefix_text(&kever.identifier)?,
            s: hex(kever.sequence_number),
            d: said_text(kever.said)?,
            prior: kever.prior.map(said_text).transpose()?,
            kind: kever.latest_kind.as_str().to_owned(),
            keys: kever
                .keys
                .iter()
                .map(|key| key.qb64().map_err(fail))
                .collect::<Result<_, _>>()?,
            signing_threshold: kever.signing_threshold.canonical_json(),
            next_digests: kever
                .next_digests
                .iter()
                .map(|digest| digest.qb64().map_err(fail))
                .collect::<Result<_, _>>()?,
            next_threshold: kever.next_threshold.canonical_json(),
            witnesses: prefixes_text(&kever.witnesses)?,
            witness_threshold: kever.witness_threshold,
            cuts: prefixes_text(&kever.cuts)?,
            adds: prefixes_text(&kever.adds)?,
            establishment_s: hex(kever.last_establishment.0),
            establishment_d: said_text(kever.last_establishment.1)?,
            since_establishment: kever
                .since_establishment
                .iter()
                .map(|said| said_text(*said))
                .collect::<Result<_, _>>()?,
            establishment_prior: kever.establishment_prior.map(said_text).transpose()?,
            establishment_only: kever.establishment_only,
            do_not_delegate: kever.do_not_delegate,
            delegator: kever.delegator.as_ref().map(prefix_text).transpose()?,
            first_seen: hex(kever.first_seen),
            first_seen_at: kever.first_seen_at.as_str().to_owned(),
        })
    }

    fn read(&self) -> Result<Kever, KelError> {
        Ok(Kever {
            identifier: prefix(&self.identifier)?,
            sequence_number: number(&self.s)?,
            said: said(&self.d)?,
            prior: self.prior.as_deref().map(said).transpose()?,
            latest_kind: EventKind::from_str(&self.kind).map_err(fail)?,
            keys: self
                .keys
                .iter()
                .map(|key| VerificationKey::from_qb64(key).map_err(fail))
                .collect::<Result<_, _>>()?,
            signing_threshold: threshold(&self.signing_threshold)?,
            next_digests: self
                .next_digests
                .iter()
                .map(|digest| Digest::from_qb64(digest).map_err(fail))
                .collect::<Result<_, _>>()?,
            next_threshold: threshold(&self.next_threshold)?,
            witnesses: prefixes(&self.witnesses)?,
            witness_threshold: self.witness_threshold,
            cuts: prefixes(&self.cuts)?,
            adds: prefixes(&self.adds)?,
            last_establishment: (number(&self.establishment_s)?, said(&self.establishment_d)?),
            since_establishment: self
                .since_establishment
                .iter()
                .map(|text| said(text))
                .collect::<Result<_, _>>()?,
            establishment_prior: self.establishment_prior.as_deref().map(said).transpose()?,
            establishment_only: self.establishment_only,
            do_not_delegate: self.do_not_delegate,
            delegator: self.delegator.as_deref().map(prefix).transpose()?,
            first_seen: number(&self.first_seen)?,
            first_seen_at: timestamp(&self.first_seen_at)?,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct LoggedMirror {
    event: String,
    signatures: Vec<String>,
    witness_signatures: Vec<String>,
    receipts: Vec<CoupleMirror>,
    validator_receipts: Vec<ValidatorMirror>,
    keys: Vec<String>,
    witnesses: Vec<String>,
    delegation: Option<SourceMirror>,
    event_seals: Vec<SealMirror>,
    first_seen: String,
    first_seen_at: String,
}

impl LoggedMirror {
    fn write(logged: &LoggedEvent) -> Result<Self, KelError> {
        Ok(Self {
            event: event_text(&logged.event)?,
            signatures: signatures_text(&logged.signatures)?,
            witness_signatures: signatures_text(&logged.witness_signatures)?,
            receipts: logged
                .receipts
                .iter()
                .map(CoupleMirror::write)
                .collect::<Result<_, _>>()?,
            validator_receipts: logged
                .validator_receipts
                .iter()
                .map(ValidatorMirror::write)
                .collect::<Result<_, _>>()?,
            keys: logged
                .keys
                .iter()
                .map(|key| key.qb64().map_err(fail))
                .collect::<Result<_, _>>()?,
            witnesses: prefixes_text(&logged.witnesses)?,
            delegation: logged.delegation.as_ref().map(SourceMirror::write).transpose()?,
            event_seals: logged.event_seals.iter().map(SealMirror::write).collect(),
            first_seen: hex(logged.first_seen),
            first_seen_at: logged.first_seen_at.as_str().to_owned(),
        })
    }

    fn read(&self) -> Result<LoggedEvent, KelError> {
        Ok(LoggedEvent {
            event: event(&self.event)?,
            signatures: signatures(&self.signatures)?,
            witness_signatures: signatures(&self.witness_signatures)?,
            receipts: self.receipts.iter().map(CoupleMirror::read).collect::<Result<_, _>>()?,
            validator_receipts: self
                .validator_receipts
                .iter()
                .map(ValidatorMirror::read)
                .collect::<Result<_, _>>()?,
            keys: self
                .keys
                .iter()
                .map(|key| VerificationKey::from_qb64(key).map_err(fail))
                .collect::<Result<_, _>>()?,
            witnesses: prefixes(&self.witnesses)?,
            delegation: self.delegation.as_ref().map(SourceMirror::read).transpose()?,
            event_seals: self.event_seals.iter().map(SealMirror::read).collect(),
            first_seen: number(&self.first_seen)?,
            first_seen_at: timestamp(&self.first_seen_at)?,
        })
    }
}

fn escrow_name(escrow: Escrow) -> &'static str {
    match escrow {
        Escrow::PartiallySigned => "partially_signed",
        Escrow::PartiallyWitnessed => "partially_witnessed",
        Escrow::UnverifiedReceipt => "unverified_receipt",
        Escrow::UnverifiedTransferableReceipt => "unverified_transferable_receipt",
        Escrow::UnverifiedReply => "unverified_reply",
        Escrow::QueryNotFound => "query_not_found",
        Escrow::PartiallyDelegated => "partially_delegated",
        Escrow::OutOfOrder => "out_of_order",
        Escrow::LikelyDuplicitous => "likely_duplicitous",
    }
}

fn escrow(name: &str) -> Result<Escrow, KelError> {
    Ok(match name {
        "partially_signed" => Escrow::PartiallySigned,
        "partially_witnessed" => Escrow::PartiallyWitnessed,
        "unverified_receipt" => Escrow::UnverifiedReceipt,
        "unverified_transferable_receipt" => Escrow::UnverifiedTransferableReceipt,
        "unverified_reply" => Escrow::UnverifiedReply,
        "query_not_found" => Escrow::QueryNotFound,
        "partially_delegated" => Escrow::PartiallyDelegated,
        "out_of_order" => Escrow::OutOfOrder,
        "likely_duplicitous" => Escrow::LikelyDuplicitous,
        other => return Err(fail(format!("unknown escrow {other:?}"))),
    })
}

#[derive(Serialize, Deserialize)]
struct EscrowedMirror {
    reason: String,
    arrival: u64,
    s: String,
    event: String,
    signatures: Vec<String>,
    witness_signatures: Vec<String>,
    source: Option<SourceMirror>,
    since: String,
}

impl EscrowedMirror {
    fn write(escrowed: &EscrowedEvent) -> Result<Self, KelError> {
        Ok(Self {
            reason: escrow_name(escrowed.reason).to_owned(),
            arrival: escrowed.arrival,
            s: hex(escrowed.sequence_number),
            event: event_text(&escrowed.event)?,
            signatures: signatures_text(&escrowed.signatures)?,
            witness_signatures: signatures_text(&escrowed.witness_signatures)?,
            source: escrowed.source.as_ref().map(SourceMirror::write).transpose()?,
            since: escrowed.since.as_str().to_owned(),
        })
    }

    fn read(&self) -> Result<EscrowedEvent, KelError> {
        Ok(EscrowedEvent {
            reason: escrow(&self.reason)?,
            arrival: self.arrival,
            sequence_number: number(&self.s)?,
            event: event(&self.event)?,
            signatures: signatures(&self.signatures)?,
            witness_signatures: signatures(&self.witness_signatures)?,
            source: self.source.as_ref().map(SourceMirror::read).transpose()?,
            since: timestamp(&self.since)?,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SignatureMirror {
    Witness(String),
    Couple(CoupleMirror),
    Validator(ValidatorMirror),
}

#[derive(Serialize, Deserialize)]
struct WaitingMirror {
    identifier: String,
    s: String,
    d: String,
    signature: SignatureMirror,
    received_at: String,
}

impl WaitingMirror {
    fn write(waiting: &WaitingReceipt) -> Result<Self, KelError> {
        Ok(Self {
            identifier: prefix_text(&waiting.identifier)?,
            s: hex(waiting.sequence_number),
            d: said_text(waiting.said)?,
            signature: match &waiting.signature {
                WaitingSignature::Witness(signature) => SignatureMirror::Witness(signature.qb64().map_err(fail)?),
                WaitingSignature::Couple(couple) => SignatureMirror::Couple(CoupleMirror::write(couple)?),
                WaitingSignature::Validator(receipt) => SignatureMirror::Validator(ValidatorMirror::write(receipt)?),
            },
            received_at: waiting.received_at.as_str().to_owned(),
        })
    }

    fn read(&self) -> Result<WaitingReceipt, KelError> {
        Ok(WaitingReceipt {
            identifier: prefix(&self.identifier)?,
            sequence_number: number(&self.s)?,
            said: said(&self.d)?,
            signature: match &self.signature {
                SignatureMirror::Witness(text) => {
                    WaitingSignature::Witness(IndexedSignature::from_qb64(text).map_err(fail)?)
                }
                SignatureMirror::Couple(couple) => WaitingSignature::Couple(couple.read()?),
                SignatureMirror::Validator(receipt) => WaitingSignature::Validator(receipt.read()?),
            },
            received_at: timestamp(&self.received_at)?,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct KeptMirror {
    reply: String,
    timestamp: String,
    signed_at: Option<String>,
}

impl KeptMirror {
    fn write(kept: &KeptReply) -> Result<Self, KelError> {
        Ok(Self {
            reply: event_text(&kept.reply)?,
            timestamp: kept.timestamp.as_str().to_owned(),
            signed_at: kept.signed_at.map(hex),
        })
    }

    fn read(&self) -> Result<KeptReply, KelError> {
        Ok(KeptReply {
            reply: event(&self.reply)?,
            timestamp: timestamp(&self.timestamp)?,
            signed_at: self.signed_at.as_deref().map(number).transpose()?,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct NoticeMirror {
    state: String,
    kept: KeptMirror,
}

impl NoticeMirror {
    fn write(notice: &KeyStateNotice) -> Result<Self, KelError> {
        let state = notice.state.to_sad().map_err(fail)?.to_json_bytes().map_err(fail)?;
        Ok(Self {
            state: String::from_utf8(state).map_err(fail)?,
            kept: KeptMirror::write(&notice.kept)?,
        })
    }

    fn read(&self) -> Result<KeyStateNotice, KelError> {
        let sad = Sad::from_json_bytes(self.state.as_bytes()).map_err(fail)?;
        Ok(KeyStateNotice {
            state: KeyStateRecord::from_sad(&sad).map_err(fail)?,
            kept: self.kept.read()?,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct SignaturesMirror {
    signer: String,
    s: String,
    d: String,
    signatures: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct EscrowedReplyMirror {
    reply: String,
    groups: Vec<SignaturesMirror>,
    since: String,
}

impl EscrowedReplyMirror {
    fn write(escrowed: &EscrowedReply) -> Result<Self, KelError> {
        Ok(Self {
            reply: event_text(&escrowed.reply)?,
            groups: escrowed
                .groups
                .iter()
                .map(|group: &ReplySignatures| {
                    Ok(SignaturesMirror {
                        signer: prefix_text(&group.signer)?,
                        s: hex(group.sequence_number),
                        d: said_text(group.said)?,
                        signatures: signatures_text(&group.signatures)?,
                    })
                })
                .collect::<Result<_, KelError>>()?,
            since: escrowed.since.as_str().to_owned(),
        })
    }

    fn read(&self) -> Result<EscrowedReply, KelError> {
        Ok(EscrowedReply {
            reply: event(&self.reply)?,
            groups: self
                .groups
                .iter()
                .map(|group| {
                    Ok(ReplySignatures {
                        signer: prefix(&group.signer)?,
                        sequence_number: number(&group.s)?,
                        said: said(&group.d)?,
                        signatures: signatures(&group.signatures)?,
                    })
                })
                .collect::<Result<_, KelError>>()?,
            since: timestamp(&self.since)?,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct EndRoleMirror {
    allowed: bool,
    kept: KeptMirror,
}

impl EndRoleMirror {
    fn write(record: &EndRoleRecord) -> Result<Self, KelError> {
        Ok(Self {
            allowed: record.allowed,
            kept: KeptMirror::write(&record.kept)?,
        })
    }

    fn read(&self) -> Result<EndRoleRecord, KelError> {
        Ok(EndRoleRecord {
            allowed: self.allowed,
            kept: self.kept.read()?,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct LocationMirror {
    url: String,
    kept: KeptMirror,
}

impl LocationMirror {
    fn write(record: &LocationRecord) -> Result<Self, KelError> {
        Ok(Self {
            url: record.url.clone(),
            kept: KeptMirror::write(&record.kept)?,
        })
    }

    fn read(&self) -> Result<LocationRecord, KelError> {
        Ok(LocationRecord {
            url: self.url.clone(),
            kept: self.kept.read()?,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct ObservationMirror {
    enabled: bool,
    kept: KeptMirror,
}

impl ObservationMirror {
    fn write(record: &ObservationRecord) -> Result<Self, KelError> {
        Ok(Self {
            enabled: record.enabled,
            kept: KeptMirror::write(&record.kept)?,
        })
    }

    fn read(&self) -> Result<ObservationRecord, KelError> {
        Ok(ObservationRecord {
            enabled: self.enabled,
            kept: self.kept.read()?,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct QueryMirror {
    query: String,
    requester: String,
    since: String,
}

impl QueryMirror {
    fn write(escrowed: &EscrowedQuery) -> Result<Self, KelError> {
        Ok(Self {
            query: event_text(&escrowed.query)?,
            requester: prefix_text(&escrowed.requester)?,
            since: escrowed.since.as_str().to_owned(),
        })
    }

    fn read(&self) -> Result<EscrowedQuery, KelError> {
        Ok(EscrowedQuery {
            query: event(&self.query)?,
            requester: prefix(&self.requester)?,
            since: timestamp(&self.since)?,
        })
    }
}

record!(Kever, KeverMirror);
record!(LoggedEvent, LoggedMirror);
record!(EscrowedEvent, EscrowedMirror);
record!(WaitingReceipt, WaitingMirror);
record!(KeyStateNotice, NoticeMirror);
record!(EscrowedReply, EscrowedReplyMirror);
record!(EndRoleRecord, EndRoleMirror);
record!(LocationRecord, LocationMirror);
record!(ObservationRecord, ObservationMirror);
record!(EscrowedQuery, QueryMirror);
