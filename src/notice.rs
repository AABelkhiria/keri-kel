//! Key state notices: replies on route `/ksn/{source}` in which an actor reports an identifier's
//! key state.
//!
//! A [`Kevery`] keeps the latest notice from each source about each identifier, once:
//!
//! - its source is trusted ([`NoticeTrust`]);
//! - the reported state is not older than the local log's;
//! - it is verified as [`crate::reply`] describes, the source being its authority;
//! - at a sequence number the local log holds, the reported event is the local one.
//!
//! This ports keripy's `Kevery.processReplyKeyStateNotice` (`src/keri/core/eventing.py`).
//!
//! One behaviour differs. keripy looks up the notice it kept before from a source by the reported
//! event's SAID, while it stores replies under their own SAIDs, so it never finds one: it compares
//! no dates, and keeps a notice made earlier than the one it replaces. Here the notice kept before
//! is found, and a reply not newer than it is refused, as keripy's best-available-data rule
//! intends.

use keri_protocol::event::key_state::KeyStateRecord;
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::serialization::SerializedEvent;

use crate::error::{Escrow, KelError};
use crate::kevery::{Kevery, Processed};
use crate::reply::{KeptReply, OfferedReply, Reoffer, Verdict};
use crate::store::Store;

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

/// A key state notice kept: the reported state, and the reply that reported it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyStateNotice {
    pub(crate) state: KeyStateRecord,
    pub(crate) kept: KeptReply,
}

impl KeyStateNotice {
    /// Returns the reported state.
    #[must_use]
    pub const fn state(&self) -> &KeyStateRecord {
        &self.state
    }

    /// Returns the reply that reported it, with what decides whether a later one replaces it.
    #[must_use]
    pub const fn kept(&self) -> &KeptReply {
        &self.kept
    }

    /// Returns the reply that reported it.
    #[must_use]
    pub const fn reply(&self) -> &SerializedEvent {
        self.kept.reply()
    }

    /// Returns when the reply was made.
    #[must_use]
    pub const fn timestamp(&self) -> &Timestamp {
        self.kept.timestamp()
    }

    /// Returns, for a transferable source, the sequence number of the establishment event whose
    /// keys signed the reply.
    #[must_use]
    pub const fn signed_at(&self) -> Option<u128> {
        self.kept.signed_at()
    }
}

impl<S: Store> Kevery<S> {
    /// keripy's `processReplyKeyStateNotice`.
    pub(crate) fn consider_notice(
        &mut self,
        offered: OfferedReply<'_>,
        source: &IdentifierPrefix,
        state: KeyStateRecord,
        now: &Timestamp,
    ) -> Result<Processed, KelError> {
        if !self.trust.trusts(source, &state) {
            return Err(KelError::UntrustedKeyStateSource);
        }
        let identifier = qb64(state.identifier())?;
        let source_text = qb64(source)?;
        let local = self.store.kever(&identifier).map_err(KelError::store)?;
        if local.is_some_and(|kever| state.sequence_number() < kever.sequence_number()) {
            return Err(KelError::StaleKeyState);
        }
        let earlier = self
            .store
            .key_state_notice(&identifier, &source_text)
            .map_err(KelError::store)?;
        // keripy finds no earlier notice at all, so the same reply offered again is accepted again.
        let verdict = self.verify_reply(
            offered,
            source,
            earlier.as_ref().map(KeyStateNotice::kept),
            Reoffer::Fresh,
            now,
        )?;
        let Verdict::Accepted(kept) = verdict else {
            return Ok(Processed::Escrowed(Escrow::UnverifiedReply));
        };
        let local = self
            .store
            .event(&identifier, state.sequence_number())
            .map_err(KelError::store)?;
        let reported = state.said().qb64().map_err(KelError::said)?;
        if local.is_some_and(|logged| logged.event().said() != Some(reported.as_str())) {
            return Err(KelError::KeyStateMismatch);
        }
        self.store
            .put_key_state_notice(&identifier, &source_text, KeyStateNotice { state, kept })
            .map_err(KelError::store)?;
        Ok(Processed::KeyStateAccepted)
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

    /// Returns every key state notice kept about `identifier`, with its source.
    ///
    /// # Errors
    ///
    /// Returns [`KelError::Prefix`] for an identifier that cannot be written or read as qb64, and
    /// [`KelError::Store`] when the store fails.
    pub fn key_state_notices(
        &self,
        identifier: &IdentifierPrefix,
    ) -> Result<Vec<(IdentifierPrefix, KeyStateNotice)>, KelError> {
        self.store
            .key_state_notices(&qb64(identifier)?)
            .map_err(KelError::store)?
            .into_iter()
            .map(|(source, notice)| Ok((IdentifierPrefix::from_qb64(&source).map_err(KelError::prefix)?, notice)))
            .collect()
    }
}

fn qb64(identifier: &IdentifierPrefix) -> Result<String, KelError> {
    identifier.qb64().map_err(KelError::prefix)
}
