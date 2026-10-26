//! Answers to queries (`qry`): replaying an identifier's log, giving its key state, or opening its
//! mailbox.
//!
//! A [`Kevery`] answers a query once its log holds what the query asks for:
//!
//! - `logs` replays the identifier's events from a first-seen ordinal, every event in the order
//!   first seen, superseded ones included, followed by its delegator's whole log. With an anchor,
//!   it waits until a fully witnessed event of the identifier, superseded or not, holds that event
//!   seal; with a sequence number, until the log reaches it and its latest event is fully
//!   witnessed;
//! - `ksn` gives the key state, once the latest event is fully witnessed;
//! - `mbx` opens the mailbox, once the identifier is known; serving it is the application's.
//!
//! A query the log cannot answer yet waits in the query escrow, and [`Kevery::process_escrows`]
//! answers it once it can. Answers are queued, as keripy cues them, and taken with
//! [`Kevery::take_answers`]; each names the requester to send it to.
//!
//! keripy does not verify a query's signatures: they only name the requester. Neither does this
//! port; whether a requester may ask is the application's decision. A query signed by a
//! transferable requester's latest establishment keys names that requester; one signed by a
//! non-transferable key names that key. keripy cannot escrow a query without a transferable
//! requester: it raises while escrowing, and the query is lost. Here such a query is refused with
//! [`KelError::QueryUnanswerable`].
//!
//! This ports keripy's `Kevery.processQuery`, `escrowQueryNotFoundEvent` and
//! `processQueryNotFound` (`src/keri/core/eventing.py`). [`LoggedEvent::replay`] writes each
//! replayed event out as keripy's `cloneEvtMsg` does.

use keri_protocol::event::key_state::KeyStateRecord;
use keri_protocol::event::query::QueryMessage;
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::serialization::{Sad, SerializedEvent};
use keri_protocol::stream::Message;

use crate::error::{Escrow, KelError};
use crate::event::EventSeal;
use crate::kever::Kever;
use crate::kevery::{Kevery, LoggedEvent, Processed};
use crate::store::Store;

/// What a query is answered with.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Answer {
    /// `logs`: the identifier's events to replay, in the order first seen, and its delegator's.
    Replay {
        /// The identifier whose log is replayed.
        identifier: IdentifierPrefix,
        /// Its events from the first-seen ordinal asked for, superseded ones included.
        events: Vec<LoggedEvent>,
        /// Its delegator's events, all of them, when it is delegated and the delegator is known.
        delegator: Vec<LoggedEvent>,
    },
    /// `ksn`: the identifier's key state.
    KeyState(Box<KeyStateRecord>),
    /// `mbx`: the identifier is known; serving its mailbox is the application's.
    Mailbox {
        /// The identifier whose mailbox is opened.
        identifier: IdentifierPrefix,
        /// The topics asked for, with the index to start each from.
        topics: Option<Sad>,
    },
}

/// A query answered, and who to send the answer to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Answered {
    query: SerializedEvent,
    requester: IdentifierPrefix,
    answer: Answer,
}

impl Answered {
    /// Returns the query.
    #[must_use]
    pub const fn query(&self) -> &SerializedEvent {
        &self.query
    }

    /// Returns the requester the query names.
    #[must_use]
    pub const fn requester(&self) -> &IdentifierPrefix {
        &self.requester
    }

    /// Returns the answer.
    #[must_use]
    pub const fn answer(&self) -> &Answer {
        &self.answer
    }

    /// Returns the answer, giving up the rest.
    #[must_use]
    pub fn into_answer(self) -> Answer {
        self.answer
    }
}

/// A query waiting for the log to hold what it asks for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowedQuery {
    pub(crate) query: SerializedEvent,
    pub(crate) requester: IdentifierPrefix,
    pub(crate) since: Timestamp,
}

impl EscrowedQuery {
    /// Returns the query.
    #[must_use]
    pub const fn query(&self) -> &SerializedEvent {
        &self.query
    }

    /// Returns the transferable requester the query names.
    #[must_use]
    pub const fn requester(&self) -> &IdentifierPrefix {
        &self.requester
    }

    /// Returns when it was escrowed.
    #[must_use]
    pub const fn since(&self) -> &Timestamp {
        &self.since
    }
}

impl<S: Store> Kevery<S> {
    /// keripy's parser and `processQuery` for a query.
    pub(crate) fn process_query(&mut self, message: &Message, now: &Timestamp) -> Result<Processed, KelError> {
        let query = QueryMessage::from_serialized(message.event().clone()).map_err(KelError::event)?;
        let attachments = message.attachments();
        // keripy's parser takes the last transferable group, and otherwise the first couple.
        let (requester, transferable) = if let Some(group) = attachments.last_establishment_signature_groups().last() {
            (group.identifier().clone(), true)
        } else if let Some(couple) = attachments.receipt_couples().first() {
            let key = couple.verifier().qb64().map_err(|_| KelError::QueryWithoutRequester)?;
            (IdentifierPrefix::from_qb64(&key).map_err(KelError::prefix)?, false)
        } else {
            return Err(KelError::QueryWithoutRequester);
        };
        if let Some(answer) = self.decide_query(&query)? {
            self.answers.push(Answered {
                query: message.event().clone(),
                requester,
                answer,
            });
            return Ok(Processed::Answered);
        }
        if !transferable {
            return Err(KelError::QueryUnanswerable);
        }
        let said = query.said().qb64().map_err(KelError::said)?;
        let escrowed = EscrowedQuery {
            query: message.event().clone(),
            requester: requester.clone(),
            since: now.clone(),
        };
        self.store
            .put_escrowed_query(&qb64(&requester)?, &said, escrowed)
            .map_err(KelError::store)?;
        Ok(Processed::Escrowed(Escrow::QueryNotFound))
    }

    /// keripy's `processQuery`: the answer, or `None` while the log cannot answer yet.
    fn decide_query(&self, query: &QueryMessage) -> Result<Option<Answer>, KelError> {
        let arguments = query.arguments().map_err(KelError::event)?;
        let identifier = arguments.identifier();
        let text = qb64(identifier)?;
        let route = query.route();
        if !matches!(route, "logs" | "ksn" | "mbx") {
            return Err(KelError::UnsupportedQueryRoute);
        }
        let Some(kever) = self.store.kever(&text).map_err(KelError::store)? else {
            return Ok(None);
        };
        match route {
            "logs" => {
                if let Some(anchor) = arguments.anchor_seal() {
                    if !self.holds_anchor(&text, &kever, anchor)? {
                        return Ok(None);
                    }
                } else if let Some(sequence_number) = arguments.sequence_floor()
                    && (kever.sequence_number() < sequence_number || !self.fully_witnessed(&text, &kever)?)
                {
                    return Ok(None);
                }
                let from = arguments.first_seen_floor().unwrap_or(0);
                let events = self.first_seen_from(&text, from)?;
                let delegator = match kever.delegator() {
                    Some(delegator) => self.first_seen_from(&qb64(delegator)?, 0)?,
                    None => Vec::new(),
                };
                Ok(Some(Answer::Replay {
                    identifier: identifier.clone(),
                    events,
                    delegator,
                }))
            }
            "ksn" => {
                if !self.fully_witnessed(&text, &kever)? {
                    return Ok(None);
                }
                Ok(Some(Answer::KeyState(Box::new(kever.state()?))))
            }
            _ => Ok(Some(Answer::Mailbox {
                identifier: identifier.clone(),
                topics: arguments.mailbox_topics().cloned(),
            })),
        }
    }

    /// keripy's `fullyWitnessed` of the latest event: its witness signatures meet the witness
    /// threshold in force.
    fn fully_witnessed(&self, identifier: &str, kever: &Kever) -> Result<bool, KelError> {
        let latest = self
            .store
            .event(identifier, kever.sequence_number())
            .map_err(KelError::store)?;
        Ok(witnessed(latest.as_ref(), kever))
    }

    /// keripy's `fetchAllSealingEventByEventSeal`: whether a fully witnessed event of the
    /// identifier, superseded or not, anchors `anchor`, which must be an event seal.
    fn holds_anchor(&self, identifier: &str, kever: &Kever, anchor: &Sad) -> Result<bool, KelError> {
        let Some(seal) = EventSeal::from_sad(anchor) else {
            return Ok(false);
        };
        let holds = |logged: &LoggedEvent| logged.anchors(&seal) && witnessed(Some(logged), kever);
        if self
            .store
            .find_event(identifier, &mut |logged| holds(logged))
            .map_err(KelError::store)?
            .is_some()
        {
            return Ok(true);
        }
        Ok(self
            .store
            .superseded(identifier)
            .map_err(KelError::store)?
            .iter()
            .any(holds))
    }

    /// Every event of the identifier first seen at or after `from`, superseded ones included, in
    /// the order first seen, keripy's `clonePreIter`.
    fn first_seen_from(&self, identifier: &str, from: u128) -> Result<Vec<LoggedEvent>, KelError> {
        let mut events: Vec<LoggedEvent> = self
            .store
            .events(identifier)
            .map_err(KelError::store)?
            .into_iter()
            .map(|(_, logged)| logged)
            .chain(self.store.superseded(identifier).map_err(KelError::store)?)
            .filter(|logged| logged.first_seen() >= from)
            .collect();
        events.sort_by_key(LoggedEvent::first_seen);
        Ok(events)
    }

    /// keripy's `processQueryNotFound`: answers each waiting query the log can answer now, and
    /// drops one it refuses for any other reason.
    pub(crate) fn retry_queries(&mut self) -> Result<(), KelError> {
        let waiting = self.store.escrowed_queries().map_err(KelError::store)?;
        for (requester, said, escrowed) in waiting {
            let decided = QueryMessage::from_serialized(escrowed.query.clone())
                .map_err(KelError::event)
                .and_then(|query| self.decide_query(&query));
            match decided {
                Ok(None) => continue,
                Ok(Some(answer)) => self.answers.push(Answered {
                    query: escrowed.query,
                    requester: escrowed.requester,
                    answer,
                }),
                Err(error @ KelError::Store { .. }) => return Err(error),
                Err(_) => {}
            }
            self.store
                .remove_escrowed_query(&requester, &said)
                .map_err(KelError::store)?;
        }
        Ok(())
    }

    /// Takes the answers given since the last call, in the order given.
    pub fn take_answers(&mut self) -> Vec<Answered> {
        std::mem::take(&mut self.answers)
    }

    /// Returns how many queries are waiting.
    ///
    /// # Errors
    ///
    /// Returns [`KelError::Store`] when the store fails.
    pub fn escrowed_queries(&self) -> Result<usize, KelError> {
        Ok(self.store.escrowed_queries().map_err(KelError::store)?.len())
    }
}

/// Whether `logged` is fully witnessed against the witness threshold in force.
fn witnessed(logged: Option<&LoggedEvent>, kever: &Kever) -> bool {
    let threshold = usize::try_from(kever.witness_threshold()).unwrap_or(usize::MAX);
    logged.is_some_and(|logged| logged.witness_signatures().len() >= threshold)
}

fn qb64(identifier: &IdentifierPrefix) -> Result<String, KelError> {
    identifier.qb64().map_err(KelError::prefix)
}
