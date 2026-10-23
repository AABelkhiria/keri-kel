//! Where a [`Kevery`](crate::Kevery) keeps what it holds.
//!
//! Validation needs four kinds of state, each behind its own trait:
//!
//! - [`KelStore`]: each identifier's key state, its accepted events by sequence number, and the
//!   events recovery rotations superseded;
//! - [`EscrowStore`]: events that cannot be decided yet, keyed by identifier and SAID, with the
//!   order they entered their escrow;
//! - [`ReceiptStore`]: receipt signatures waiting for the events they name;
//! - [`ReplyStore`]: the key state notices kept, per identifier and reporting source, and replies
//!   waiting for their signer's establishment event or more signatures.
//!
//! [`Store`] is all four together, which is what a `Kevery` takes. [`MemoryStore`] keeps
//! everything in memory and is what [`Kevery::new`](crate::Kevery::new) uses.
//!
//! Every method reads or writes owned values and may fail with a [`StoreError`], so that a store
//! can live in a database. The validation rules stay in `Kevery`: a store decides nothing, it only
//! keeps what it is given and returns it. A `Kevery` writes as it goes, several writes for one
//! message; a store that needs a message's writes to land together has to group them itself.

use core::fmt;
use std::collections::BTreeMap;
use std::error::Error;

use keri_protocol::event::timestamp::Timestamp;

use crate::error::Escrow;
use crate::kever::Kever;
use crate::kevery::{EscrowedEvent, LoggedEvent, WaitingReceipt};
use crate::notice::{EscrowedReply, KeyStateNotice};

/// Why a store could not read or write.
#[derive(Debug)]
pub struct StoreError {
    source: Box<dyn Error + Send + Sync>,
}

impl StoreError {
    /// Wraps the failure of the store's own backend.
    pub fn new(source: impl Into<Box<dyn Error + Send + Sync>>) -> Self {
        Self { source: source.into() }
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("store could not read or write")
    }
}

impl Error for StoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Each identifier's key state and events, keripy's `kels`, `evts`, `sigs`, `wigs`, `rcts`,
/// `vrcs`, `aess` and `states` tables. Identifiers are qb64 text.
pub trait KelStore {
    /// Returns an identifier's key state, once its inception is accepted.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the store cannot be read.
    fn kever(&self, identifier: &str) -> Result<Option<Kever>, StoreError>;

    /// Returns an identifier's accepted event at `sequence_number`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the store cannot be read.
    fn event(&self, identifier: &str, sequence_number: u128) -> Result<Option<LoggedEvent>, StoreError>;

    /// Returns the earliest accepted event of an identifier, by sequence number, for which
    /// `matches` holds, with its sequence number.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the store cannot be read.
    fn find_event(
        &self,
        identifier: &str,
        matches: &mut dyn FnMut(&LoggedEvent) -> bool,
    ) -> Result<Option<(u128, LoggedEvent)>, StoreError>;

    /// Returns the events of an identifier that recovery rotations superseded, in the order they
    /// were superseded.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the store cannot be read.
    fn superseded(&self, identifier: &str) -> Result<Vec<LoggedEvent>, StoreError>;

    /// Accepts `event` at `sequence_number` with the key state it puts in force. Events already
    /// accepted at that sequence number or after it, which a recovery rotation supersedes, move to
    /// the superseded events.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the store cannot be written.
    fn accept(
        &mut self,
        identifier: &str,
        kever: Kever,
        sequence_number: u128,
        event: LoggedEvent,
    ) -> Result<(), StoreError>;

    /// Replaces an accepted event with the same event holding more signatures or receipts.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the store cannot be written.
    fn update_event(&mut self, identifier: &str, sequence_number: u128, event: LoggedEvent) -> Result<(), StoreError>;
}

/// Events waiting to be decided, keripy's `ooes`, `pses`, `pwes`, `pdes`, `udes` and `ldes`
/// tables. Each entry is keyed by the event's identifier and SAID, both qb64 text.
pub trait EscrowStore {
    /// Returns the escrowed event with this identifier and SAID.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the store cannot be read.
    fn escrowed(&self, identifier: &str, said: &str) -> Result<Option<EscrowedEvent>, StoreError>;

    /// Returns every event escrowed for `reason`, with its identifier and SAID, in any order.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the store cannot be read.
    fn escrowed_for(&self, reason: Escrow) -> Result<Vec<(String, String, EscrowedEvent)>, StoreError>;

    /// Escrows an event, replacing any entry with the same identifier and SAID.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the store cannot be written.
    fn put_escrowed(&mut self, identifier: &str, said: &str, event: EscrowedEvent) -> Result<(), StoreError>;

    /// Removes an escrowed event, if there is one.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the store cannot be written.
    fn remove_escrowed(&mut self, identifier: &str, said: &str) -> Result<(), StoreError>;

    /// Returns a number larger than every one returned before, which orders entries by when they
    /// entered their escrow.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the store cannot be written.
    fn next_arrival(&mut self) -> Result<u64, StoreError>;

    /// Returns how many events are escrowed, for any reason.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the store cannot be read.
    fn escrowed_count(&self) -> Result<usize, StoreError>;

    /// Removes every escrowed event first escrowed before `cutoff`, and returns how many.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the store cannot be written.
    fn expire_escrowed(&mut self, cutoff: &Timestamp) -> Result<usize, StoreError>;
}

/// Receipt signatures waiting for the events they name, keripy's `uwes`, `ures` and `vres`
/// tables.
pub trait ReceiptStore {
    /// Keeps a waiting receipt signature.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the store cannot be written.
    fn hold_receipt(&mut self, receipt: WaitingReceipt) -> Result<(), StoreError>;

    /// Removes and returns every waiting receipt signature, in the order they were held.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the store cannot be written.
    fn take_receipts(&mut self) -> Result<Vec<WaitingReceipt>, StoreError>;

    /// Returns how many receipt signatures are waiting.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the store cannot be read.
    fn receipt_count(&self) -> Result<usize, StoreError>;

    /// Removes every waiting receipt signature received before `cutoff`, and returns how many.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the store cannot be written.
    fn expire_receipts(&mut self, cutoff: &Timestamp) -> Result<usize, StoreError>;
}

/// Key state notices kept and replies waiting, keripy's `knas`, `ksns`, `kdts`, `rpys`, `sdts`,
/// `ssgs` and `rpes` tables. Identifiers, sources and SAIDs are qb64 text.
pub trait ReplyStore {
    /// Returns the notice kept from `source` about `identifier`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the store cannot be read.
    fn key_state_notice(&self, identifier: &str, source: &str) -> Result<Option<KeyStateNotice>, StoreError>;

    /// Returns every notice kept about `identifier`, with its source, in any order.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the store cannot be read.
    fn key_state_notices(&self, identifier: &str) -> Result<Vec<(String, KeyStateNotice)>, StoreError>;

    /// Keeps a notice from `source` about `identifier`, replacing any earlier one.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the store cannot be written.
    fn put_key_state_notice(
        &mut self,
        identifier: &str,
        source: &str,
        notice: KeyStateNotice,
    ) -> Result<(), StoreError>;

    /// Returns the waiting reply with this SAID.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the store cannot be read.
    fn escrowed_reply(&self, said: &str) -> Result<Option<EscrowedReply>, StoreError>;

    /// Returns every waiting reply with its SAID, in any order.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the store cannot be read.
    fn escrowed_replies(&self) -> Result<Vec<(String, EscrowedReply)>, StoreError>;

    /// Keeps a waiting reply, replacing any with the same SAID.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the store cannot be written.
    fn put_escrowed_reply(&mut self, said: &str, reply: EscrowedReply) -> Result<(), StoreError>;

    /// Removes a waiting reply, if there is one.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the store cannot be written.
    fn remove_escrowed_reply(&mut self, said: &str) -> Result<(), StoreError>;

    /// Removes every waiting reply first escrowed before `cutoff`, and returns how many.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the store cannot be written.
    fn expire_escrowed_replies(&mut self, cutoff: &Timestamp) -> Result<usize, StoreError>;
}

/// Everything a [`Kevery`](crate::Kevery) keeps.
pub trait Store: KelStore + EscrowStore + ReceiptStore + ReplyStore {}

impl<T: KelStore + EscrowStore + ReceiptStore + ReplyStore> Store for T {}

/// One identifier's key state, accepted events, and the events recovery rotations superseded.
#[derive(Clone, Debug)]
struct Log {
    kever: Kever,
    events: BTreeMap<u128, LoggedEvent>,
    superseded: Vec<LoggedEvent>,
}

/// A [`Store`] in memory, which never fails.
#[derive(Clone, Debug, Default)]
pub struct MemoryStore {
    logs: BTreeMap<String, Log>,
    escrowed: BTreeMap<(String, String), EscrowedEvent>,
    arrivals: u64,
    receipts: Vec<WaitingReceipt>,
    notices: BTreeMap<(String, String), KeyStateNotice>,
    replies: BTreeMap<String, EscrowedReply>,
}

impl MemoryStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl KelStore for MemoryStore {
    fn kever(&self, identifier: &str) -> Result<Option<Kever>, StoreError> {
        Ok(self.logs.get(identifier).map(|log| log.kever.clone()))
    }

    fn event(&self, identifier: &str, sequence_number: u128) -> Result<Option<LoggedEvent>, StoreError> {
        Ok(self
            .logs
            .get(identifier)
            .and_then(|log| log.events.get(&sequence_number))
            .cloned())
    }

    fn find_event(
        &self,
        identifier: &str,
        matches: &mut dyn FnMut(&LoggedEvent) -> bool,
    ) -> Result<Option<(u128, LoggedEvent)>, StoreError> {
        Ok(self.logs.get(identifier).and_then(|log| {
            log.events
                .iter()
                .find(|(_, event)| matches(event))
                .map(|(sequence_number, event)| (*sequence_number, event.clone()))
        }))
    }

    fn superseded(&self, identifier: &str) -> Result<Vec<LoggedEvent>, StoreError> {
        Ok(self
            .logs
            .get(identifier)
            .map(|log| log.superseded.clone())
            .unwrap_or_default())
    }

    fn accept(
        &mut self,
        identifier: &str,
        kever: Kever,
        sequence_number: u128,
        event: LoggedEvent,
    ) -> Result<(), StoreError> {
        let log = self.logs.entry(identifier.to_owned()).or_insert_with(|| Log {
            kever: kever.clone(),
            events: BTreeMap::new(),
            superseded: Vec::new(),
        });
        log.kever = kever;
        let superseded = log.events.split_off(&sequence_number);
        log.superseded.extend(superseded.into_values());
        log.events.insert(sequence_number, event);
        Ok(())
    }

    fn update_event(&mut self, identifier: &str, sequence_number: u128, event: LoggedEvent) -> Result<(), StoreError> {
        if let Some(stored) = self
            .logs
            .get_mut(identifier)
            .and_then(|log| log.events.get_mut(&sequence_number))
        {
            *stored = event;
        }
        Ok(())
    }
}

impl EscrowStore for MemoryStore {
    fn escrowed(&self, identifier: &str, said: &str) -> Result<Option<EscrowedEvent>, StoreError> {
        Ok(self.escrowed.get(&(identifier.to_owned(), said.to_owned())).cloned())
    }

    fn escrowed_for(&self, reason: Escrow) -> Result<Vec<(String, String, EscrowedEvent)>, StoreError> {
        Ok(self
            .escrowed
            .iter()
            .filter(|(_, escrowed)| escrowed.reason() == reason)
            .map(|((identifier, said), escrowed)| (identifier.clone(), said.clone(), escrowed.clone()))
            .collect())
    }

    fn put_escrowed(&mut self, identifier: &str, said: &str, event: EscrowedEvent) -> Result<(), StoreError> {
        self.escrowed.insert((identifier.to_owned(), said.to_owned()), event);
        Ok(())
    }

    fn remove_escrowed(&mut self, identifier: &str, said: &str) -> Result<(), StoreError> {
        self.escrowed.remove(&(identifier.to_owned(), said.to_owned()));
        Ok(())
    }

    fn next_arrival(&mut self) -> Result<u64, StoreError> {
        let arrival = self.arrivals;
        self.arrivals = self.arrivals.saturating_add(1);
        Ok(arrival)
    }

    fn escrowed_count(&self) -> Result<usize, StoreError> {
        Ok(self.escrowed.len())
    }

    fn expire_escrowed(&mut self, cutoff: &Timestamp) -> Result<usize, StoreError> {
        let before = self.escrowed.len();
        self.escrowed.retain(|_, escrowed| escrowed.since() >= cutoff);
        Ok(before - self.escrowed.len())
    }
}

impl ReceiptStore for MemoryStore {
    fn hold_receipt(&mut self, receipt: WaitingReceipt) -> Result<(), StoreError> {
        self.receipts.push(receipt);
        Ok(())
    }

    fn take_receipts(&mut self) -> Result<Vec<WaitingReceipt>, StoreError> {
        Ok(std::mem::take(&mut self.receipts))
    }

    fn receipt_count(&self) -> Result<usize, StoreError> {
        Ok(self.receipts.len())
    }

    fn expire_receipts(&mut self, cutoff: &Timestamp) -> Result<usize, StoreError> {
        let before = self.receipts.len();
        self.receipts.retain(|receipt| receipt.received_at() >= cutoff);
        Ok(before - self.receipts.len())
    }
}

impl ReplyStore for MemoryStore {
    fn key_state_notice(&self, identifier: &str, source: &str) -> Result<Option<KeyStateNotice>, StoreError> {
        Ok(self.notices.get(&(identifier.to_owned(), source.to_owned())).cloned())
    }

    fn key_state_notices(&self, identifier: &str) -> Result<Vec<(String, KeyStateNotice)>, StoreError> {
        Ok(self
            .notices
            .iter()
            .filter(|((reported, _), _)| reported == identifier)
            .map(|((_, source), notice)| (source.clone(), notice.clone()))
            .collect())
    }

    fn put_key_state_notice(
        &mut self,
        identifier: &str,
        source: &str,
        notice: KeyStateNotice,
    ) -> Result<(), StoreError> {
        self.notices.insert((identifier.to_owned(), source.to_owned()), notice);
        Ok(())
    }

    fn escrowed_reply(&self, said: &str) -> Result<Option<EscrowedReply>, StoreError> {
        Ok(self.replies.get(said).cloned())
    }

    fn escrowed_replies(&self) -> Result<Vec<(String, EscrowedReply)>, StoreError> {
        Ok(self
            .replies
            .iter()
            .map(|(said, reply)| (said.clone(), reply.clone()))
            .collect())
    }

    fn put_escrowed_reply(&mut self, said: &str, reply: EscrowedReply) -> Result<(), StoreError> {
        self.replies.insert(said.to_owned(), reply);
        Ok(())
    }

    fn remove_escrowed_reply(&mut self, said: &str) -> Result<(), StoreError> {
        self.replies.remove(said);
        Ok(())
    }

    fn expire_escrowed_replies(&mut self, cutoff: &Timestamp) -> Result<usize, StoreError> {
        let before = self.replies.len();
        self.replies.retain(|_, reply| reply.since() >= cutoff);
        Ok(before - self.replies.len())
    }
}
