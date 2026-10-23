//! Adjudicating an identifier's key state against what its watchers report.
//!
//! An identifier is observed by a set of watchers, each of which reports the key state it holds in
//! a key state notice. [`adjudicate`] compares the latest report of each watcher with the local
//! state and decides, in this order:
//!
//! - any watcher reporting another event at the local sequence number is [`Adjudication::Duplicitous`];
//! - watchers ahead of the local state that report different events are duplicitous too; watchers
//!   ahead that agree, at least `threshold` of them, are an [`Adjudication::Update`] the local log
//!   can be brought up to from any of them; fewer than `threshold` decide nothing,
//!   [`Adjudication::Undecided`], even when other watchers lag;
//! - watchers behind the local state are [`Adjudication::Lagging`];
//! - otherwise the reports are [`Adjudication::Consistent`], even when no watcher has reported
//!   yet.
//!
//! The threshold defaults to every watcher, silent ones included; zero means the same.
//!
//! This ports keripy's `Adjudicator.adjudicate` and `diffState` (`src/keri/app/watching.py`), using
//! keri-protocol's port of `diffState`. keripy reads the watchers from its observation records and
//! emits a cue; here the caller names the watchers, and the decision is returned.

use keri_protocol::event::key_state::{KeyStateRecord, StateComparison, StateDifference, compare};
use keri_protocol::prefix::IdentifierPrefix;

use crate::error::KelError;
use crate::kevery::Kevery;
use crate::store::Store;

/// One watcher's latest report compared with the local state, keripy's `DiffState`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatcherReport {
    watcher: IdentifierPrefix,
    difference: StateDifference,
}

impl WatcherReport {
    /// Returns the watcher.
    #[must_use]
    pub const fn watcher(&self) -> &IdentifierPrefix {
        &self.watcher
    }

    /// Returns how its report relates to the local state, with the reported sequence number and
    /// latest event.
    #[must_use]
    pub const fn difference(&self) -> &StateDifference {
        &self.difference
    }
}

/// What the watchers' reports say about an identifier's local key state, keripy's adjudication
/// cues.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Adjudication {
    /// Every watcher that reported agrees with the local state, keripy's `keyStateConsistent`.
    Consistent(Vec<WatcherReport>),
    /// Some watchers report an earlier state than the local one, keripy's `keyStateLagging`.
    Lagging(Vec<WatcherReport>),
    /// Enough watchers agree on a later state, keripy's `keyStateUpdate`: the local log can be
    /// brought up to `sequence_number` from any of them.
    Update {
        /// The later state's sequence number.
        sequence_number: u128,
        /// The watchers ahead.
        ahead: Vec<WatcherReport>,
    },
    /// Watchers report events that contradict the local log or each other, keripy's
    /// `keyStateDuplicitous`; the local state stands.
    Duplicitous(Vec<WatcherReport>),
    /// Watchers ahead agree, but fewer than the threshold; keripy emits no cue.
    Undecided,
}

/// Adjudicates the `local` state against `reports`, each watcher with its latest reported state,
/// or `None` when it has reported none, keripy's `Adjudicator.adjudicate`.
///
/// # Errors
///
/// Returns [`KelError::ThresholdAboveWatchers`] when `threshold` exceeds the watchers, and
/// [`KelError::IdentifierMismatch`] for a report about another identifier.
pub fn adjudicate(
    local: &KeyStateRecord,
    reports: &[(IdentifierPrefix, Option<KeyStateRecord>)],
    threshold: Option<usize>,
) -> Result<Adjudication, KelError> {
    let watchers = reports.len();
    let threshold = threshold.filter(|threshold| *threshold > 0).unwrap_or(watchers);
    if threshold > watchers {
        return Err(KelError::ThresholdAboveWatchers { threshold, watchers });
    }
    let mut compared = Vec::new();
    for (watcher, reported) in reports {
        let Some(reported) = reported else {
            continue;
        };
        let difference = compare(local, reported).map_err(|_| KelError::IdentifierMismatch)?;
        compared.push(WatcherReport {
            watcher: watcher.clone(),
            difference,
        });
    }
    let with = |comparison: StateComparison| -> Vec<WatcherReport> {
        compared
            .iter()
            .filter(|report| report.difference.comparison() == comparison)
            .cloned()
            .collect()
    };
    let duplicitous = with(StateComparison::Duplicitous);
    if !duplicitous.is_empty() {
        return Ok(Adjudication::Duplicitous(duplicitous));
    }
    let ahead = with(StateComparison::Ahead);
    if let Some(first) = ahead.first() {
        let said = first.difference.said();
        if ahead.iter().any(|report| report.difference.said() != said) {
            return Ok(Adjudication::Duplicitous(ahead));
        }
        if ahead.len() >= threshold {
            return Ok(Adjudication::Update {
                sequence_number: first.difference.sequence_number(),
                ahead,
            });
        }
        return Ok(Adjudication::Undecided);
    }
    let behind = with(StateComparison::Behind);
    if !behind.is_empty() {
        return Ok(Adjudication::Lagging(behind));
    }
    Ok(Adjudication::Consistent(compared))
}

impl<S: Store> Kevery<S> {
    /// Adjudicates an identifier's local key state against the key state notices kept from each
    /// of `watchers`; see [`adjudicate`].
    ///
    /// # Errors
    ///
    /// Returns [`KelError::IdentifierUnknown`] when no inception of `identifier` is accepted, the
    /// errors of [`adjudicate`], and [`KelError::Store`] when the store fails.
    pub fn adjudicate(
        &self,
        identifier: &IdentifierPrefix,
        watchers: &[IdentifierPrefix],
        threshold: Option<usize>,
    ) -> Result<Adjudication, KelError> {
        let local = self.kever(identifier)?.ok_or(KelError::IdentifierUnknown)?.state()?;
        let reports = watchers
            .iter()
            .map(|watcher| {
                let notice = self.key_state_notice(identifier, watcher)?;
                Ok((watcher.clone(), notice.map(|notice| notice.state().clone())))
            })
            .collect::<Result<Vec<_>, KelError>>()?;
        adjudicate(&local, &reports, threshold)
    }
}
