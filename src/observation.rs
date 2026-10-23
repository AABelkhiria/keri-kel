//! Watcher registrations: which identifiers a controller asks a watcher to observe.
//!
//! A `/watcher/{watcher}/add` reply is a controller asking a watcher to start observing an
//! identifier, and `/watcher/{watcher}/cut` asks it to stop; the controller is the reply's
//! authority. A [`Kevery`] keeps the latest per controller, watcher and observed identifier, once
//! verified as [`crate::reply`] describes; offered again, the reply kept is not newer than itself
//! and is refused. A registration may carry an OOBI for the observed identifier, which is queued
//! for whoever resolves OOBIs ([`Kevery::oobis`]).
//!
//! This ports keripy's `Kevery.processReplyAddWatched` and `updateWatched`
//! (`src/keri/core/eventing.py`). Which watcher a registration is meant for is the application's
//! concern: like keripy, every registration that verifies is kept.

use keri_protocol::event::reply::route::{RouteAction, WatcherObservation};
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::IdentifierPrefix;

use crate::error::{Escrow, KelError};
use crate::kevery::{Kevery, Processed};
use crate::reply::{KeptReply, OfferedReply, Reoffer, Verdict};
use crate::store::Store;

/// An observation kept: whether the watcher is asked to observe, and the reply that asked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationRecord {
    enabled: bool,
    kept: KeptReply,
}

impl ObservationRecord {
    /// Returns whether observation is asked for (`add`) rather than stopped (`cut`).
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the reply that asked, with what decides whether a later one replaces it.
    #[must_use]
    pub const fn kept(&self) -> &KeptReply {
        &self.kept
    }
}

impl<S: Store> Kevery<S> {
    /// keripy's `processReplyAddWatched`.
    pub(crate) fn consider_observation(
        &mut self,
        offered: OfferedReply<'_>,
        watcher: &IdentifierPrefix,
        action: RouteAction,
        observation: &WatcherObservation,
        now: &Timestamp,
    ) -> Result<Processed, KelError> {
        let controller = qb64(observation.controller())?;
        let watcher = qb64(watcher)?;
        let observed = qb64(observation.observed())?;
        let earlier = self
            .store
            .observation(&controller, &watcher, &observed)
            .map_err(KelError::store)?;
        let verdict = self.verify_reply(
            offered,
            observation.controller(),
            earlier.as_ref().map(ObservationRecord::kept),
            Reoffer::Stale,
            now,
        )?;
        let Verdict::Accepted(kept) = verdict else {
            return Ok(Processed::Escrowed(Escrow::UnverifiedReply));
        };
        if let Some(oobi) = observation.oobi_url() {
            self.store.hold_oobi(oobi).map_err(KelError::store)?;
        }
        let record = ObservationRecord {
            enabled: action == RouteAction::Add,
            kept,
        };
        self.store
            .put_observation(&controller, &watcher, &observed, record)
            .map_err(KelError::store)?;
        Ok(Processed::ObservationAccepted)
    }

    /// Returns the observation kept for `controller`, `watcher` and `observed`.
    ///
    /// # Errors
    ///
    /// Returns [`KelError::Prefix`] for an identifier that cannot be written as qb64, and
    /// [`KelError::Store`] when the store fails.
    pub fn observation(
        &self,
        controller: &IdentifierPrefix,
        watcher: &IdentifierPrefix,
        observed: &IdentifierPrefix,
    ) -> Result<Option<ObservationRecord>, KelError> {
        self.store
            .observation(&qb64(controller)?, &qb64(watcher)?, &qb64(observed)?)
            .map_err(KelError::store)
    }

    /// Returns every observation kept for `watcher`, with the controller that asked for it and the
    /// observed identifier.
    ///
    /// # Errors
    ///
    /// Returns [`KelError::Prefix`] for an identifier that cannot be written or read as qb64, and
    /// [`KelError::Store`] when the store fails.
    pub fn observations(
        &self,
        watcher: &IdentifierPrefix,
    ) -> Result<Vec<(IdentifierPrefix, IdentifierPrefix, ObservationRecord)>, KelError> {
        self.store
            .observations(&qb64(watcher)?)
            .map_err(KelError::store)?
            .into_iter()
            .map(|(controller, observed, record)| {
                Ok((
                    IdentifierPrefix::from_qb64(&controller).map_err(KelError::prefix)?,
                    IdentifierPrefix::from_qb64(&observed).map_err(KelError::prefix)?,
                    record,
                ))
            })
            .collect()
    }

    /// Returns the OOBIs registrations queued for resolution, keripy's `oobis` table.
    ///
    /// # Errors
    ///
    /// Returns [`KelError::Store`] when the store fails.
    pub fn oobis(&self) -> Result<Vec<String>, KelError> {
        self.store.oobis().map_err(KelError::store)
    }
}

fn qb64(identifier: &IdentifierPrefix) -> Result<String, KelError> {
    identifier.qb64().map_err(KelError::prefix)
}
