//! Where an identifier is served: end role grants and endpoint locations.
//!
//! An end role reply (`/end/role/add` or `/end/role/cut`) is a controller granting or withdrawing a
//! role, such as witness, watcher or mailbox, to an endpoint identifier; the controller is its
//! authority. A location reply (`/loc/scheme`) is an endpoint giving its URL for a scheme; the
//! endpoint is its authority. A [`Kevery`] keeps the latest of each, per controller, role and
//! endpoint, and per endpoint and scheme, once verified as [`crate::reply`] describes.
//!
//! Offered again, the end role reply kept is accepted again, as keripy's end role handler does,
//! while the location reply kept is not newer than itself and is refused.
//!
//! This ports keripy's `Kevery.processReplyEndRole`, `processReplyLocScheme`, `updateEnd` and
//! `updateLoc` (`src/keri/core/eventing.py`). The role, the scheme, and a URL's scheme are checked
//! by keri-protocol's reading of the route.

use keri_protocol::event::reply::route::{EndRole, LocationScheme, Role, RouteAction, Scheme};
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::IdentifierPrefix;

use crate::error::{Escrow, KelError};
use crate::kevery::{Kevery, Processed};
use crate::reply::{KeptReply, OfferedReply, Reoffer, Verdict};
use crate::store::Store;

/// An end role kept: whether the role is granted, and the reply that said so.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndRoleRecord {
    pub(crate) allowed: bool,
    pub(crate) kept: KeptReply,
}

impl EndRoleRecord {
    /// Returns whether the role is granted (`/end/role/add`) rather than withdrawn
    /// (`/end/role/cut`).
    #[must_use]
    pub const fn allowed(&self) -> bool {
        self.allowed
    }

    /// Returns the reply that said so, with what decides whether a later one replaces it.
    #[must_use]
    pub const fn kept(&self) -> &KeptReply {
        &self.kept
    }
}

/// A location kept: the endpoint's URL for a scheme, and the reply that gave it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocationRecord {
    pub(crate) url: String,
    pub(crate) kept: KeptReply,
}

impl LocationRecord {
    /// Returns the URL.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Returns the reply that gave it, with what decides whether a later one replaces it.
    #[must_use]
    pub const fn kept(&self) -> &KeptReply {
        &self.kept
    }
}

impl<S: Store> Kevery<S> {
    /// keripy's `processReplyEndRole`.
    pub(crate) fn consider_end_role(
        &mut self,
        offered: OfferedReply<'_>,
        action: RouteAction,
        end_role: &EndRole,
        now: &Timestamp,
    ) -> Result<Processed, KelError> {
        let controller = qb64(end_role.controller())?;
        let endpoint = qb64(end_role.endpoint())?;
        let role = end_role.role().as_str();
        let earlier = self
            .store
            .end_role(&controller, role, &endpoint)
            .map_err(KelError::store)?;
        let verdict = self.verify_reply(
            offered,
            end_role.controller(),
            earlier.as_ref().map(EndRoleRecord::kept),
            Reoffer::Fresh,
            now,
        )?;
        let Verdict::Accepted(kept) = verdict else {
            return Ok(Processed::Escrowed(Escrow::UnverifiedReply));
        };
        let record = EndRoleRecord {
            allowed: action == RouteAction::Add,
            kept,
        };
        self.store
            .put_end_role(&controller, role, &endpoint, record)
            .map_err(KelError::store)?;
        Ok(Processed::EndRoleAccepted)
    }

    /// keripy's `processReplyLocScheme`.
    pub(crate) fn consider_location(
        &mut self,
        offered: OfferedReply<'_>,
        location: &LocationScheme,
        now: &Timestamp,
    ) -> Result<Processed, KelError> {
        let endpoint = qb64(location.endpoint())?;
        let scheme = location.scheme().as_str();
        let earlier = self.store.location(&endpoint, scheme).map_err(KelError::store)?;
        let verdict = self.verify_reply(
            offered,
            location.endpoint(),
            earlier.as_ref().map(LocationRecord::kept),
            Reoffer::Stale,
            now,
        )?;
        let Verdict::Accepted(kept) = verdict else {
            return Ok(Processed::Escrowed(Escrow::UnverifiedReply));
        };
        let record = LocationRecord {
            url: location.url().to_owned(),
            kept,
        };
        self.store
            .put_location(&endpoint, scheme, record)
            .map_err(KelError::store)?;
        Ok(Processed::LocationAccepted)
    }

    /// Returns the end role kept for `controller`, `role` and `endpoint`.
    ///
    /// # Errors
    ///
    /// Returns [`KelError::Prefix`] for an identifier that cannot be written as qb64, and
    /// [`KelError::Store`] when the store fails.
    pub fn end_role(
        &self,
        controller: &IdentifierPrefix,
        role: Role,
        endpoint: &IdentifierPrefix,
    ) -> Result<Option<EndRoleRecord>, KelError> {
        self.store
            .end_role(&qb64(controller)?, role.as_str(), &qb64(endpoint)?)
            .map_err(KelError::store)
    }

    /// Returns every end role kept for `controller`, with its role and endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`KelError::Prefix`] for an identifier that cannot be written or read as qb64,
    /// [`KelError::Store`] when the store fails, and [`KelError::Record`] for a stored role that
    /// cannot be read back.
    pub fn end_roles(
        &self,
        controller: &IdentifierPrefix,
    ) -> Result<Vec<(Role, IdentifierPrefix, EndRoleRecord)>, KelError> {
        self.store
            .end_roles(&qb64(controller)?)
            .map_err(KelError::store)?
            .into_iter()
            .map(|(role, endpoint, record)| {
                let role = role.parse::<Role>().map_err(KelError::record)?;
                let endpoint = IdentifierPrefix::from_qb64(&endpoint).map_err(KelError::prefix)?;
                Ok((role, endpoint, record))
            })
            .collect()
    }

    /// Returns the location kept for `endpoint` and `scheme`.
    ///
    /// # Errors
    ///
    /// Returns [`KelError::Prefix`] for an identifier that cannot be written as qb64, and
    /// [`KelError::Store`] when the store fails.
    pub fn location(&self, endpoint: &IdentifierPrefix, scheme: Scheme) -> Result<Option<LocationRecord>, KelError> {
        self.store
            .location(&qb64(endpoint)?, scheme.as_str())
            .map_err(KelError::store)
    }

    /// Returns every location kept for `endpoint`, with its scheme.
    ///
    /// # Errors
    ///
    /// Returns [`KelError::Prefix`] for an identifier that cannot be written as qb64,
    /// [`KelError::Store`] when the store fails, and [`KelError::Record`] for a stored scheme that
    /// cannot be read back.
    pub fn locations(&self, endpoint: &IdentifierPrefix) -> Result<Vec<(Scheme, LocationRecord)>, KelError> {
        self.store
            .locations(&qb64(endpoint)?)
            .map_err(KelError::store)?
            .into_iter()
            .map(|(scheme, record)| Ok((scheme.parse::<Scheme>().map_err(KelError::record)?, record)))
            .collect()
    }
}

fn qb64(identifier: &IdentifierPrefix) -> Result<String, KelError> {
    identifier.qb64().map_err(KelError::prefix)
}
