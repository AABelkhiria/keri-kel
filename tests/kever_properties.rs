//! Property coverage for key event validation over logs built with keri-protocol's own builders.

use keri_cesr::crypto::digest::{Digest, DigestAlgorithm};
use keri_cesr::crypto::signer::{SignaturePlacement, Signer};
use keri_cesr::crypto::verifier::KeyTransferability;
use keri_kel::{KelError, Kever};
use keri_protocol::attachment::SignedMessageBuilder;
use keri_protocol::event::KeyEvent;
use keri_protocol::event::inception::InceptionBuilder;
use keri_protocol::event::interaction::InteractionBuilder;
use keri_protocol::event::rotation::RotationBuilder;
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::PrefixDerivation;
use keri_protocol::stream::Message;
use proptest::{prelude::*, test_runner::TestCaseError};

const STAMP: &str = "2021-01-01T00:00:00.000000+00:00";

fn fail<T, E: core::fmt::Display>(result: Result<T, E>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

fn signer(seed: u8) -> Result<Signer, TestCaseError> {
    fail(Signer::from_seed(&[seed; 32], KeyTransferability::Transferable))
}

fn commitment(signer: &Signer) -> Result<Digest, TestCaseError> {
    Ok(Digest::derive(
        DigestAlgorithm::Blake3_256,
        &fail(signer.verifier().qb64_bytes())?,
    ))
}

/// Signs `event` with `signer` at index zero and parses it back as a received message.
fn signed(event: &KeyEvent, signer: &Signer) -> Result<Message, TestCaseError> {
    let signature = fail(signer.sign_indexed(event.raw(), SignaturePlacement::both_lists(0)))?;
    let bytes = fail(
        SignedMessageBuilder::new(event.serialized())
            .controller_signatures(vec![signature])
            .build(),
    )?;
    fail(Message::from_bytes(bytes.as_bytes()))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Any sequence of interactions and rotations, each signed by the keys in force and each
    /// rotation revealing the committed next key, is accepted event by event.
    #[test]
    fn a_well_formed_log_is_accepted_event_by_event(rotations in prop::collection::vec(any::<bool>(), 0..10), seed in 1_u8..100) {
        let stamp = fail(Timestamp::parse(STAMP))?;
        let mut current = signer(seed)?;
        let mut next = signer(seed.wrapping_add(100))?;
        let inception = fail(
            InceptionBuilder::new(vec![current.verifier().clone()])
                .next_key_digests(vec![commitment(&next)?])
                .prefix_derivation(PrefixDerivation::Blake3_256)
                .build(),
        )?;
        let mut kever = fail(Kever::incept(&signed(&inception, &current)?, stamp.clone()))?;
        let identifier = inception.identifier().clone();
        let mut prior = inception.said();
        for (offset, rotate) in rotations.iter().enumerate() {
            let sequence_number = u128::try_from(offset).unwrap_or(u128::MAX) + 1;
            let event = if *rotate {
                let after = signer(seed.wrapping_add(150).wrapping_add(u8::try_from(offset).unwrap_or(0)))?;
                let event = fail(
                    RotationBuilder::new(identifier.clone(), prior, sequence_number, vec![next.verifier().clone()])
                        .next_key_digests(vec![commitment(&after)?])
                        .build(),
                )?;
                current = next;
                next = after;
                event
            } else {
                fail(InteractionBuilder::new(identifier.clone(), prior, sequence_number).build())?
            };
            fail(kever.update(&signed(&event, &current)?, stamp.clone()))?;
            prop_assert_eq!(kever.sequence_number(), sequence_number);
            prop_assert_eq!(kever.said(), event.said());
            prior = event.said();
        }
        let state = fail(kever.state())?;
        prop_assert_eq!(state.keys(), [current.verifier().clone()]);
    }

    /// An interaction signed by anyone but the keys in force is refused, and the state does not move.
    #[test]
    fn a_stranger_cannot_extend_the_log(seed in 1_u8..100, stranger in 101_u8..200) {
        let stamp = fail(Timestamp::parse(STAMP))?;
        let controller = signer(seed)?;
        let inception = fail(
            InceptionBuilder::new(vec![controller.verifier().clone()])
                .next_key_digests(vec![commitment(&signer(seed.wrapping_add(1))?)?])
                .prefix_derivation(PrefixDerivation::Blake3_256)
                .build(),
        )?;
        let mut kever = fail(Kever::incept(&signed(&inception, &controller)?, stamp.clone()))?;
        let before = kever.clone();
        let interaction = fail(InteractionBuilder::new(inception.identifier().clone(), inception.said(), 1).build())?;
        let refused = kever.update(&signed(&interaction, &signer(stranger)?)?, stamp);
        prop_assert!(matches!(refused, Err(KelError::NoVerifiedSignatures)));
        prop_assert_eq!(kever, before);
    }

    /// A rotation to keys the prior event did not commit to is refused as partially signed, which
    /// is escrowable, and the state does not move.
    #[test]
    fn a_rotation_must_reveal_the_committed_keys(seed in 1_u8..100, impostor in 101_u8..200) {
        let stamp = fail(Timestamp::parse(STAMP))?;
        let controller = signer(seed)?;
        let inception = fail(
            InceptionBuilder::new(vec![controller.verifier().clone()])
                .next_key_digests(vec![commitment(&signer(seed.wrapping_add(1))?)?])
                .prefix_derivation(PrefixDerivation::Blake3_256)
                .build(),
        )?;
        let mut kever = fail(Kever::incept(&signed(&inception, &controller)?, stamp.clone()))?;
        let before = kever.clone();
        let impostor = signer(impostor)?;
        let rotation = fail(
            RotationBuilder::new(inception.identifier().clone(), inception.said(), 1, vec![impostor.verifier().clone()])
                .next_key_digests(vec![commitment(&controller)?])
                .build(),
        )?;
        let refused = kever.update(&signed(&rotation, &impostor)?, stamp);
        prop_assert!(matches!(&refused, Err(KelError::PriorNextNotSatisfied)));
        prop_assert!(refused.err().and_then(|error| error.escrow()).is_some());
        prop_assert_eq!(kever, before);
    }
}
