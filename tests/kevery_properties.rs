//! Property coverage for log processing: what arrives in any order ends in the same place.

use keri_cesr::crypto::digest::{Digest, DigestAlgorithm};
use keri_cesr::crypto::signer::{SignaturePlacement, Signer};
use keri_cesr::crypto::verifier::KeyTransferability;
use keri_kel::{Kevery, Processed};
use keri_protocol::attachment::SignedMessageBuilder;
use keri_protocol::event::inception::InceptionBuilder;
use keri_protocol::event::receipt::ReceiptBuilder;
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::{IdentifierPrefix, PrefixDerivation};
use keri_protocol::stream::Message;
use proptest::{prelude::*, test_runner::TestCaseError};

const STAMP: &str = "2021-01-01T00:00:00.000000+00:00";
const WITNESSES: usize = 4;

fn fail<T, E: core::fmt::Display>(result: Result<T, E>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

fn signer(seed: u8, transferability: KeyTransferability) -> Result<Signer, TestCaseError> {
    fail(Signer::from_seed(&[seed; 32], transferability))
}

/// A witnessed inception carrying no witness signature, and one receipt per witness.
fn messages(threshold: u32) -> Result<(IdentifierPrefix, Message, Vec<Message>), TestCaseError> {
    let controller = signer(1, KeyTransferability::Transferable)?;
    let next = signer(2, KeyTransferability::Transferable)?;
    let witnesses: Vec<Signer> = (0..WITNESSES)
        .map(|index| {
            signer(
                10 + u8::try_from(index).unwrap_or(0),
                KeyTransferability::NonTransferable,
            )
        })
        .collect::<Result<_, _>>()?;
    let prefixes: Vec<IdentifierPrefix> = witnesses
        .iter()
        .map(|witness| fail(witness.verifier().qb64()).and_then(|text| fail(IdentifierPrefix::from_qb64(&text))))
        .collect::<Result<_, _>>()?;
    let inception = fail(
        InceptionBuilder::new(vec![controller.verifier().clone()])
            .next_key_digests(vec![Digest::derive(
                DigestAlgorithm::Blake3_256,
                &fail(next.verifier().qb64_bytes())?,
            )])
            .witnesses(prefixes)
            .witness_threshold(threshold)
            .prefix_derivation(PrefixDerivation::Blake3_256)
            .build(),
    )?;
    let signature = fail(controller.sign_indexed(inception.raw(), SignaturePlacement::both_lists(0)))?;
    let event = fail(
        SignedMessageBuilder::new(inception.serialized())
            .controller_signatures(vec![signature])
            .build(),
    )?;
    let receipt = fail(ReceiptBuilder::new(inception.identifier().clone(), 0, inception.said()).build())?;
    let mut receipts = Vec::new();
    for (index, witness) in witnesses.iter().enumerate() {
        let placement = SignaturePlacement::both_lists(u32::try_from(index).unwrap_or(0));
        let signature = fail(witness.sign_indexed(inception.raw(), placement))?;
        let bytes = fail(
            SignedMessageBuilder::new(receipt.serialized())
                .witness_signatures(vec![signature])
                .build(),
        )?;
        receipts.push(fail(Message::from_bytes(bytes.as_bytes()))?);
    }
    Ok((
        inception.identifier().clone(),
        fail(Message::from_bytes(event.as_bytes()))?,
        receipts,
    ))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Whether the receipts arrive before the event, after it, or interleaved, once escrows are
    /// processed the event is accepted exactly when enough witnesses receipted it, and it holds
    /// every receipted witness signature.
    #[test]
    fn arrival_order_does_not_change_the_outcome(
        threshold in 1_u32..=4,
        receipted in prop::collection::btree_set(0_usize..WITNESSES, 0..=WITNESSES),
        event_position in 0_usize..=WITNESSES,
    ) {
        let now = fail(Timestamp::parse(STAMP))?;
        let (identifier, event, receipts) = messages(threshold)?;
        let chosen: Vec<&Message> = receipts
            .iter()
            .enumerate()
            .filter(|(index, _)| receipted.contains(index))
            .map(|(_, receipt)| receipt)
            .collect();
        let position = event_position.min(chosen.len());
        let mut kevery = Kevery::new();
        for (index, receipt) in chosen.iter().enumerate() {
            if index == position {
                fail(kevery.process(&event, &now))?;
                fail(kevery.process_escrows(&now))?;
            }
            fail(kevery.process(receipt, &now))?;
            fail(kevery.process_escrows(&now))?;
        }
        if position == chosen.len() {
            fail(kevery.process(&event, &now))?;
            fail(kevery.process_escrows(&now))?;
        }

        let enough = u32::try_from(receipted.len()).unwrap_or(u32::MAX) >= threshold;
        prop_assert_eq!(fail(kevery.kever(&identifier))?.is_some(), enough);
        if enough {
            let logged = fail(kevery.logged(&identifier, 0))?.ok_or_else(|| TestCaseError::fail("no logged inception"))?;
            prop_assert_eq!(logged.witness_signatures().len(), receipted.len());
            prop_assert_eq!(fail(kevery.escrowed_event_count())?, 0);
        } else {
            prop_assert_eq!(fail(kevery.escrowed_event_count())?, 1);
        }
    }

    /// Offering an accepted event again, any number of times, never changes what is held.
    #[test]
    fn duplicates_are_idempotent(repeats in 1_usize..5) {
        let now = fail(Timestamp::parse(STAMP))?;
        let (identifier, event, receipts) = messages(1)?;
        let mut kevery = Kevery::new();
        for receipt in &receipts {
            fail(kevery.process(receipt, &now))?;
        }
        fail(kevery.process(&event, &now))?;
        fail(kevery.process_escrows(&now))?;
        let before = fail(kevery.logged(&identifier, 0))?;
        prop_assert!(before.is_some());
        for _ in 0..repeats {
            prop_assert_eq!(fail(kevery.process(&event, &now))?, Processed::Duplicate);
        }
        prop_assert_eq!(fail(kevery.logged(&identifier, 0))?, before);
    }
}
