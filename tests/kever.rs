//! Key event validation cases the keripy fixtures do not reach.

use keri_cesr::crypto::signer::{SignaturePlacement, Signer};
use keri_cesr::crypto::verifier::KeyTransferability;
use keri_kel::{KelError, Kever};
use keri_protocol::attachment::SignedMessageBuilder;
use keri_protocol::event::inception::InceptionBuilder;
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::PrefixDerivation;
use keri_protocol::stream::Message;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn a_self_addressing_witness_is_refused() -> TestResult {
    let signer = Signer::from_seed(&[1; 32], KeyTransferability::Transferable)?;
    let other = InceptionBuilder::new(vec![signer.verifier().clone()])
        .prefix_derivation(PrefixDerivation::Blake3_256)
        .build()?;
    let inception = InceptionBuilder::new(vec![signer.verifier().clone()])
        .witnesses(vec![other.identifier().clone()])
        .prefix_derivation(PrefixDerivation::Blake3_256)
        .build()?;
    let signature = signer.sign_indexed(inception.raw(), SignaturePlacement::both_lists(0))?;
    let bytes = SignedMessageBuilder::new(inception.serialized())
        .controller_signatures(vec![signature])
        .build()?;
    let message = Message::from_bytes(bytes.as_bytes())?;

    let refused = Kever::incept(&message, Timestamp::parse("2021-01-01T00:00:00.000000+00:00")?);
    assert!(matches!(refused, Err(KelError::UnexpectedFieldShape { label: "b" })));
    Ok(())
}
