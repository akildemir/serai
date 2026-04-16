use core::time::Duration;
use std::collections::HashMap;

use serai_abi::primitives::validator_sets::Session;
use zeroize::Zeroizing;
use rand_core::OsRng;

use ciphersuite::{group::GroupEncoding as _, GroupIo, WrappedGroup as _};
use dkg_musig::{Participant, ThresholdKeys, musig};
use dalek_ff_group::Ristretto;
use schnorrkel::Schnorrkel;

use sp_core::{Pair as _, sr25519::Pair};
use sp_application_crypto::RuntimePublic as _;

use serai_client_serai::{
  InInstructions, Serai, ValidatorSets,
  abi::{
    Transaction,
    primitives::{
      BlockHash,
      crypto::{KeyPair, RistrettoSignature},
      instructions::{Batch, SignedBatch},
      validator_sets::{ExternalValidatorSet, ValidatorSet},
      crypto::ExternalKey,
    },
    validator_sets::Event as ValidatorSetsEvent,
    in_instructions::Event as InInstructionsEvent,
  },
};

/// Waits until the genesis block is complete, panics if it isn't complete for 5 minutes.
pub async fn wait_until_genesis_block_completed(serai: &Serai) {
  'outer: {
    for _ in 0 .. (5 * 10) {
      tokio::time::sleep(Duration::from_secs(6)).await;

      let latest_finalized = serai.latest_finalized_block_number().await.unwrap();
      if latest_finalized > 0 {
        break 'outer;
      }
    }
    panic!("finalized block remained the genesis block for over five minutes");
  };
}

/// Publish a transaction, yielding the hash of the block which included it.
pub async fn publish_tx(serai: &Serai, tx: &Transaction) -> BlockHash {
  serai.publish_transaction(tx).await.unwrap();

  // Get the block it was included in
  // TODO: Add an RPC method for this/check the guarantee on the subscription
  for _ in 0 .. 60 {
    tokio::time::sleep(Duration::from_secs(1)).await;

    let latest = serai.latest_finalized_block_number().await.unwrap();
    let block = serai.block_by_number(latest).await.unwrap().unwrap();

    for transaction in &block.transactions {
      if transaction == tx {
        return block.header.hash();
      }
    }
  }
  panic!("transaction wasn't included in a finalized block within 60 seconds");
}

/// Set a validator set's keys on the Serai network.
///
/// This requires the pairs to be declared in the exact order they'll be expected in on-chain.
pub async fn set_keys(
  serai: &Serai,
  set: ExternalValidatorSet,
  key_pair: KeyPair,
  pairs: &[Pair],
) -> BlockHash {
  let msg = set.set_keys_message(&key_pair);
  let sig = musig_sign(set.into(), pairs, msg.as_slice());

  // Set the key pair
  let block = publish_tx(
    serai,
    &ValidatorSets::set_keys(
      set.network,
      key_pair.clone(),
      {
        let mut signature_participants = bitvec::vec::BitVec::new();
        for _ in 0 .. pairs.len() {
          signature_participants.push(true);
        }
        signature_participants.try_into().unwrap()
      },
      sig.into(),
    ),
  )
  .await;

  assert_eq!(
    serai
      .events(block)
      .await
      .unwrap()
      .validator_sets()
      .set_keys_events()
      .cloned()
      .collect::<Vec<_>>(),
    vec![ValidatorSetsEvent::SetKeys { set, key_pair: key_pair.clone() }]
  );
  assert_eq!(serai.state().await.unwrap().keys(set).await.unwrap(), Some(key_pair));

  block
}

#[allow(dead_code)]
pub async fn provide_batch(serai: &Serai, batch: Batch) -> BlockHash {
  let serai_latest = serai.state().await.unwrap();
  let session =
    serai_latest.current_session(batch.network().into()).await.unwrap().unwrap_or(Session(0));
  let set = ExternalValidatorSet { session, network: batch.network() };

  let pair = Pair::from_string(&format!("//ValidatorSet {set:?}"), None).unwrap();
  let aux_keys = Pair::from_string("//Alice", None).unwrap();
  let keys = if let Some(keys) = serai_latest.keys(set).await.unwrap() {
    keys
  } else {
    let keys = KeyPair(pair.public().into(), ExternalKey(vec![].try_into().unwrap()));
    set_keys(serai, set, keys.clone(), &[aux_keys]).await;
    keys
  };
  assert_eq!(keys.0, pair.public().into());

  let block = publish_tx(
    serai,
    &InInstructions::execute_batch(SignedBatch {
      batch: batch.clone(),
      signature: pair.sign(&batch.publish_batch_message().as_slice()).into(),
    }),
  )
  .await;

  let batches = serai
    .events(block)
    .await
    .unwrap()
    .in_instructions()
    .batch_events()
    .cloned()
    .collect::<Vec<_>>();

  // we expect all to be successful
  let mut in_instruction_results = bitvec::vec::BitVec::new();
  for _ in 0 .. batch.instructions().len() {
    in_instruction_results.push(true);
  }

  assert_eq!(
    batches,
    vec![InInstructionsEvent::Batch {
      network: batch.network(),
      id: batch.id(),
      external_network_block_hash: batch.external_network_block_hash(),
      publishing_session: session,
      in_instructions_hash: sp_core::blake2_256(&borsh::to_vec(batch.instructions()).unwrap()),
      in_instruction_results: in_instruction_results.try_into().unwrap()
    }],
  );

  block
}

pub fn musig_sign(set: ValidatorSet, pairs: &[Pair], msg: &[u8]) -> RistrettoSignature {
  let mut pub_keys = vec![];
  for pair in pairs {
    let public_key =
      <Ristretto as GroupIo>::read_G::<&[u8]>(&mut pair.public().0.as_ref()).unwrap();
    pub_keys.push(public_key);
  }

  let mut musig_keys = HashMap::new();
  for i in 0 .. pairs.len() {
    let secret_key = <Ristretto as GroupIo>::read_F::<&[u8]>(
      &mut pairs[i].as_ref().secret.to_bytes()[.. 32].as_ref(),
    )
    .unwrap();
    assert_eq!(Ristretto::generator() * secret_key, pub_keys[i]);

    let keys =
      musig::<Ristretto>(set.musig_context(), Zeroizing::new(secret_key), &pub_keys).unwrap();
    assert_eq!(
      sp_core::sr25519::Public::from(keys.group_key().to_bytes()),
      set
        .musig_key(&pub_keys.iter().map(|pub_key| pub_key.to_bytes().into()).collect::<Vec<_>>())
        .unwrap()
    );
    musig_keys.insert(keys.params().i(), keys);
  }

  // Map from the `Ristretto` ciphersuite used for MuSig to the `Ristretto` ciphersuite used for
  // signing, the former preferring Blake2b and the latter derived from FROST's IRTF standard
  let musig_keys = musig_keys
    .into_iter()
    .map(|(i, keys)| {
      (
        i,
        ThresholdKeys::<frost::curve::Ristretto>::new(
          keys.params(),
          keys.interpolation().clone(),
          keys.original_secret_share().clone(),
          (1 ..= keys.params().n())
            .map(|i| {
              let i = Participant::new(i).unwrap();
              (i, keys.original_verification_share(i))
            })
            .collect::<HashMap<_, _>>(),
        )
        .unwrap(),
      )
    })
    .collect::<HashMap<_, _>>();

  let machines =
    frost::tests::algorithm_machines(&mut OsRng, &Schnorrkel::new(b"substrate"), &musig_keys);
  let sig = frost::tests::sign_without_caching(&mut OsRng, machines, msg);
  assert!(sp_core::sr25519::Public::from(
    musig_keys.values().next().unwrap().group_key().to_bytes()
  )
  .verify(&msg, &sig.to_bytes().into()));

  sig.into()
}
