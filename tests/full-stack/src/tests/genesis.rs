//! Completes the genesis liquidity period for the local test network.
//!
//! The genesis liquidity of every external network is expected to come from real deposits made
//! through the processors (with `InInstruction::GenesisLiquidity`). Forging their batches isn't
//! possible (their keys are set by the real DKG) and would poison the processors' state if it
//! were.
//!
//! The helpers here are largely copied from `substrate/client/serai/tests/common/mod.rs`.

use core::time::Duration;
use std::collections::HashMap;

use zeroize::Zeroizing;
use rand_core::OsRng;

use ciphersuite::{group::GroupEncoding as _, GroupIo, WrappedGroup as _};
use musig::{Participant, ThresholdKeys, musig};
use dalek_ff_group::Ristretto;
use schnorrkel::Schnorrkel;

use sp_core::{Pair as _, sr25519::Pair};
use sp_application_crypto::RuntimePublic as _;

use serai_client_serai::{
  Serai,
  abi::{
    Call, Transaction,
    genesis_liquidity::Call as GenesisLiquidityCall,
    primitives::{
      BlockHash,
      balance::Amount,
      coin::ExternalCoin,
      crypto::RistrettoSignature,
      genesis_liquidity::GenesisValues,
      network_id::NetworkId,
      validator_sets::{Session, ValidatorSet},
    },
  },
};

/// The validators of the `local` chain config, in genesis (chain-spec) order.
const VALIDATOR_NAMES: [&str; 4] = ["Alice", "Bob", "Charlie", "Dave"];

fn insecure_pair_from_name(name: &str) -> Pair {
  Pair::from_string(&format!("//{name}"), None).unwrap()
}

/// The dev validators' key pairs, in the order their auxiliary keys appear in
/// `GenesisValidatorsAuxiliaryKeys` (the genesis order).
fn dev_pairs_in_genesis_order() -> Vec<Pair> {
  VALIDATOR_NAMES.iter().map(|name| insecure_pair_from_name(name)).collect()
}

/// Publish a transaction, yielding the hash of the block which included it.
async fn publish_tx(serai: &Serai, tx: &Transaction) -> BlockHash {
  serai.publish_transaction(tx).await.unwrap();

  // Get the block it was included in
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

fn musig_sign(set: ValidatorSet, pairs: &[Pair], msg: &[u8]) -> RistrettoSignature {
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

/// Oraclize the genesis values, ending the genesis period and initializing the pools.
async fn oraclize_values(serai: &Serai) {
  let values = GenesisValues { ether: Amount(3097630), dai: Amount(1417), monero: Amount(488472) };
  let set = ValidatorSet { network: NetworkId::Serai, session: Session(0) };
  let pairs = dev_pairs_in_genesis_order();

  let signature = musig_sign(set, &pairs, &values.oraclize_values_message());
  let mut signature_participants = bitvec::vec::BitVec::new();
  for _ in 0 .. pairs.len() {
    signature_participants.push(true);
  }

  publish_tx(
    serai,
    &Transaction::Unsigned {
      call: Call::GenesisLiquidity(GenesisLiquidityCall::oraclize_values {
        values,
        signature_participants: signature_participants.try_into().unwrap(),
        signature,
      })
      .try_into()
      .unwrap(),
    },
  )
  .await;
}

/// Complete the genesis liquidity period.
///
/// This waits for real genesis liquidity deposits on every external network, and then oraclizes
/// the genesis values (initializing the pools).
pub(crate) async fn complete_genesis(serai: &Serai) {
  if serai.state().await.unwrap().genesis_completed().await.unwrap() {
    println!("Genesis already completed.");
    return;
  }

  println!(
    "Waiting for BTC, ETH, DAI and XMR genesis liquidity deposits before oraclizing values..."
  );
  loop {
    let state = serai.state().await.unwrap();
    let mut all_deposited = true;
    for coin in
      [ExternalCoin::Bitcoin, ExternalCoin::Ether, ExternalCoin::Dai, ExternalCoin::Monero]
    {
      if state.genesis_liquidity_supply(coin).await.unwrap().0 == 0 {
        all_deposited = false;
      }
    }
    if all_deposited {
      break;
    }
    tokio::time::sleep(Duration::from_secs(30)).await;
  }

  // wait for genesis time to complete
  {
    const GENESIS_LIQUIDITY_TIME: Duration = HOUR.checked_mul(5).unwrap();;

    let genesis_time = Duration::from_millis(
      serai.block_by_number(1).await.unwrap().unwrap().header.unix_time_in_millis(),
    );
    let end_of_genesis = genesis_time.checked_add(GENESIS_LIQUIDITY_TIME).unwrap();

    async fn latest_time(serai: &Serai) -> Duration {
      let latest = serai.latest_finalized_block_number().await.unwrap();
      Duration::from_millis(
        serai.block_by_number(latest).await.unwrap().unwrap().header.unix_time_in_millis(),
      )
    }

    let remaining = end_of_genesis.saturating_sub(latest_time(serai).await);
    if !remaining.is_zero() {
      println!("Waiting {}s for the genesis liquidity period to pass...", remaining.as_secs());
    }
    while latest_time(serai).await < end_of_genesis {
      tokio::time::sleep(Duration::from_secs(30)).await;
    }
  }

  println!("Oraclizing genesis values...");
  oraclize_values(serai).await;

  // `oraclize_values`' dispatch may fail even when its `validate_unsigned` passes, so confirm
  // genesis actually completed
  for _ in 0 .. 10 {
    if serai.state().await.unwrap().genesis_completed().await.unwrap() {
      println!("Genesis completed. Pools are initialized.");
      return;
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
  }
  panic!("`oraclize_values` was published yet genesis didn't complete");
}
