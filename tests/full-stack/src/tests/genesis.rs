//! Completes the genesis liquidity period for the local test network.
//!
//! The BTC/XMR genesis liquidity is expected to come from real deposits made through the
//! processors (with `InInstruction::GenesisLiquidity`). Forging their batches isn't possible
//! (their keys are set by the real DKG) and would poison the processors' state if it were.
//!
//! No Ethereum stack runs on this network, yet `oraclize_values` errors if the ETH/DAI genesis
//! liquidity is zero. Accordingly, we forge their batches: we set the Ethereum validator set's
//! keys to a key pair we control, which is possible as the dev validators' auxiliary keys are
//! well-known.
//!
//! The helpers here are largely copied from `substrate/client/serai/tests/common/mod.rs`.

use core::time::Duration;
use std::collections::HashMap;

use zeroize::Zeroizing;
use rand_core::{RngCore, OsRng};

use ciphersuite::{group::GroupEncoding as _, GroupIo, WrappedGroup as _};
use musig::{Participant, ThresholdKeys, musig};
use dalek_ff_group::Ristretto;
use schnorrkel::Schnorrkel;

use sp_core::{Pair as _, sr25519::Pair};
use sp_application_crypto::RuntimePublic as _;

use serai_client_serai::{
  InInstructions, Serai, ValidatorSets,
  abi::{
    Call, Transaction,
    genesis_liquidity::Call as GenesisLiquidityCall,
    primitives::{
      BlockHash,
      constants::DAY,
      address::SeraiAddress,
      balance::{Amount, ExternalBalance},
      coin::ExternalCoin,
      crypto::{ExternalKey, KeyPair, RistrettoSignature},
      genesis_liquidity::GenesisValues,
      instructions::{Batch, InInstruction, InInstructionWithBalance, SignedBatch},
      network_id::{ExternalNetworkId, NetworkId},
      validator_sets::{ExternalValidatorSet, Session, ValidatorSet},
    },
  },
};

/// The validators of the `local` chain config, in genesis (chain-spec) order.
const VALIDATOR_NAMES: [&str; 4] = ["Alice", "Bob", "Charlie", "Dave"];

/// The ferryswap test account, endowed in the `local` chain config.
const FERRYSWAP_ACCOUNT: SeraiAddress = SeraiAddress([
  96, 179, 105, 228, 44, 215, 87, 50, 205, 39, 90, 154, 92, 29, 4, 96, 191, 99, 226, 151, 249, 41,
  77, 39, 53, 96, 126, 250, 146, 111, 132, 24,
]);

fn insecure_pair_from_name(name: &str) -> Pair {
  Pair::from_string(&format!("//{name}"), None).unwrap()
}

fn address_of(pair: &Pair) -> SeraiAddress {
  let mut address = [0; 32];
  address.copy_from_slice(pair.public().as_ref());
  SeraiAddress(address)
}

/// The dev validators' key pairs, in the order their auxiliary keys appear in
/// `GenesisValidatorsAuxiliaryKeys` (the genesis order).
fn dev_pairs_in_genesis_order() -> Vec<Pair> {
  VALIDATOR_NAMES.iter().map(|name| insecure_pair_from_name(name)).collect()
}

/// The dev validators' key pairs, in the order `SelectedValidators::iter_prefix` yields them.
///
/// `set_keys` validates its MuSig signature against the participants in this order.
/// `SelectedValidators` hashes the validator with `Blake2_128Concat`, so its iteration order is
/// by `blake2_128(address) || address`.
fn dev_pairs_in_storage_order() -> Vec<Pair> {
  let mut pairs = dev_pairs_in_genesis_order();
  pairs.sort_by_key(|pair| {
    let address = address_of(pair);
    let mut key = sp_core::blake2_128(&address.0).to_vec();
    key.extend_from_slice(&address.0);
    key
  });
  pairs
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

/// Set the specified Ethereum validator set's keys, with a MuSig signature from the dev
/// validators' auxiliary keys.
async fn set_ethereum_keys(serai: &Serai, set: ExternalValidatorSet, key_pair: &KeyPair) {
  let pairs = dev_pairs_in_storage_order();

  let msg = set.set_keys_message(key_pair);
  let sig = musig_sign(set.into(), &pairs, msg.as_slice());

  let mut signature_participants = bitvec::vec::BitVec::new();
  for _ in 0 .. pairs.len() {
    signature_participants.push(true);
  }

  publish_tx(
    serai,
    &ValidatorSets::set_keys(
      set.network,
      key_pair.clone(),
      signature_participants.try_into().unwrap(),
      sig.into(),
    ),
  )
  .await;
}

/// Provide the ETH/DAI genesis liquidity with forged batches.
async fn provide_ethereum_genesis_liquidity(serai: &Serai) {
  let network = ExternalNetworkId::Ethereum;
  let session = serai
    .state()
    .await
    .unwrap()
    .latest_decided_session(network.into())
    .await
    .unwrap()
    .unwrap_or(Session(0));
  let set = ExternalValidatorSet { network, session };

  // The key pair used to sign the batches, which we control
  let pair = Pair::from_string(&format!("//ValidatorSet {set:?}"), None).unwrap();
  let keys = if let Some(keys) = serai.state().await.unwrap().keys(set).await.unwrap() {
    keys
  } else {
    let keys = KeyPair(pair.public().into(), ExternalKey(vec![].try_into().unwrap()));
    set_ethereum_keys(serai, set, &keys).await;
    keys
  };
  assert_eq!(keys.0, pair.public().into(), "Ethereum set's keys weren't a key pair we control");

  // make a batch
  let mut external_network_block_hash = BlockHash([0; 32]);
  OsRng.fill_bytes(&mut external_network_block_hash.0);
  let mut batch = Batch::new(network, u32::try_from(0).unwrap(), external_network_block_hash);
  for coin in ExternalNetworkId::Ethereum.coins() {
    let amount = if coin == ExternalCoin::Ether {
      // 1k eth
      Amount(1000 * 10u64.pow(coin.decimals()))
    } else {
      // 1M Dai
      Amount(1_000_000 * 10u64.pow(coin.decimals()))
    };
    batch
      .push_instruction(InInstructionWithBalance {
        instruction: InInstruction::GenesisLiquidity(FERRYSWAP_ACCOUNT),
        balance: ExternalBalance { coin, amount },
      })
      .unwrap();
  }

  // sign & publish batch
  let signature = pair.sign(batch.publish_batch_message().as_slice());
  publish_tx(
    serai,
    &InInstructions::execute_batch(SignedBatch { batch, signature: signature.into() }),
  )
  .await;

  // Sanity check the batches actually credited the genesis liquidity
  let state = serai.state().await.unwrap();
  for coin in ExternalNetworkId::Ethereum.coins() {
    assert_ne!(
      state.genesis_liquidity_supply(coin).await.unwrap().0,
      0,
      "forged genesis liquidity batch for {coin:?} didn't credit anything",
    );
  }
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
/// This waits for real BTC/XMR genesis liquidity deposits, provides the ETH/DAI genesis
/// liquidity with forged batches, and then oraclizes the genesis values (initializing the pools).
pub(crate) async fn complete_genesis(serai: &Serai) {
  if serai.state().await.unwrap().genesis_completed().await.unwrap() {
    println!("Genesis already completed.");
    return;
  }

  println!("Waiting for BTC and XMR genesis liquidity deposits before oraclizing values...");
  loop {
    let state = serai.state().await.unwrap();
    let btc = state.genesis_liquidity_supply(ExternalCoin::Bitcoin).await.unwrap().0;
    let xmr = state.genesis_liquidity_supply(ExternalCoin::Monero).await.unwrap().0;
    if (btc != 0) && (xmr != 0) {
      break;
    }
    tokio::time::sleep(Duration::from_secs(30)).await;
  }

  println!("Providing ETH/DAI genesis liquidity with forged batches...");
  provide_ethereum_genesis_liquidity(serai).await;

  // wait for genesis time to complete
  {
    const GENESIS_LIQUIDITY_TIME: Duration = DAY;

    let genesis_time = Duration::from_millis(
      serai.block_by_number(1).await.unwrap().unwrap().header.unix_time_in_millis(),
    );
    let end_of_genesis = genesis_time.checked_add(GENESIS_LIQUIDITY_TIME).unwrap();

    let latest_time = |serai: &Serai| async {
      let latest = serai.latest_finalized_block_number().await.unwrap();
      Duration::from_millis(
        serai.block_by_number(latest).await.unwrap().unwrap().header.unix_time_in_millis(),
      )
    };

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
