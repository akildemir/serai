use std::{sync::Arc, fs};

use rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use zeroize::Zeroizing;
use ciphersuite::{
  group::ff::PrimeField as _,
  WrappedGroup, WithPreferredHash,
};
use dalek_ff_group::Ristretto;
use embedwards25519::Embedwards25519;
use secq256k1::Secq256k1;

use sp_core::{
  Encode as _, Decode as _, Pair as _,
  sr25519::Pair,
  traits::{RuntimeCode, WrappedRuntimeCode, CallContext, CodeExecutor as _},
};
use sp_runtime::{
  Digest,
  traits::{Block as _, Header as _},
};
use sp_state_machine::BasicExternalities;
use sp_io::SubstrateHostFunctions;

use serai_abi::{
  primitives::{prelude::*, crypto::SignedEmbeddedEllipticCurveKeys},
  SubstrateBlock as Block,
};
use serai_runtime::GenesisConfig;

use sc_client_db::{BlockImportOperation, Backend};
use sc_executor::{RuntimeVersionOf, WasmExecutor};
use sc_chain_spec::{BuildGenesisBlock, GenesisBlockBuilder, ChainSpecBuilder};
use sc_service::{ChainType, ChainSpec as _, GenericChainSpec as ChainSpec};

/// Generate the key pair for the validator corresponding to a development seed.
///
/// This is insecure and MUST NOT be used except testing purposes.
///
/// Note the development seed itself is used as the _auxiliary key_ used to operate the node with.
pub(super) fn validator_identity_for_dev_seed(dev_seed: &str) -> SeraiAddress {
  Pair::from_string(dev_seed, None).unwrap().public().into()
}

/// Create an insecure key pair from a name alone.
///
/// This will have effectively no entropy and MUST NOT be used except for testing purposes.
fn insecure_keypair_from_name(name: &'static str) -> Pair {
  Pair::from_string(&format!("//{name}"), None).unwrap()
}

/// Create an insecure Serai address (with known private key) from a name alone.
///
/// This will have effectively no entropy and MUST NOT be used except for testing purposes.
fn insecure_account_from_name(name: &'static str) -> SeraiAddress {
  insecure_keypair_from_name(name).public().into()
}

// This is for test only.
fn insecure_arbitrary_key_from_name<C: WithPreferredHash>(name: &str) -> C::F {
  C::hash_to_F(&[b"insecure arbitrary key".as_slice(), name.as_bytes()].concat())
}

/// Create a list of insecure auxiliary keys for the specified validator.
fn insecure_auxiliary_keys(name: &'static str) -> Vec<SignedEmbeddedEllipticCurveKeys> {
  let validator = insecure_account_from_name(name);

  // Seed a deterministic RNG from the validator's name so every node generates an identical set of
  // auxiliary keys, using `OsRng` here would cause each node to produce distinct keys, yielding
  // a genesis mismatch which prevents peering.
  let mut rng =
    ChaCha20Rng::from_seed(sp_core::blake2_256(format!("auxiliary-keys-//{name}").as_bytes()));

  let serai = SignedEmbeddedEllipticCurveKeys::serai(
    &mut rng,
    validator,
    &Zeroizing::new(
      <Ristretto as WrappedGroup>::F::from_repr(
        insecure_keypair_from_name(name).to_raw_vec()[.. 32].try_into().unwrap(),
      )
      .unwrap(),
    ),
  );

  let bitcoin = {
    let embedwards = Zeroizing::new(insecure_arbitrary_key_from_name::<Embedwards25519>(name));
    let secq = Zeroizing::new(insecure_arbitrary_key_from_name::<Secq256k1>(name));
    SignedEmbeddedEllipticCurveKeys::bitcoin(&mut rng, validator, &embedwards, &secq)
  };

  let ethereum = {
    let embedwards = Zeroizing::new(insecure_arbitrary_key_from_name::<Embedwards25519>(name));
    let secq = Zeroizing::new(insecure_arbitrary_key_from_name::<Secq256k1>(name));
    SignedEmbeddedEllipticCurveKeys::ethereum(&mut rng, validator, &embedwards, &secq)
  };

  let monero = {
    let embedwards = Zeroizing::new(insecure_arbitrary_key_from_name::<Embedwards25519>(name));
    SignedEmbeddedEllipticCurveKeys::monero(&mut rng, validator, &embedwards)
  };

  vec![serai, bitcoin, ethereum, monero]
}

fn wasm_binary(allow_builtin: bool) -> Vec<u8> {
  const DEFAULT_WASM_PATH: &str = "/runtime/serai.wasm";
  let path = serai_env::var("SERAI_WASM_PATH").unwrap_or(DEFAULT_WASM_PATH.to_owned());
  if let Ok(binary) = fs::read(&path) {
    sp_tracing::info!("using {path} for the WASM");
    return binary;
  }

  assert!(allow_builtin, "could not read WASM for the runtime and this is a public network");

  sp_tracing::info!("using built-in wasm");
  serai_runtime::WASM.to_vec()
}

fn devnet_genesis(
  validators: &[&'static str],
  endowed_accounts: Vec<SeraiAddress>,
) -> GenesisConfig {
  GenesisConfig {
    validators: validators
      .iter()
      .map(|name| (insecure_account_from_name(name), insecure_auxiliary_keys(name)))
      .collect(),
    fees: vec![
      (ExternalCoin::Bitcoin, 2),
      (ExternalCoin::Ether, 2),
      (ExternalCoin::Dai, 2),
      (ExternalCoin::Monero, 15),
    ],
    coins: endowed_accounts
      .into_iter()
      .map(|address| (address, Balance { coin: Coin::Serai, amount: Amount(1 << 60) }))
      .collect(),
  }
}

/// Call Serai's genesis API, used to initialize the on-chain storage.
fn genesis(
  name: &'static str,
  id: &'static str,
  chain_type: ChainType,
  protocol_id: &'static str,
  config: &GenesisConfig,
) -> ChainSpec {
  // permit the built-in WASM for all non-public(test) networks.
  let bin = wasm_binary(!matches!(chain_type, ChainType::Live));
  let hash = sp_core::blake2_256(&bin).to_vec();

  let mut chain_spec = ChainSpecBuilder::new(&bin, None)
    .with_name(name)
    .with_id(id)
    .with_chain_type(chain_type)
    .with_protocol_id(protocol_id)
    .build();

  let mut ext = BasicExternalities::new_empty();
  let code_fetcher = WrappedRuntimeCode(bin.clone().into());
  WasmExecutor::<SubstrateHostFunctions>::builder()
    .build()
    .call(
      &mut ext,
      &RuntimeCode { code_fetcher: &code_fetcher, heap_pages: None, hash },
      "GenesisApi_build",
      &config.encode(),
      CallContext::Onchain,
    )
    .0
    .unwrap();
  let mut storage = ext.into_storages();
  storage.top.insert(sp_core::storage::well_known_keys::CODE.to_vec(), bin);
  chain_spec.set_storage(storage);

  chain_spec
}

pub(super) fn solo_config() -> ChainSpec {
  genesis(
    "Solo Network",
    "solo",
    ChainType::Development,
    "serai-solo",
    &devnet_genesis(
      &["Alice"],
      vec![
        insecure_account_from_name("Alice"),
        insecure_account_from_name("Bob"),
        insecure_account_from_name("Charlie"),
        insecure_account_from_name("Dave"),
        insecure_account_from_name("Eve"),
        // ferryswap test account
        SeraiAddress([
          78, 8, 16, 157, 111, 15, 126, 163, 155, 125, 161, 74, 246, 71, 181, 89, 252, 91, 42, 241,
          182, 122, 43, 61, 42, 63, 64, 122, 199, 214, 8, 93,
        ]),
      ],
    ),
  )
}

pub(super) fn local_config() -> ChainSpec {
  genesis(
    "Local Test Network",
    "local",
    ChainType::Local,
    "serai-local",
    &devnet_genesis(
      &["Alice", "Bob", "Charlie", "Dave"],
      vec![
        insecure_account_from_name("Alice"),
        insecure_account_from_name("Bob"),
        insecure_account_from_name("Charlie"),
        insecure_account_from_name("Dave"),
        insecure_account_from_name("Eve"),
      ],
    ),
  )
}

/// Construct Serai's genesis block.
struct GenesisBlock<Executor> {
  /// The underlying genesis block builder from Substrate.
  builder: GenesisBlockBuilder<Block, Backend<Block>, Executor>,
  /// The `Digest`, which we want with the genesis block but must keep track of ourselves.
  digest: Digest,
}
impl<Executor: RuntimeVersionOf> BuildGenesisBlock<Block> for GenesisBlock<Executor> {
  type BlockImportOperation = BlockImportOperation<Block>;

  fn build_genesis_block(
    self,
  ) -> Result<(Block, Self::BlockImportOperation), sp_blockchain::Error> {
    let Self { builder, digest } = self;

    let (genesis_block, op) = builder.build_genesis_block()?;

    // Attach the digest to the yielded block's header now
    let genesis_block = {
      let (mut header, transactions) = genesis_block.deconstruct();
      *header.digest_mut() = digest;
      Block::new(header, transactions)
    };

    Ok((genesis_block, op))
  }
}

/// Construct the genesis block for Serai.
pub(super) fn genesis_block(
  chain_spec: &dyn sc_chain_spec::ChainSpec,
  backend: Arc<Backend<Block>>,
  executor: impl RuntimeVersionOf,
) -> Result<
  impl BuildGenesisBlock<Block, BlockImportOperation = BlockImportOperation<Block>>,
  sc_service::error::Error,
> {
  let storage = chain_spec.as_storage_builder().build_storage()?;
  // Manually extract the `Digest` from `frame-system` as Substrate won't yield it for us
  // TODO: While this is technically fine, it'd be better to use a `RuntimeApi`
  let digest = {
    let digest_key = [sp_core::twox_128(b"System"), sp_core::twox_128(b"Digest")].concat();
    Digest::decode(&mut storage.top.get(&digest_key).expect("`System Digest` not set").as_slice())
      .expect("failed to decode `System Digest`")
  };

  let commit_genesis_state = true;
  Ok(GenesisBlock {
    builder: GenesisBlockBuilder::new_with_storage(
      storage,
      commit_genesis_state,
      backend,
      executor,
    )?,
    digest,
  })
}
