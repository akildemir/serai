//! Serai's Ethereum contracts on the local test network.
//!
//! Nothing in the Serai stack deploys the Deployer/Router, nor publishes the transactions the
//! Ethereum processors sign (those are solely handed to the relayers). This bootstraps the
//! contracts once the Ethereum key is set on Serai, places an ERC20 at the address the processor
//! recognizes DAI at, and relays the processors' Router transactions onto the chain.

use core::time::Duration;
use alloc::sync::Arc;

use alloy_core::primitives::{address, Address, U256, Bytes, TxKind};
use alloy_sol_types::SolCall as _;
use alloy_consensus::{TxLegacy, Signed};
use alloy_rlp::Decodable as _;
use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
use alloy_provider::{Provider as _, RootProvider};

use tokio::{
  io::{AsyncReadExt as _, AsyncWriteExt as _},
  net::TcpStream,
};

use serai_client_serai::{
  Serai,
  abi::primitives::{
    network_id::ExternalNetworkId,
    validator_sets::{ExternalValidatorSet, Session},
  },
};

use ethereum_schnorr::PublicKey;
use ethereum_primitives::deterministically_sign;
use ethereum_deployer::Deployer;
use ethereum_router::Router;

/// The address of DAI on Ethereum mainnet, the sole address the Ethereum processor recognizes
/// DAI at (regardless of the chain).
pub(crate) const DAI: Address = address!("6B175474E89094C44Da98b954EedeAC495271d0F");

/// The runtime code of the Router's test ERC20, placed at `DAI`.
const TEST_ERC20_RUNTIME: &str =
  include_str!(concat!(env!("OUT_DIR"), "/serai-full-stack-tests/TestERC20.bin-runtime"));

/// The address funded with ETH and DAI, to test with.
///
/// Ethereum has no block rewards to mine to an address (unlike the Bitcoin and Monero nodes), so
/// this address's balances are set directly instead.
pub(crate) const FUNDED_ADDRESS: Address = address!("77154AaCf48Aa5d010ED0d13b756FEc07aB3d5F1");

/// The amount of ETH the funded address receives.
const FUNDED_ETH: u64 = 1000;
/// The amount of DAI the funded address receives.
const FUNDED_DAI: u64 = 1_000_000;

/// An amount of ETH/DAI, which both have 18 decimals, in their atomic units.
fn eighteen_decimals(amount: u64) -> U256 {
  U256::from(amount) * U256::from(10u64).pow(U256::from(18))
}

/// The gas price used for every transaction published here.
const GAS_PRICE: u128 = 100_000_000_000;

/// The interval between checks of the relayers.
const RELAY_INTERVAL: Duration = Duration::from_secs(5);

/// The delay between Serai's Ethereum key being set and the Router being deployed.
///
/// The processors scan from the first epoch after the time the key was set. The Router must be
/// deployed within a scanned epoch (its constructor's event is what triggers confirming the key),
/// so its deployment waits past any clock skew between the nodes.
const ROUTER_DEPLOYMENT_DELAY: Duration = Duration::from_secs(60);

mod abi {
  alloy_sol_macro::sol! {
    interface IRouterNonce {
      function nextNonce() external view returns (uint256);
    }

    interface IMintable {
      function mint(address owner, uint256 value) external;
    }
  }
}

/// Deploy the Deployer and Router (once the Ethereum key is set on Serai), and place the test
/// ERC20 at the DAI address, if not already done.
pub(crate) async fn bootstrap(provider: &Arc<RootProvider>, serai: &Serai) -> Router {
  // The Deployer, which has a deterministic address
  if Deployer::new(provider.clone()).await.unwrap().is_none() {
    println!("Deploying the Deployer...");
    let receipt = ethereum_test_primitives::publish_tx(provider, Deployer::deployment_tx()).await;
    assert!(receipt.status(), "deploying the Deployer failed");
  }
  println!("Deployer: {}", Deployer::address());

  // DAI
  if provider.get_code_at(DAI).await.unwrap().is_empty() {
    println!("Placing the test ERC20 at the DAI address...");
    let code = Bytes::from(hex::decode(TEST_ERC20_RUNTIME.trim()).unwrap());
    let _: () = provider.raw_request("anvil_setCode".into(), (DAI, code)).await.unwrap();
  }
  println!("DAI: {DAI}");

  // The address to test with
  if provider.get_balance(FUNDED_ADDRESS).await.unwrap().is_zero() {
    println!("Funding {FUNDED_ADDRESS} with {FUNDED_ETH} ETH and {FUNDED_DAI} DAI...");
    let _: () = provider
      .raw_request(
        "anvil_setBalance".into(),
        [FUNDED_ADDRESS.to_string(), eighteen_decimals(FUNDED_ETH).to_string()],
      )
      .await
      .unwrap();
    let mint = TxLegacy {
      chain_id: None,
      nonce: 0,
      gas_price: GAS_PRICE,
      gas_limit: 100_000,
      to: TxKind::Call(DAI),
      value: U256::ZERO,
      input: abi::IMintable::mintCall {
        owner: FUNDED_ADDRESS,
        value: eighteen_decimals(FUNDED_DAI),
      }
      .abi_encode()
      .into(),
    };
    publish(provider, deterministically_sign(mint)).await.expect("minting DAI failed");
  }

  // The Router, which is constructed with Serai's initial Ethereum key
  println!("Waiting for Serai's Ethereum key to be set...");
  let key = loop {
    let set = ExternalValidatorSet { network: ExternalNetworkId::Ethereum, session: Session(0) };
    if let Some(keys) = serai.state().await.unwrap().keys(set).await.unwrap() {
      let repr = <[u8; 32]>::try_from(keys.1.as_ref()).expect("Ethereum key wasn't 32 bytes");
      break PublicKey::from_eth_repr(repr).expect("Ethereum key set on Serai wasn't valid");
    }
    tokio::time::sleep(Duration::from_secs(10)).await;
  };
  let router = if let Some(router) = Router::new(provider.clone(), &key).await.unwrap() {
    router
  } else {
    tokio::time::sleep(ROUTER_DEPLOYMENT_DELAY).await;
    println!("Deploying the Router...");
    let mut tx = Router::deployment_tx(&key);
    tx.gas_limit = 1_100_000;
    tx.gas_price = GAS_PRICE;
    let receipt = ethereum_test_primitives::publish_tx(provider, deterministically_sign(tx)).await;
    assert!(receipt.status(), "deploying the Router failed");
    Router::new(provider.clone(), &key)
      .await
      .unwrap()
      .expect("deployed the Router yet couldn't find it")
  };
  println!("Router: {}", router.address());

  router
}

/// The nonce the Router expects the next transaction from Serai to use.
async fn next_nonce(provider: &RootProvider, router: &Router) -> Result<u64, String> {
  let call = TransactionRequest::default()
    .to(router.address())
    .input(TransactionInput::new(abi::IRouterNonce::nextNonceCall {}.abi_encode().into()));
  let bytes = provider
    .call(call)
    .await
    .map_err(|e| format!("couldn't fetch the Router's next nonce: {e:?}"))?;
  let nonce = abi::IRouterNonce::nextNonceCall::abi_decode_returns(&bytes)
    .map_err(|e| format!("couldn't decode the Router's next nonce: {e:?}"))?;
  u64::try_from(nonce).map_err(|e| format!("Router's next nonce exceeded u64: {e:?}"))
}

/// Fetch the transaction for the specified nonce from a relayer, if it has one.
async fn fetch_from_relayer(relayer: &str, nonce: u32) -> Result<Option<Vec<u8>>, String> {
  let mut socket = TcpStream::connect(relayer)
    .await
    .map_err(|e| format!("couldn't connect to the relayer {relayer}: {e:?}"))?;
  socket
    .write_all(&nonce.to_le_bytes())
    .await
    .map_err(|e| format!("couldn't write to the relayer {relayer}: {e:?}"))?;

  let mut len = [0; 4];
  socket
    .read_exact(&mut len)
    .await
    .map_err(|e| format!("couldn't read from the relayer {relayer}: {e:?}"))?;
  let len = usize::try_from(u32::from_le_bytes(len)).unwrap();
  if len == 0 {
    return Ok(None);
  }

  let mut msg = vec![0; len];
  socket
    .read_exact(&mut msg)
    .await
    .map_err(|e| format!("couldn't read from the relayer {relayer}: {e:?}"))?;
  Ok(Some(msg))
}

/// Fund the signer of an already-signed transaction, publish it, and wait for its receipt.
async fn publish(provider: &RootProvider, tx: Signed<TxLegacy>) -> Result<(), String> {
  let signer = tx.recover_signer().map_err(|e| format!("couldn't recover the signer: {e:?}"))?;
  let funds = (U256::from(tx.tx().gas_limit) * U256::from(tx.tx().gas_price)) + tx.tx().value;
  let _: () = provider
    .raw_request("anvil_setBalance".into(), [signer.to_string(), funds.to_string()])
    .await
    .map_err(|e| format!("couldn't fund the signer: {e:?}"))?;

  let mut bytes = vec![];
  tx.eip2718_encode(&mut bytes);
  let pending = provider
    .send_raw_transaction(&bytes)
    .await
    .map_err(|e| format!("couldn't publish the transaction: {e:?}"))?;
  let receipt = tokio::time::timeout(Duration::from_secs(120), pending.get_receipt())
    .await
    .map_err(|_| "timed out waiting for the transaction's receipt".to_owned())?
    .map_err(|e| format!("couldn't fetch the transaction's receipt: {e:?}"))?;
  if !receipt.status() {
    Err("the published transaction reverted".to_owned())?;
  }
  Ok(())
}

/// Publish the transaction for the Router's next nonce, if any relayer has it.
async fn relay_next_transaction(
  provider: &RootProvider,
  router: &Router,
  relayers: &[String],
) -> Result<(), String> {
  let nonce = next_nonce(provider, router).await?;

  // Every validator which signed hands the same transaction to its relayer, so the first to have
  // it suffices
  let mut msg = None;
  for relayer in relayers {
    match fetch_from_relayer(relayer, u32::try_from(nonce).unwrap()).await {
      Ok(Some(this_msg)) => {
        msg = Some(this_msg);
        break;
      }
      Ok(None) => {}
      Err(e) => println!("{e}"),
    }
  }
  let Some(msg) = msg else { return Ok(()) };

  // The processor prefixes the transaction with its nonce as a u64, of which the relayer solely
  // consumes (and strips) the first four bytes
  if msg.len() < 4 {
    Err("relayer returned a malformed transaction".to_owned())?;
  }
  let mut tx = TxLegacy::decode(&mut &msg[4 ..])
    .map_err(|e| format!("couldn't decode the transaction to relay: {e:?}"))?;

  // The processor leaves the gas to the publisher
  tx.gas_price = GAS_PRICE;
  tx.gas_limit = {
    let estimate = provider
      .estimate_gas(
        TransactionRequest::default()
          .to(router.address())
          .value(tx.value)
          .input(TransactionInput::new(tx.input.clone())),
      )
      .await
      .map_err(|e| format!("couldn't estimate the gas for the transaction to relay: {e:?}"))?;
    (estimate * 3) / 2
  };

  println!("Publishing the Router transaction for nonce {nonce}...");
  publish(provider, deterministically_sign(tx)).await
}

/// Relay the transactions the processors signed onto the chain, forever.
pub(crate) async fn relay_published_transactions(
  provider: Arc<RootProvider>,
  router: Router,
  relayers: Vec<String>,
) {
  loop {
    tokio::time::sleep(RELAY_INTERVAL).await;
    // Log, without halting the network, on failures
    if let Err(e) = relay_next_transaction(&provider, &router, &relayers).await {
      println!("{e}");
    }
  }
}
