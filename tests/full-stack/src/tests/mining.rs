//! Mining for the local test network's regtest Bitcoin and Monero nodes and its Ethereum node.
//!
//! Regtest networks don't mine blocks on their own. We initially mine enough blocks to mature
//! the coinbase outputs (100 blocks on Bitcoin, 60 on Monero), then keep the chains moving with
//! a block per minute on each.
//!
//! The Ethereum node (anvil) is likewise run without mining. The Ethereum processor handles the
//! chain in epochs of 32 blocks and solely finalized ones (anvil finalizes two epochs behind the
//! tip), so Ethereum is mined at a faster rate.

use core::time::Duration;

use monero_wallet::address::{MoneroAddress, Network};
use monero_simple_request_rpc::{SimpleRequestTransport, prelude::MoneroDaemon};

use alloy_provider::{Provider as _, RootProvider};

use dockertest::DockerOperations;

use crate::Handles;

/// The address the Bitcoin block rewards are mined to.
// TODO: Hardcode the mining address
const BITCOIN_MINING_ADDRESS: &str =
  "bcrt1p2tng7xpsjk5dc06khtjf8q9mhme7spc55c0jyh0p8l5ne3nz0grqjtlsdq";

/// The address the Monero block rewards are mined to.
///
/// Any standard (non-subaddress) mainnet address works for regtest.
// TODO: Hardcode the mining address
const MONERO_MINING_ADDRESS: &str =
  "41p2XQsX6twKNj1qFRM6dG22rLNac52qc44gymKAHuEDfiqby4WF8f9dD72mmjRcLgFQFL79ML71jamMHKC1c6mHC6FiApR";

/// The amount of blocks initially mined on each network, maturing the coinbase outputs.
const INITIAL_BLOCKS: usize = 100;

/// The interval between blocks mined on each network.
const BLOCK_INTERVAL: Duration = Duration::from_secs(60);

/// The amount of blocks initially mined on Ethereum: one epoch, plus the two it takes for anvil
/// to consider it finalized.
const ETH_INITIAL_BLOCKS: u64 = 96;

/// The amount of Ethereum blocks mined per `BLOCK_INTERVAL`.
///
/// Mined in steady, small batches so block timestamps track the wall clock, which the processor
/// relies on when choosing where to start scanning.
const ETH_BLOCKS_PER_INTERVAL: u64 = 5;

async fn mine_bitcoin_blocks(rpc: &bitcoin_serai::rpc::Rpc, count: usize) -> Result<(), String> {
  rpc
    .call::<Vec<String>>("generatetoaddress", &format!(r#"[{count}, "{BITCOIN_MINING_ADDRESS}"]"#))
    .await
    .map(|_| ())
    .map_err(|e| format!("failed to mine Bitcoin block(s): {e:?}"))
}

async fn mine_ethereum_blocks(provider: &RootProvider, count: u64) -> Result<(), String> {
  provider
    .raw_request::<_, ()>("anvil_mine".into(), [count])
    .await
    .map_err(|e| format!("failed to mine Ethereum block(s): {e:?}"))
}

async fn mine_monero_blocks(
  rpc: &MoneroDaemon<SimpleRequestTransport>,
  count: usize,
) -> Result<(), String> {
  let address = MoneroAddress::from_str(Network::Mainnet, MONERO_MINING_ADDRESS)
    .map_err(|e| format!("invalid `MONERO_MINING_ADDRESS`: {e:?}"))?;
  rpc
    .generate_blocks(&address, count)
    .await
    .map(|_| ())
    .map_err(|e| format!("failed to mine Monero block(s): {e:?}"))
}

/// Mine `INITIAL_BLOCKS` blocks on Bitcoin and Monero (`ETH_INITIAL_BLOCKS` on Ethereum), then a
/// block per `BLOCK_INTERVAL` on each (`ETH_BLOCKS_PER_INTERVAL` on Ethereum), forever.
pub(crate) async fn mine(ops: &DockerOperations, handles: &Handles) {
  let bitcoin = handles.bitcoin(ops).await;
  let ethereum = handles.ethereum(ops).await;
  let monero = handles.monero(ops).await;

  println!(
    "Mining {INITIAL_BLOCKS} blocks on Bitcoin and Monero, {ETH_INITIAL_BLOCKS} on Ethereum..."
  );
  mine_bitcoin_blocks(&bitcoin, INITIAL_BLOCKS).await.unwrap();
  mine_ethereum_blocks(&ethereum, ETH_INITIAL_BLOCKS).await.unwrap();
  // The Monero node runs without `--offline` so external nodes can sync from it, yet it then
  // refuses `generateblocks` (CORE_BUSY) until a first P2P peer connection marks it as
  // synchronized, so retry until such a peer connects
  while let Err(e) = mine_monero_blocks(&monero, INITIAL_BLOCKS).await {
    println!("{e} (retrying in 15s...)");
    tokio::time::sleep(Duration::from_secs(15)).await;
  }

  println!(
    "Mining a block per interval on Bitcoin and Monero, {ETH_BLOCKS_PER_INTERVAL} on Ethereum..."
  );
  loop {
    tokio::time::sleep(BLOCK_INTERVAL).await;
    // Log, without halting the network, on transient RPC failures
    if let Err(e) = mine_bitcoin_blocks(&bitcoin, 1).await {
      println!("{e}");
    }
    if let Err(e) = mine_ethereum_blocks(&ethereum, ETH_BLOCKS_PER_INTERVAL).await {
      println!("{e}");
    }
    if let Err(e) = mine_monero_blocks(&monero, 1).await {
      println!("{e}");
    }
  }
}
