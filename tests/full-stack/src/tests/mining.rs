//! Mining for the local test network's regtest Bitcoin and Monero nodes.
//!
//! Regtest networks don't mine blocks on their own. We initially mine enough blocks to mature
//! the coinbase outputs (100 blocks on Bitcoin, 60 on Monero), then keep the chains moving with
//! a block per minute on each.

use core::time::Duration;

use monero_wallet::address::{MoneroAddress, Network};
use monero_simple_request_rpc::{SimpleRequestTransport, prelude::MoneroDaemon};

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
const BLOCK_INTERVAL: Duration = Duration::from_secs(10);

async fn mine_bitcoin_blocks(rpc: &bitcoin_serai::rpc::Rpc, count: usize) -> Result<(), String> {
  rpc
    .call::<Vec<String>>("generatetoaddress", &format!(r#"[{count}, "{BITCOIN_MINING_ADDRESS}"]"#))
    .await
    .map(|_| ())
    .map_err(|e| format!("failed to mine Bitcoin block(s): {e:?}"))
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

/// Mine `INITIAL_BLOCKS` blocks on each external network, then a block per `BLOCK_INTERVAL` on
/// each, forever.
pub(crate) async fn mine(ops: &DockerOperations, handles: &Handles) {
  let bitcoin = handles.bitcoin(ops).await;
  let monero = handles.monero(ops).await;

  println!("Mining {INITIAL_BLOCKS} blocks on Bitcoin and Monero...");
  mine_bitcoin_blocks(&bitcoin, INITIAL_BLOCKS).await.unwrap();
  mine_monero_blocks(&monero, INITIAL_BLOCKS).await.unwrap();

  println!("Mining a block per minute on Bitcoin and Monero...");
  loop {
    tokio::time::sleep(BLOCK_INTERVAL).await;
    // Log, without halting the network, on transient RPC failures
    if let Err(e) = mine_bitcoin_blocks(&bitcoin, 1).await {
      println!("{e}");
    }
    if let Err(e) = mine_monero_blocks(&monero, 1).await {
      println!("{e}");
    }
  }
}
