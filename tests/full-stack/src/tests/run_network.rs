use core::time::Duration;
use std::u64;

use crate::tests::{*, RPC_USER, RPC_PASS};

#[tokio::test]
async fn run_local_network() {
  new_test(async move |ops, handles: Vec<Handles>| {
    // ensure the network is up
    let serai = handles[0].serai(&ops).await;

    // serai validator names
    let names = ["Alice", "Bob", "Charlie", "Dave"];

    println!();
    println!("===================== Serai local network is up =====================");
    // check btc & xmr node up
    {
      let bitcoin = ops.handle(&handles[0].bitcoin.0).host_port(handles[0].bitcoin.1).unwrap();
      let monero = ops.handle(&handles[0].monero.0).host_port(handles[0].monero.1).unwrap();
      println!("Shared external nodes:");
      println!("  Bitcoin RPC: http://{RPC_USER}:{RPC_PASS}@{}:{}", bitcoin.0, bitcoin.1);
      println!("  Monero RPC:  http://{RPC_USER}:{RPC_PASS}@{}:{}", monero.0, monero.1);
    }

    // check validators are up
    for (i, handle) in handles.iter().enumerate() {
      let name = names.get(i).copied().unwrap_or("?");

      let serai = ops.handle(&handle.serai).host_port(9944).unwrap();

      println!("Validator {name}:");
      println!("  Serai RPC:   http://{}:{}", serai.0, serai.1);
    }
    println!("=====================================================================");
    println!("Network running..");

    // Complete the genesis liquidity period (waits for BTC/XMR genesis deposits, forges the
    // ETH/DAI genesis liquidity, then oraclizes the values, initializing the pools)
    genesis::complete_genesis(&serai).await;

    // Wait forever
    tokio::time::sleep(Duration::from_secs(u64::MAX)).await;
  })
  .await;
}
