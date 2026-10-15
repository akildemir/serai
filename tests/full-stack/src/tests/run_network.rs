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
    // check btc, eth & xmr node up
    {
      let bitcoin = ops.handle(&handles[0].bitcoin.0).host_port(handles[0].bitcoin.1).unwrap();
      let ethereum = ops.handle(&handles[0].ethereum.0).host_port(handles[0].ethereum.1).unwrap();
      let monero = ops.handle(&handles[0].monero.0).host_port(handles[0].monero.1).unwrap();
      println!("Shared external nodes:");
      println!("  Bitcoin RPC:  http://{RPC_USER}:{RPC_PASS}@{}:{}", bitcoin.0, bitcoin.1);
      println!("  Ethereum RPC: http://{}:{}", ethereum.0, ethereum.1);
      println!("  Monero RPC:   http://{RPC_USER}:{RPC_PASS}@{}:{}", monero.0, monero.1);
    }

    // check validators are up
    for (i, handle) in handles.iter().enumerate() {
      let name = names.get(i).copied().unwrap_or("?");

      let serai = ops.handle(&handle.serai).host_port(9944).unwrap();

      println!("Validator {name}:");
      println!("  Serai RPC:        http://{}:{}", serai.0, serai.1);
      println!("  Ethereum relayer: {}", handle.ethereum_relayer(&ops));
    }
    println!("=====================================================================");
    println!("Network running..");

    // Start mining the external networks: mature the initial coinbase outputs, then a block per
    // minute on each, forever
    let mining_task = {
      let ops = ops.clone();
      let handles = handles[0].clone();
      tokio::spawn(async move { mining::mine(&ops, &handles).await })
    };

    // Bootstrap Serai's Ethereum contracts (once the Ethereum key is set on Serai), then relay the
    // transactions the Ethereum processors sign onto the chain, forever
    let _relay_task = {
      let provider = handles[0].ethereum(&ops).await;
      let router = ethereum::bootstrap(&provider, &serai).await;
      let relayers = handles.iter().map(|handle| handle.ethereum_relayer(&ops)).collect();
      tokio::spawn(ethereum::relay_published_transactions(provider, router, relayers))
    };

    println!("Genesis liquidity deposits may now be made.");
    println!("  Ethereum: {} holds ETH and DAI", ethereum::FUNDED_ADDRESS);
    println!("  To fund another address: `anvil_setBalance <address> <wei>` (RPC) for ETH, and");
    println!("  `mint(address,uint256)` on the DAI contract, from any account, for DAI");

    // Complete the genesis liquidity period (waits for the genesis deposits on every external
    // network, then oraclizes the values, initializing the pools)
    genesis::complete_genesis(&serai).await;

    // The mining task never returns, so joining it keeps the network up forever
    mining_task.await.unwrap();
  })
  .await;
}
