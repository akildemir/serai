extern crate alloc;
use alloc::sync::Arc;
use core::time::Duration;

use serai_client_serai::Serai;
use monero_simple_request_rpc::SimpleRequestTransport;

use alloy_simple_request_transport::SimpleRequest;
use alloy_rpc_client::ClientBuilder;
use alloy_provider::{Provider as _, RootProvider};

use dockertest::DockerOperations;

const RPC_USER: &str = "serai";
const RPC_PASS: &str = "seraidex";

#[cfg(test)]
mod tests;

#[expect(unused)]
#[derive(Clone, Debug)]
pub struct Handles {
  bitcoin: (String, u32),
  bitcoin_processor: String,
  ethereum: (String, u32),
  ethereum_processor: String,
  ethereum_relayer: String,
  monero: (String, u32),
  monero_processor: String,
  message_queue: String,
  serai: String,
}

impl Handles {
  pub async fn serai(&self, ops: &DockerOperations) -> Serai {
    let serai_rpc = ops.handle(&self.serai).host_port(9944).unwrap();
    let serai_rpc = format!("http://{}:{}", serai_rpc.0, serai_rpc.1);

    // If the RPC server has yet to start, sleep for up to 60s until it does
    for _ in 0 .. 60 {
      tokio::time::sleep(Duration::from_secs(1)).await;
      let Ok(client) = Serai::new(serai_rpc.clone()) else { continue };
      if client.latest_finalized_block_number().await.is_err() {
        continue;
      }
      return client;
    }
    panic!("serai RPC server wasn't available after 60s");
  }

  pub async fn bitcoin(&self, ops: &DockerOperations) -> bitcoin_serai::rpc::Rpc {
    let rpc = ops.handle(&self.bitcoin.0).host_port(self.bitcoin.1).unwrap();
    let rpc = format!("http://{RPC_USER}:{RPC_PASS}@{}:{}", rpc.0, rpc.1);

    // If the RPC server has yet to start, sleep for up to 60s until it does
    for _ in 0 .. 60 {
      tokio::time::sleep(Duration::from_secs(1)).await;
      let Ok(client) = bitcoin_serai::rpc::Rpc::new(rpc.clone()).await else { continue };
      return client;
    }
    panic!("bitcoin RPC server wasn't available after 60s");
  }

  pub async fn ethereum(&self, ops: &DockerOperations) -> Arc<RootProvider> {
    let rpc = ops.handle(&self.ethereum.0).host_port(self.ethereum.1).unwrap();
    let rpc = format!("http://{}:{}", rpc.0, rpc.1);

    // If the RPC server has yet to start, sleep for up to 60s until it does
    for _ in 0 .. 60 {
      tokio::time::sleep(Duration::from_secs(1)).await;
      let Ok(transport) = SimpleRequest::new(rpc.clone()) else { continue };
      let provider =
        Arc::new(RootProvider::new(ClientBuilder::default().transport(transport, true)));
      if provider.get_chain_id().await.is_err() {
        continue;
      }
      return provider;
    }
    panic!("ethereum RPC server wasn't available after 60s");
  }

  /// The endpoint to fetch the transactions this validator's Ethereum processor published from.
  pub fn ethereum_relayer(&self, ops: &DockerOperations) -> String {
    let (ip, port) = ops.handle(&self.ethereum_relayer).host_port(20831).unwrap();
    format!("{ip}:{port}")
  }

  pub async fn monero(
    &self,
    ops: &DockerOperations,
  ) -> monero_simple_request_rpc::prelude::MoneroDaemon<SimpleRequestTransport> {
    use monero_simple_request_rpc::prelude::ProvidesBlockchainMeta;

    let rpc = ops.handle(&self.monero.0).host_port(self.monero.1).unwrap();
    let rpc = format!("http://{RPC_USER}:{RPC_PASS}@{}:{}", rpc.0, rpc.1);

    // If the RPC server has yet to start, sleep for up to 60s until it does
    for _ in 0 .. 60 {
      tokio::time::sleep(Duration::from_secs(1)).await;
      let Ok(client) = SimpleRequestTransport::new(rpc.clone()).await else { continue };
      if client.latest_block_number().await.is_err() {
        continue;
      }
      return client;
    }
    panic!("monero RPC server wasn't available after 60s");
  }
}
