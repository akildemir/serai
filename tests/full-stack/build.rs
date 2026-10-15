use std::{env, fs};

fn main() {
  let artifacts_path = env::var("OUT_DIR").unwrap() + "/serai-full-stack-tests";
  if !fs::exists(&artifacts_path).unwrap() {
    fs::create_dir_all(&artifacts_path).unwrap();
  }

  // Build the Router's test contracts for their ERC20, which stands in for DAI on the local
  // Ethereum network
  build_solidity_contracts::build(
    &[
      "../../networks/ethereum/schnorr/contracts",
      "../../processor/ethereum/erc20/contracts",
      "../../processor/ethereum/router/contracts",
    ],
    "../../processor/ethereum/router/contracts/tests",
    &artifacts_path,
  )
  .unwrap();
}
