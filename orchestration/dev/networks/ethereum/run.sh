#!/bin/sh
set -e

~/.foundry/bin/anvil --host 0.0.0.0 --no-mining --slots-in-an-epoch 32 --silent
