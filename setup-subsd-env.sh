#!/bin/bash
# Source this file with: source setup-subsd-env.sh

export PS1='subsd:\w$ '
export PATH="$HOME/.cargo/bin:$PATH"
export SUBSD_SPACED_RPC_URL=http://127.0.0.1:7224
export SUBSD_SPACED_RPC_USER=testuser
export SUBSD_SPACED_RPC_PASSWORD=SomeRisk84
export SUBSD_DATA_DIR=./data/spaces
export SUBSD_LIST_SUBSPACES=true
export SUBSD_RPC_BIND=0.0.0.0
export SUBSD_RPC_PORT=7244
export SUBSD_RPC_URL=http://0.0.0.0:7244
export SUBSD_RPC_USER=subsdadmin
export SUBSD_RPC_PASSWORD=OtherRisk84
export RUST_LOG=subsd=info,error

echo "cargo run --bin subsd"