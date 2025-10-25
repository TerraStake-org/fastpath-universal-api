# ⚡ FastPath Universal API

**Bitcoin ⇄ Ethereum Bridge with Mathematical Proofs, Not Promises**

> Universal RPC interface that makes any blockchain speak Ethereum JSON-RPC. Start with Bitcoin, scale to everything.

## 🚀 Lightning Setup

```bash
# Clone & conquer
git clone https://github.com/TerraStake-org/fastpath-universal-api
cd fastpath-universal-api

# Install the magic
pnpm i

# Compile the future
pnpm hardhat compile

# Test the impossible
forge test -vv
🌉 Bridge Bitcoin in 3 Commands
# 1. Deploy the verifier (mathematical truth machine)
pnpm hardhat run scripts/deploy/01_deploy_verifier.ts --network sepolia

# 2. Launch sBTC (real Bitcoin on Ethereum)
pnpm hardhat run scripts/deploy/02_deploy_sbtc.ts --network sepolia

# 3. Activate the bridge (BTC → sBTC highway)
pnpm hardhat run scripts/deploy/03_deploy_bridge.ts --network sepolia

Traditional Bridges: "Trust our multisig" 🤞
FastPath: "Trust math" 🔐

    ✅ VRF Proofs - Verifiable randomness for fair ordering

    ✅ ECDSA Attestations - Backend-signed verification bundles

    ✅ Canonical UTXO Pool - Only 5 pre-vetted Bitcoin transactions

    ✅ Universal RPC - Bitcoin speaks Ethereum JSON-RPC

🌟 Why This Matters

For Users: Self-custody, instant verification, 75-minute bridges (not 12-hour)
For Developers: One API for all chains, existing tooling just works
For Bitcoin: Real DeFi utility without wrapped token risk

Ready to bridge the impossible? The future speaks Ethereum. 
