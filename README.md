# ⚡ FastPath Universal API

**Bitcoin ⇄ Ethereum Bridge with Mathematical Proofs, Not Promises**

> 🚧 **ALPHA WARNING**: This is under active development. Core contracts are stabilizing but deployment setup needs completion.

## 🎯 Current Status

| Component | Status | Notes |
|-----------|---------|-------|
| **Core Contracts** | ✅ Stable | BitcoinDeFi, SyntheticBTC, FastPathVRFVerifier |
| **Tests** | ✅ Basic coverage | Foundry tests passing |
| **Deployment Scripts** | 🚧 Scaffolded | Need environment setup |
| **Universal RPC** | 🔮 Ready and tested, will be updated | Bitcoin JSON-RPC → Ethereum translation |
| **Verification Demo** | ✅ Live | [Proof Bundle Verifier](https://terrastake-org.github.io/proof-bundle-verifier-/proof-bundle-verifier.html) |

*Signatures are done via our VRF generator*

## 🛠️ Development Setup

### Prerequisites
```bash
# Node.js + Hardhat
npm install -g hardhat

# Foundry (for tests)
curl -L https://foundry.paradigm.xyz | bash
foundryup

Quick Start
git clone https://github.com/TerraStake-org/fastpath-universal-api
cd fastpath-universal-api

# Install dependencies
npm install

# Compile contracts
npx hardhat compile

# Run tests
forge test -vv
