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
------------------------------------------------------------------------------
## 📜 Historical Context

### The Canonical UTXO Pool - Bitcoin History Preserved

Our fixed 5-UTXO pool isn't arbitrary - it represents key moments in Bitcoin's history:

| UTXO | Historical Significance | Details |
|------|------------------------|---------|
| **`f4184fc...e9e16`** | **First Bitcoin Transaction**<br>Satoshi → Hal Finney (10 BTC)<br>*Block 170* | The very first Bitcoin transaction between Satoshi Nakamoto and Hal Finney, marking the beginning of peer-to-peer electronic cash |
| **`0437cd7...a597c9`** | **Early Coinbase**<br>50 BTC block reward<br>*Block 9* | From Bitcoin's first month of existence, representing the early mining era when block rewards were the primary coin distribution |
| **`a1075db...f5d48d`** | **Early Whale Transaction**<br>10,000 BTC transfer<br>*Block 57,043* | One of the largest early transactions, showcasing Bitcoin's capability for substantial value transfer without intermediaries |
| **`777ed67...438ce2`** | **Exchange Era**<br>500 BTC (Mt. Gox era)<br>*Block 91,812* | From the period when Bitcoin began trading on early exchanges, representing the transition from cypherpunk experiment to digital asset |
| **`c2bfb6f...8531b6`** | **Modern Era**<br>1 BTC SegWit transaction<br>*Block 481,824* | Post-SegWit activation, demonstrating Bitcoin's evolution with improved scalability and feature sets |

### Why These Specific UTXOs?

- **Historical Significance**: Each represents a milestone in Bitcoin's evolution
- **Publicly Verifiable**: All transactions are permanently recorded on Bitcoin's blockchain
- **Temporal Diversity**: Spans from 2009 to modern Bitcoin era
- **Technical Evolution**: Shows script evolution from P2PK to P2WPKH

### Security Through Transparency

The fixed pool approach provides:
- **Deterministic Verification**: No ambiguity about which UTXOs are accepted
- **Audit Trail**: Every canonical UTXO has public historical context
- **No Oracle Risk**: No dependency on real-time Bitcoin state
- **Reproducible**: Anyone can verify the merkle tree construction

---

*These UTXOs aren't just data points - they're pieces of Bitcoin's story, now preserved as trust anchors for cross-chain verification.*

"We speak Bitcoin in Ethereum. Your dApp talks to Bitcoin exactly like it talks to Ethereum - same calls, same tools, same developers. 
No multisig risks, no wrapped token compromises - just pure cryptographic verification with a unified interface."

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


