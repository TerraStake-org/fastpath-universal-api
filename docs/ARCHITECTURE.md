# 🏗️ FastPath Universal API Architecture

## 🎯 System Overview

FastPath enables Bitcoin→Ethereum bridging using cryptographic proofs and an attested bundle,
*not* a multisig. Developers interact with an EVM-shaped interface; off-chain services verify Bitcoin/VRF facts and attest once.

## 🧩 Components

* **Off‑chain Attestor (FastPath service)**

  * Verifies: RFC 9381 ECVRF (ed25519‑TAI), Ed25519ph production seal, domain‑separated Merkle inclusion in the **fixed 5‑UTXO pool**, and Bitcoin temporal anchor (UTXO spent).
  * Produces a 65‑byte **secp256k1 ECDSA attestation** over canonical fields.
* **`FastPathVRFVerifier` (Solidity)**

  * Checks canonical CID + Merkle root.
  * Enforces `txid` ∈ known pool and **attestation signature** matches `fastPathAttestor`.
* **`BitcoinDeFi` (bridge)**

  * Single entry `depositBitcoin(bundle)` → mints sBTC if `verifyOwnership` passes.
  * Tracks used UTXOs by **`keccak(txid, vout)`**.
* **`BitcoinDepositLib`**

  * Fee math, min/max limits, pre-mark used UTXO; returns `(gross, net, fee)`.
* **`RedemptionLib`**

  * Burns sBTC and records redemption intent; owner fulfills with BTC txid (can be upgraded to attested payout later).
* **`SyntheticBTC` (sBTC)**

  * ERC‑20 (default 18 decimals; optional 8). `MINTER_ROLE` restricted to bridge.
* **Canonical Dataset**

  * Fixed 5 historic UTXOs; published Merkle root and CID (v2) embedded in contracts.

## 🗺️ ASCII Data Flow

```
User → Wallet/SDK → BitcoinDeFi.depositBitcoin(bundle)
                       │
                       ▼
            FastPathVRFVerifier.verifyOwnership
     ┌─────────────────────────────────────────────┐
     │ 1) Check CID & MerkleRoot against constants │
     │ 2) Check UTXO txid ∈ known pool             │
     │ 3) ecrecover(attestation) == attestor       │
     └─────────────────────────────────────────────┘
                       │  (true)
                       ▼
        BitcoinDepositLib.processDeposit()
        - key = keccak(txid,vout)
        - mark used → mint net to user, fee to treasury
                       ▼
                 sBTC minted
```

## 🔐 Attestation (digest summary)

* Domain: `keccak256("FastPathV1:verify")`
* Digest fields (ABI‐encoded in this order):

  * domain, `bundle.requestId`, `ipfsManifest.merkleRoot`, `keccak(bytes(cidString))`,
  * `bitcoinAnchor.txid`, `blockHeight`, `spentAtBlock`, `value`,
  * `vrfProof.output`, `keccak(vrfProof.proof)`
* Sign: `toEthSignedMessageHash(digest)` with `fastPathAttestor` key → `{r,s,v}` stored in `bundle.seal.signature`.

## ⚙️ Translator (Universal RPC)

* Public API exposes EVM‑shaped JSON‑RPC for multiple chains; e.g., `eth_blockNumber` → BTC `getblockcount` and returns hex.
* This is orthogonal to mint/redeem; used for a unified dev experience and monitoring.

## 🛡️ Security Model (high‑level)

* **Replay Resistance**: Digest binds requestId, CID/root, txid, heights, value, VRF output, proof hash.
* **DoS Hardening**: UTXO key is `txid+vout`; pre‑marked used before external mints.
* **Constant Canonical Set**: Contract rejects bundles outside the fixed pool.
* **Upgradability**: UUPS; owner‑gated `_authorizeUpgrade`. Attestor updatable via `updateAttestor`.

## 🚨 Failure Modes & Handling

* Bad bundle → revert `InvalidAttestation` / CID/root mismatch / unknown txid.
* Duplicate UTXO → revert `BitcoinTxAlreadyUsed`.
* Fee/limit violations → revert on lib checks.

## 📈 Observability

* Events: `ProofVerified`, `BitcoinDeposited`, `BitcoinMinted`, `BitcoinRedeemed` (+ `RedemptionFulfilled`).
* Expose `/status`, `/latest`, `/metrics` in the off‑chain service for ops.

## 🧪 Test Matrix (essentials)

* Verifier: correct attestation pass/fail, wrong CID/root, unknown txid, mutated VRF proof.
* Deposit: txid+vout uniqueness, fee math, min/max, treasury accrual.
* Bridge: end‑to‑end happy path, pause/upgrade paths.

## 🔧 Config

* Attestor address, treasury, fee (≤ 5%), min/max sats are settable by owner.
* sBTC decimals: 18 by default; switch to 8 for satoshi parity if desired (adjust lib accordingly).
