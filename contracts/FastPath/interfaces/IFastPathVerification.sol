// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @title IFastPathVerification
 * @notice Interface for FastPath VRF + Bitcoin anchor verification (fixed 5-UTXO pool)
 */
interface IFastPathVerification {
    // --------- Structs ---------

    struct VRFProof {
        bytes32 publicKey;   // Ed25519 VRF public key (32 bytes)
        bytes32 output;      // VRF output (truncated to 32 bytes for on-chain binding)
        bytes   proof;       // RFC 9381 proof (80 bytes)
    }

    struct BitcoinAnchor {
        bytes32 txid;        // Bitcoin txid (big-endian, 32 bytes)
        uint32  vout;        // Output index
        uint256 blockHeight; // Block where the UTXO was created
        uint256 spentAtBlock;// Block where the UTXO was spent (temporal proof)
        uint256 value;       // Satoshis
    }

    struct IPFSManifest {
        string  cidString;   // Full CID string (e.g., bafk...)
        bytes32 merkleRoot;  // Merkle root of the fixed UTXO pool
    }

    struct NFTIdentifier {
        address collection;  // Optional: collection address for provenance
        uint256 tokenId;     // Optional: token id for provenance
        string  collectionName; // Optional human-readable label
    }

    struct ProductionSeal {
        bytes32 publicKey;   // Ed25519 signing key (used off-chain)
        bytes   signature;   // 65-byte secp256k1 attestation (EIP-191) from FastPath attestor
        uint256 signedAt;    // Unix timestamp (seconds)
    }

    struct VerificationBundle {
        bytes32        requestId;      // Unique request id
        NFTIdentifier  nft;            // Optional provenance context
        VRFProof       vrfProof;       // VRF cryptographic proof (checked off-chain by attestor)
        BitcoinAnchor  bitcoinAnchor;  // Temporal anchor fields
        IPFSManifest   ipfsManifest;   // Must match canonical CID/root
        ProductionSeal seal;           // Attestor’s ECDSA signature binding all fields
        address        verifier;       // Caller asserting verification (e.g., depositor)
        uint256        verifiedAt;     // Client-side timestamp (informational)
    }

    // --------- Events ---------

    event NFTVerified(
        bytes32 indexed requestId,
        address indexed collection,
        uint256 indexed tokenId,
        bytes32 btcTxid,
        uint256 verifiedAt
    );

    event ProvenanceRecorded(
        address indexed collection,
        uint256 indexed tokenId,
        address indexed owner,
        bytes32 btcTxid,
        uint256 blockHeight
    );

    // --------- Core ---------

    /**
     * @notice Verify a bundle (attested VRF + Ed25519 + Merkle + anchor) against the fixed pool
     * @return True if the attestation is valid and canonical checks pass
     */
    function verifyOwnership(VerificationBundle calldata bundle) external returns (bool);

    function getProvenanceHistory(
        address collection,
        uint256 tokenId
    ) external view returns (VerificationBundle[] memory);

    function isVerified(
        address collection,
        uint256 tokenId
    ) external view returns (bool);

    function getLatestVerification(
        address collection,
        uint256 tokenId
    ) external view returns (VerificationBundle memory);
}
