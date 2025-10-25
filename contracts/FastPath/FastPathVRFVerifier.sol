// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";
import "./interfaces/IFastPathVerification.sol";

contract FastPathVRFVerifier is
    Initializable,
    OwnableUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable,
    IFastPathVerification
{
    using ECDSAUpgradeable for bytes32;

    // ============ Constants ============
    bytes32 public constant CANONICAL_UTXO_CID =
        keccak256("bafkreiaw5csnjj2tiplhhz72qfq4ab5hlhral3x3iy2k4chk377bmbpivy");
    bytes32 public constant CANONICAL_MERKLE_ROOT =
        0xc0bf4602062643725c8ada560c71ab6a897bc17abf0ee1d76cd85ab681aafa6e;
    uint256 public constant MIN_CONFIRMATIONS = 6;
    uint256 public constant MAX_VERIFICATIONS = 10_000;
    
    // Domain separator with contract + chain binding
    bytes32 public constant DOMAIN = keccak256("FastPathV1:verify");

    // ============ State Variables (Upgradeable Keys) ============
    bytes32 public fastPathVRFKey = 0x2909f6f6dfa87a14cdf85783f8ec09148e08bd89036ee0f54ef9b1ff3ebae43b;
    bytes32 public fastPathSigningKey = 0x7689ca2f6b19eb0fef04a81953f2dcab685b4158d78ca5287ee998e8469fbde4;
    
    // ============ ECDSA Attestor ============
    address public fastPathAttestor;

    // ============ Storage ============
    mapping(bytes32 => bool) public knownUTXOs;
    mapping(bytes32 => bool) public usedRequests;
    mapping(bytes32 => VerificationRecord) public verifications;
    bytes32[] public verificationList;

    // NFT-specific storage (for optional NFT functionality)
    mapping(address => mapping(uint256 => VerificationBundle[])) private _provenanceHistory;
    mapping(address => mapping(uint256 => bytes32)) public latestVerification;

    struct VerificationRecord {
        bytes32 requestId;
        bytes32 btcTxid;
        address verifier;
        uint256 timestamp;
        string useCase;
    }

    // ============ Events ============
    event ProofVerified(
        bytes32 indexed requestId,
        bytes32 indexed btcTxid,
        address indexed verifier,
        string useCase,
        uint256 timestamp
    );
    event CanonicalUTXOVerified(bytes32 indexed btcTxid, uint256 timestamp);
    event AttestorUpdated(address indexed attestor);

    // ============ Errors ============
    error RequestAlreadyUsed(bytes32 requestId);
    error InsufficientConfirmations(uint256 required, uint256 actual);
    error InvalidBitcoinAnchor();
    error InvalidCanonicalCID();
    error MerkleRootMismatch();
    error UTXONotInCanonicalPool(bytes32 txid);
    error ZeroRequestID();
    error InvalidAttestation();
    error InvalidVout(); // New error for vout validation

    // ============ Initialization ============
    constructor() {
        _disableInitializers();
    }

    function initialize(address attestor) external initializer {
        __Ownable_init(msg.sender);
        __Pausable_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        _initializeKnownUTXOs();
        require(attestor != address(0), "attestor=0");
        fastPathAttestor = attestor;
        emit AttestorUpdated(attestor);
    }

    function _initializeKnownUTXOs() private {
        // All UTXOs have vout = 0 in the canonical pool
        knownUTXOs[0xf4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16] = true;
        knownUTXOs[0x0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9] = true;
        knownUTXOs[0xa1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d] = true;
        knownUTXOs[0x777ed67c58761dcaf3762e64576591c8d39317bcbebf0cb335e138d6ea438ce2] = true;
        knownUTXOs[0xc2bfb6f1bf791308c6b8f73f5d4181be9aa490da6e73c188f9ebd0723e8531b6] = true;
    }

    // ============ Core Verification ============
    function verifyOwnership(VerificationBundle calldata bundle)
        external
        override
        whenNotPaused
        nonReentrant
        returns (bool)
    {
        // Input validation
        if (bundle.requestId == bytes32(0)) revert ZeroRequestID();
        if (usedRequests[bundle.requestId]) revert RequestAlreadyUsed(bundle.requestId);

        // Structural checks
        _verifyBitcoinAnchor(bundle.bitcoinAnchor);
        _verifyIPFSManifest(bundle.ipfsManifest, bundle.bitcoinAnchor);
        _verifyProofStructure(bundle);
        
        // ECDSA attestation verification
        _verifyAttestation(bundle);

        // Record verification
        _recordVerification(bundle);

        // Emit event
        emit ProofVerified(
            bundle.requestId,
            bundle.bitcoinAnchor.txid,
            bundle.verifier,
            bundle.nft.collectionName,
            block.timestamp
        );

        return true;
    }

    // ============ Structural Validation ============
    function _verifyBitcoinAnchor(BitcoinAnchor calldata anchor) private pure {
        uint256 confirmations = anchor.spentAtBlock > anchor.blockHeight
            ? anchor.spentAtBlock - anchor.blockHeight
            : 0;
        if (confirmations < MIN_CONFIRMATIONS) {
            revert InsufficientConfirmations(MIN_CONFIRMATIONS, confirmations);
        }
        require(anchor.value > 0, "Zero BTC value");
        require(anchor.blockHeight > 0, "Invalid block height");
        
        // Validate vout is 0 for all canonical UTXOs
        if (anchor.vout != 0) {
            revert InvalidVout();
        }
    }

    function _verifyIPFSManifest(
        IPFSManifest calldata manifest,
        BitcoinAnchor calldata anchor
    ) private {
        if (keccak256(bytes(manifest.cidString)) != CANONICAL_UTXO_CID) {
            revert InvalidCanonicalCID();
        }
        if (manifest.merkleRoot != CANONICAL_MERKLE_ROOT) {
            revert MerkleRootMismatch();
        }
        if (!knownUTXOs[anchor.txid]) {
            revert UTXONotInCanonicalPool(anchor.txid);
        }
        emit CanonicalUTXOVerified(anchor.txid, block.timestamp);
    }

    function _verifyProofStructure(VerificationBundle calldata bundle) private pure {
        require(bundle.vrfProof.proof.length == 80, "Invalid VRF proof length");
        require(bundle.vrfProof.output != bytes32(0), "Zero VRF output");
        require(bundle.seal.signature.length == 65, "Invalid attestation signature length");
    }

    // ============ ECDSA Attestation ============
    function _verifyAttestation(VerificationBundle calldata b) private view {
        // Enhanced digest with vout + contract + chain binding
        bytes32 digest = keccak256(
            abi.encode(
                DOMAIN,
                address(this),                    // Bind to this verifier
                block.chainid,                    // Bind to chain
                b.requestId,
                b.ipfsManifest.merkleRoot,
                keccak256(bytes(b.ipfsManifest.cidString)),
                b.bitcoinAnchor.txid,             // big-endian
                b.bitcoinAnchor.vout,             // << Added vout
                b.bitcoinAnchor.blockHeight,
                b.bitcoinAnchor.spentAtBlock,
                b.bitcoinAnchor.value,
                b.vrfProof.output,
                keccak256(b.vrfProof.proof)
            )
        );

        // EIP-191 personal-sign style
        address recovered = digest.toEthSignedMessageHash().recover(b.seal.signature);
        if (recovered != fastPathAttestor) revert InvalidAttestation();
    }

    // ============ Storage Management ============
    function _recordVerification(VerificationBundle calldata bundle) private {
        if (verificationList.length >= MAX_VERIFICATIONS) {
            delete verifications[verificationList[0]];
            verificationList[0] = verificationList[verificationList.length - 1];
            verificationList.pop();
        }
        
        usedRequests[bundle.requestId] = true;
        verifications[bundle.requestId] = VerificationRecord({
            requestId: bundle.requestId,
            btcTxid: bundle.bitcoinAnchor.txid,
            verifier: bundle.verifier,
            timestamp: block.timestamp,
            useCase: bundle.nft.collectionName
        });
        verificationList.push(bundle.requestId);
    }

    // ============ Interface Implementation ============
    function getProvenanceHistory(address collection, uint256 tokenId) 
        external 
        view 
        override
        returns (VerificationBundle[] memory) 
    {
        return _provenanceHistory[collection][tokenId];
    }

    function isVerified(address collection, uint256 tokenId) 
        external 
        view 
        override
        returns (bool) 
    {
        return latestVerification[collection][tokenId] != bytes32(0);
    }

    function getLatestVerification(address collection, uint256 tokenId) 
        external 
        view 
        override
        returns (VerificationBundle memory) 
    {
        VerificationBundle[] memory history = _provenanceHistory[collection][tokenId];
        require(history.length > 0, "No verification found");
        return history[history.length - 1];
    }

    // ============ View Functions ============
    function getVerification(bytes32 requestId) external view returns (
        bytes32 btcTxid,
        address verifier,
        uint256 timestamp,
        string memory useCase
    ) {
        VerificationRecord memory record = verifications[requestId];
        return (
            record.btcTxid,
            record.verifier,
            record.timestamp,
            record.useCase
        );
    }

    function getVerificationCount() external view returns (uint256) {
        return verificationList.length;
    }

    function isCanonicalUTXO(bytes32 txid) external view returns (bool) {
        return knownUTXOs[txid];
    }

    function getCanonicalUTXOs() external pure returns (bytes32[5] memory) {
        return [
            bytes32(0xf4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16),
            bytes32(0x0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9),
            bytes32(0xa1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d),
            bytes32(0x777ed67c58761dcaf3762e64576591c8d39317bcbebf0cb335e138d6ea438ce2),
            bytes32(0xc2bfb6f1bf791308c6b8f73f5d4181be9aa490da6e73c188f9ebd0723e8531b6)
        ];
    }

    function getCanonicalPoolInfo() external pure returns (
        bytes32 cid,
        bytes32 merkleRoot,
        uint256 utxoCount
    ) {
        return (CANONICAL_UTXO_CID, CANONICAL_MERKLE_ROOT, 5);
    }

    // ============ Admin Functions ============
    function updateVRFKey(bytes32 newKey) external onlyOwner {
        require(newKey != bytes32(0), "Zero key");
        fastPathVRFKey = newKey;
    }

    function updateSigningKey(bytes32 newKey) external onlyOwner {
        require(newKey != bytes32(0), "Zero key");
        fastPathSigningKey = newKey;
    }

    function updateAttestor(address attestor) external onlyOwner {
        require(attestor != address(0), "attestor=0");
        fastPathAttestor = attestor;
        emit AttestorUpdated(attestor);
    }

    function pause() external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }
    function _authorizeUpgrade(address) internal override onlyOwner {}
}
