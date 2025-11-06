// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title FastPath Multi-Attestor VRF Verifier
/// @notice Decentralized VRF verification with multiple independent attestors
/// @dev Implements 2-of-3 or 3-of-5 threshold verification for Bitcoin UTXO ownership
contract FastPathMultiAttestorVerifier is UUPSUpgradeable, OwnableUpgradeable {
    using ECDSA for bytes32;

    // ============ Events ============
    event AttestorAdded(address indexed attestor, string attestorId);
    event AttestorRemoved(address indexed attestor);
    event ThresholdUpdated(uint256 oldThreshold, uint256 newThreshold);
    event MultiAttestationVerified(
        bytes32 indexed utxoHash,
        address[] attestors,
        bytes32 combinedOutput
    );

    // ============ State Variables ============
    
    /// @notice Mapping of attestor addresses to their metadata
    mapping(address => AttestorInfo) public attestors;
    
    /// @notice Array of active attestor addresses
    address[] public attestorList;
    
    /// @notice Minimum number of attestors required (e.g., 2 for 2-of-3)
    uint256 public threshold;
    
    /// @notice Total number of registered attestors
    uint256 public attestorCount;
    
    /// @notice Domain separator for signature verification
    bytes32 public constant DOMAIN = keccak256("FastPathMultiAttestorV1");
    
    /// @notice Tracks verified UTXOs to prevent replay attacks
    mapping(bytes32 => bool) public verifiedUTXOs;

    // ============ Structs ============
    
    struct AttestorInfo {
        bool active;
        string attestorId;
        uint256 verificationCount;
        uint256 addedAt;
    }
    
    struct VRFAttestation {
        address attestor;       // Attestor address
        bytes32 vrfOutput;      // VRF output (beta)
        bytes vrfProof;         // VRF proof (80 bytes for RFC 9381)
        bytes signature;        // ECDSA signature (65 bytes)
        bytes32 utxoHash;       // Hash of Bitcoin UTXO (txid + vout)
    }
    
    struct MultiAttestationBundle {
        VRFAttestation[] attestations;  // Array of attestations
        bytes32 bitcoinTxId;            // Bitcoin transaction ID
        uint32 vout;                    // UTXO output index
        uint256 blockHeight;            // Bitcoin block height
        uint64 value;                   // UTXO value in satoshis
    }

    // ============ Initialization ============
    
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address[] memory _attestors,
        string[] memory _attestorIds,
        uint256 _threshold
    ) public initializer {
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
        
        require(_attestors.length == _attestorIds.length, "Length mismatch");
        require(_threshold > 0 && _threshold <= _attestors.length, "Invalid threshold");
        
        threshold = _threshold;
        
        for (uint256 i = 0; i < _attestors.length; i++) {
            _addAttestor(_attestors[i], _attestorIds[i]);
        }
    }

    // ============ Core Verification ============
    
    /// @notice Verifies Bitcoin UTXO ownership using multiple attestors
    /// @param bundle Multi-attestation bundle with proofs from multiple attestors
    /// @return combinedOutput The combined VRF output from all attestors
    function verifyMultiAttestation(MultiAttestationBundle calldata bundle) 
        external 
        returns (bytes32 combinedOutput) 
    {
        require(bundle.attestations.length >= threshold, "Insufficient attestations");
        
        // Create UTXO hash for verification
        bytes32 utxoHash = keccak256(abi.encodePacked(
            bundle.bitcoinTxId,
            bundle.vout,
            bundle.blockHeight,
            bundle.value
        ));
        
        require(!verifiedUTXOs[utxoHash], "UTXO already verified");
        
        uint256 validCount = 0;
        bytes32[] memory vrfOutputs = new bytes32[](bundle.attestations.length);
        address[] memory validAttestors = new address[](bundle.attestations.length);
        
        // Verify each attestation
        for (uint256 i = 0; i < bundle.attestations.length; i++) {
            VRFAttestation calldata att = bundle.attestations[i];
            
            // Check attestor is registered and active
            require(attestors[att.attestor].active, "Invalid attestor");
            
            // Verify UTXO hash matches
            require(att.utxoHash == utxoHash, "UTXO hash mismatch");
            
            // Verify VRF proof structure
            require(att.vrfProof.length == 80, "Invalid VRF proof length");
            require(att.vrfOutput != bytes32(0), "Zero VRF output");
            require(att.signature.length == 65, "Invalid signature length");
            
            // Verify ECDSA signature
            bytes32 digest = keccak256(abi.encodePacked(
                DOMAIN,
                att.utxoHash,
                att.vrfOutput,
                att.vrfProof
            ));
            
            address recovered = digest.toEthSignedMessageHash().recover(att.signature);
            require(recovered == att.attestor, "Invalid signature");
            
            // Store valid attestation
            vrfOutputs[validCount] = att.vrfOutput;
            validAttestors[validCount] = att.attestor;
            validCount++;
            
            // Update attestor stats
            attestors[att.attestor].verificationCount++;
        }
        
        // Check threshold met
        require(validCount >= threshold, "Threshold not met");
        
        // Combine VRF outputs (XOR for simplicity, can use other methods)
        combinedOutput = _combineVRFOutputs(vrfOutputs, validCount);
        
        // Mark UTXO as verified
        verifiedUTXOs[utxoHash] = true;
        
        // Trim array to valid attestors only
        address[] memory finalAttestors = new address[](validCount);
        for (uint256 i = 0; i < validCount; i++) {
            finalAttestors[i] = validAttestors[i];
        }
        
        emit MultiAttestationVerified(utxoHash, finalAttestors, combinedOutput);
        
        return combinedOutput;
    }

    // ============ VRF Combination ============
    
    /// @notice Combines multiple VRF outputs into a single output
    /// @dev Uses XOR for Byzantine fault tolerance
    function _combineVRFOutputs(bytes32[] memory outputs, uint256 count) 
        internal 
        pure 
        returns (bytes32 combined) 
    {
        require(count > 0, "No outputs to combine");
        
        combined = outputs[0];
        for (uint256 i = 1; i < count; i++) {
            combined = combined ^ outputs[i];  // XOR combination
        }
        
        // Alternative: Hash combination for better randomness
        // combined = keccak256(abi.encodePacked(outputs));
        
        return combined;
    }

    // ============ Attestor Management ============
    
    /// @notice Adds a new attestor (owner only)
    function addAttestor(address attestor, string memory attestorId) external onlyOwner {
        _addAttestor(attestor, attestorId);
    }
    
    function _addAttestor(address attestor, string memory attestorId) internal {
        require(attestor != address(0), "Zero address");
        require(!attestors[attestor].active, "Attestor already exists");
        
        attestors[attestor] = AttestorInfo({
            active: true,
            attestorId: attestorId,
            verificationCount: 0,
            addedAt: block.timestamp
        });
        
        attestorList.push(attestor);
        attestorCount++;
        
        emit AttestorAdded(attestor, attestorId);
    }
    
    /// @notice Removes an attestor (owner only)
    function removeAttestor(address attestor) external onlyOwner {
        require(attestors[attestor].active, "Attestor not active");
        require(attestorCount - 1 >= threshold, "Would break threshold");
        
        attestors[attestor].active = false;
        attestorCount--;
        
        // Remove from list
        for (uint256 i = 0; i < attestorList.length; i++) {
            if (attestorList[i] == attestor) {
                attestorList[i] = attestorList[attestorList.length - 1];
                attestorList.pop();
                break;
            }
        }
        
        emit AttestorRemoved(attestor);
    }
    
    /// @notice Updates verification threshold (owner only)
    function updateThreshold(uint256 newThreshold) external onlyOwner {
        require(newThreshold > 0 && newThreshold <= attestorCount, "Invalid threshold");
        
        uint256 oldThreshold = threshold;
        threshold = newThreshold;
        
        emit ThresholdUpdated(oldThreshold, newThreshold);
    }

    // ============ View Functions ============
    
    /// @notice Gets all active attestors
    function getActiveAttestors() external view returns (address[] memory) {
        return attestorList;
    }
    
    /// @notice Checks if an attestor is active
    function isActiveAttestor(address attestor) external view returns (bool) {
        return attestors[attestor].active;
    }
    
    /// @notice Gets attestor information
    function getAttestorInfo(address attestor) external view returns (
        bool active,
        string memory attestorId,
        uint256 verificationCount,
        uint256 addedAt
    ) {
        AttestorInfo memory info = attestors[attestor];
        return (info.active, info.attestorId, info.verificationCount, info.addedAt);
    }

    // ============ Upgradability ============
    
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}

