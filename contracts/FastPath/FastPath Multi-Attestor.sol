// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

/// @title FastPath Multi-Attestor VRF Verifier
/// @notice Decentralized VRF verification with multiple independent attestors
/// @dev Implements 2-of-3 or 3-of-5 threshold verification for Bitcoin UTXO ownership
/// @dev VRF proofs follow RFC 9381 ECVRF-ED25519-SHA512-TAI standard
/// @dev This contract verifies ECDSA signatures from attestors; actual VRF verification happens off-chain
contract FastPathMultiAttestorVerifier is 
    UUPSUpgradeable, 
    Ownable2StepUpgradeable, 
    PausableUpgradeable,
    ReentrancyGuardUpgradeable 
{
    using ECDSA for bytes32;
    using Strings for uint256;

    bytes32 private constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant VRF_ATTESTATION_TYPEHASH = keccak256(
        "VRFAttestation(bytes32 utxoHash,bytes32 vrfOutput,bytes vrfProof,uint64 expiresAt,uint256 nonce)"
    );
    bytes32 private constant NAME_HASH = keccak256("FastPathMultiAttestorVerifier");

    // ============ Events ============
    event AttestorAdded(address indexed attestor, string attestorId);
    event AttestorRemoved(address indexed attestor);
    event AttestorSlashed(address indexed attestor, string reason);
    event ThresholdUpdated(uint256 indexed oldThreshold, uint256 indexed newThreshold);
    event MultiAttestationVerified(
        bytes32 indexed utxoHash,
        address[] attestors,
        bytes32 combinedOutput
    );
    event BatchVerificationCompleted(uint256 indexed count, uint256 indexed successCount);
    event FeeDistributed(address indexed attestor, uint256 amount);
    event VerificationFeeUpdated(uint256 indexed oldFee, uint256 indexed newFee);
    event RequiredStakeUpdated(uint256 indexed oldStake, uint256 indexed newStake);
    event StakeUnlockDelayUpdated(uint256 indexed oldDelay, uint256 indexed newDelay);
    event TreasuryUpdated(address indexed oldTreasury, address indexed newTreasury);
    event StakeDeposited(address indexed attestor, uint256 amount, uint256 newTotal);
    event StakeWithdrawalRequested(address indexed attestor, uint256 amount, uint256 releaseTime);
    event StakeWithdrawalClaimed(address indexed attestor, uint256 amount);
    event StakeWithdrawalCancelled(address indexed attestor, uint256 amount);
    event ContractUpgraded(address indexed oldImplementation, address indexed newImplementation);
    event EmergencyPaused(address indexed by);
    event EmergencyUnpaused(address indexed by);
    event AttestorReinstated(address indexed attestor);

    // ============ State Variables ============
    
    /// @notice Mapping of attestor addresses to their metadata
    mapping(address => AttestorInfo) public attestors;
    
    /// @notice Array of active attestor addresses
    address[] public attestorList;
    
    /// @notice Minimum number of attestors required (e.g., 2 for 2-of-3)
    uint256 public threshold;
    
    /// @notice Total number of registered attestors
    uint256 public attestorCount;
    
    /// @notice Domain separator for EIP-712 signature verification (includes chain ID)
    bytes32 public DOMAIN_SEPARATOR;
    uint96 private _cachedChainId;
    address private _cachedThis;
    
    /// @notice Tracks verified UTXOs to prevent replay attacks
    mapping(bytes32 => bool) public verifiedUTXOs;
    
    /// @notice Fee per verification (in wei)
    uint256 public verificationFee;
    
    /// @notice Accumulated fees per attestor (withdrawable)
    mapping(address => uint256) public attestorFees;
    
    /// @notice Slashing stake per attestor (for misbehavior penalties)
    uint256 public requiredStake;
    
    /// @notice Stake locked by each attestor
    mapping(address => uint256) public attestorStakes;
    
    /// @notice Treasury address for protocol fees
    address public treasury;
    
    /// @notice Delay before stake can be withdrawn (in seconds)
    uint256 public stakeUnlockDelay;

    /// @notice Per-attestor nonce to prevent signature replay
    mapping(address => uint256) public attestorNonces;
    
    /// @notice Contract version for upgrade tracking
    uint256 public version;
    
    /// @notice Contract version string
    string public constant CONTRACT_VERSION = "1.0.0";
    
    struct WithdrawalRequest {
        uint256 amount;
        uint256 releaseTime;
    }
    
    /// @notice Pending withdrawal requests per attestor
    mapping(address => WithdrawalRequest) public pendingWithdrawals;
    
    /**
     * @dev Storage gap for future upgrades
     * @dev When adding new state variables in future versions:
     * 1. Add them BEFORE this gap
     * 2. Reduce gap size by the number of new slots used
     * 3. NEVER reorder existing variables
     * 4. Document all storage layout changes
     * 
     * Current storage layout (do not modify order):
     * - attestors (mapping)
     * - attestorList (array)
     * - threshold (uint256)
    * - attestorCount (uint256)
    * - DOMAIN_SEPARATOR (bytes32)
    * - _cachedChainId (uint96)
    * - _cachedThis (address)
     * - verifiedUTXOs (mapping)
     * - verificationFee (uint256)
     * - attestorFees (mapping)
     * - requiredStake (uint256)
     * - attestorStakes (mapping)
     * - treasury (address)
     * - stakeUnlockDelay (uint256)
     * - attestorNonces (mapping)
     * - version (uint256)
    * - CONTRACT_VERSION (constant - not in storage)
    * - pendingWithdrawals (mapping)
    * - __gap[48] (reserved for future use)
     */
    uint256[48] private __gap;

    // ============ Structs ============
    
    struct AttestorInfo {
        bool active;
        string attestorId;
        uint256 verificationCount;
        uint256 addedAt;
        uint256 slashCount;      // Number of times slashed
        bool slashed;            // Currently slashed status
    }
    
    // Compact view struct to avoid "stack too deep" when returning many values
    struct AttestorDetails {
        bool active;
        string attestorId;
        uint256 verificationCount;
        uint256 addedAt;
        uint256 slashCount;
        bool slashed;
        uint256 stake;
        uint256 accumulatedFees;
    }
    
    struct VRFAttestation {
        address attestor;       // Attestor address
        bytes32 vrfOutput;      // VRF output (beta)
        bytes vrfProof;         // VRF proof (80 bytes for RFC 9381)
        bytes signature;        // ECDSA signature (65 bytes)
        bytes32 utxoHash;       // Hash of Bitcoin UTXO (txid + vout)
        uint64 expiresAt;       // Expiration timestamp (unix seconds)
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

    /// @notice Initializes the contract with initial attestors and parameters
    /// @param _attestors Array of initial attestor addresses
    /// @param _attestorIds Array of attestor identifier strings
    /// @param _threshold Minimum number of attestors required for verification
    /// @param _verificationFee Fee charged per verification (in wei)
    /// @param _requiredStake Minimum stake required for attestors
    /// @param _treasury Address to receive protocol fees and slashed stakes
    /// @param _initialOwner Address that will become the contract owner
    function initialize(
        address[] memory _attestors,
        string[] memory _attestorIds,
        uint256 _threshold,
        uint256 _verificationFee,
        uint256 _requiredStake,
        address _treasury,
        address _initialOwner
    ) public initializer {
        require(_initialOwner != address(0), "Invalid owner");
        require(_attestors.length == _attestorIds.length, "Length mismatch");
        require(_threshold > 0 && _threshold <= _attestors.length, "Invalid threshold");
        require(_treasury != address(0), "Invalid treasury");
        
        // Initialize base contracts
        __Ownable2Step_init();
        __UUPSUpgradeable_init();
        __Pausable_init();
        __ReentrancyGuard_init();
        
        // Transfer ownership to specified owner
        _transferOwnership(_initialOwner);
        
        // Set initial version
        version = 1;
        
        // Initialize contract parameters
        threshold = _threshold;
        verificationFee = _verificationFee;
        requiredStake = _requiredStake;
        treasury = _treasury;
        // Set default unlock delay to 7 days; can be updated by owner
        stakeUnlockDelay = 7 days;

        // Initialize EIP-712 domain separator using current chain context
        _refreshDomainSeparator();
        
        // Add initial attestors
        uint256 attestorLength = _attestors.length;
        for (uint256 i = 0; i < attestorLength; ++i) {
            _addAttestor(_attestors[i], _attestorIds[i]);
        }
    }

    // ============ EIP-712 Helpers ============

    function _domainSeparator() internal returns (bytes32) {
        if (
            DOMAIN_SEPARATOR == bytes32(0) ||
            _cachedChainId != uint96(block.chainid) ||
            _cachedThis != address(this)
        ) {
            return _refreshDomainSeparator();
        }
        return DOMAIN_SEPARATOR;
    }

    function _refreshDomainSeparator() internal returns (bytes32) {
        bytes32 separator = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                NAME_HASH,
                keccak256(bytes(CONTRACT_VERSION)),
                block.chainid,
                address(this)
            )
        );
        DOMAIN_SEPARATOR = separator;
        _cachedChainId = uint96(block.chainid);
        _cachedThis = address(this);
        return separator;
    }

    function _computeAttestationDigest(
        VRFAttestation calldata att,
        uint256 nonce,
        bytes32 domainSeparator
    ) private pure returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                VRF_ATTESTATION_TYPEHASH,
                att.utxoHash,
                att.vrfOutput,
                keccak256(att.vrfProof),
                att.expiresAt,
                nonce
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    // ============ Core Verification ============
    
    /// @notice Verifies Bitcoin UTXO ownership using multiple attestors
    /// @param bundle Multi-attestation bundle with proofs from multiple attestors
    /// @return combinedOutput The combined VRF output from all attestors
    /// @dev VRF proof verification (RFC 9381) happens off-chain by attestors
    /// @dev This contract verifies attestor signatures and combines outputs
    function verifyMultiAttestation(MultiAttestationBundle calldata bundle) 
        external 
        payable
        nonReentrant
        whenNotPaused
        returns (bytes32 combinedOutput) 
    {
        require(msg.value >= verificationFee, "Insufficient fee");
        require(bundle.attestations.length >= threshold, "Insufficient attestations");
        require(bundle.attestations.length <= 50, "Too many attestations");
        
        // Create UTXO hash for verification
        bytes32 utxoHash = keccak256(abi.encode(
            bundle.bitcoinTxId,
            bundle.vout,
            bundle.blockHeight,
            bundle.value
        ));
        
        require(!verifiedUTXOs[utxoHash], "UTXO already verified");
        
        uint256 validCount = 0;
        bytes32[] memory vrfOutputs = new bytes32[](bundle.attestations.length);
        address[] memory validAttestors = new address[](bundle.attestations.length);

        bytes32 domainSeparator = _domainSeparator();
        
        // Verify each attestation
        uint256 attestationsLength = bundle.attestations.length;
        for (uint256 i = 0; i < attestationsLength; ++i) {
            VRFAttestation calldata att = bundle.attestations[i];
            
            // Check attestor is registered, active, and not slashed
            require(attestors[att.attestor].active, "Invalid attestor");
            require(!attestors[att.attestor].slashed, "Attestor is slashed");
            
            // Prevent duplicate attestor in same bundle
            for (uint256 j = 0; j < validCount; ++j) {
                require(validAttestors[j] != att.attestor, "Duplicate attestor");
            }
            
            // Verify UTXO hash matches
            require(att.utxoHash == utxoHash, "UTXO hash mismatch");
            // Verify attestation not expired
            require(att.expiresAt == 0 || block.timestamp <= att.expiresAt, "Attestation expired");
            
            // Verify VRF proof structure (RFC 9381: 80 bytes for ED25519)
            require(att.vrfProof.length == 80, "Invalid VRF proof length");
            require(att.vrfOutput != bytes32(0), "Zero VRF output");
            require(att.signature.length == 65, "Invalid signature length");
            
            // Verify ECDSA signature with per-attestor nonce for replay protection
            uint256 currentNonce = attestorNonces[att.attestor];
            bytes32 digest = _computeAttestationDigest(att, currentNonce, domainSeparator);

            address recovered = digest.recover(att.signature);
            require(
                recovered == att.attestor,
                string(
                    abi.encodePacked(
                        "Signature mismatch: expected ",
                        Strings.toHexString(uint160(att.attestor), 20),
                        " got ",
                        Strings.toHexString(uint160(recovered), 20)
                    )
                )
            );
            // consume nonce only after successful verification
            attestorNonces[att.attestor] = currentNonce + 1;
            
            // Store valid attestation
            vrfOutputs[validCount] = att.vrfOutput;
            validAttestors[validCount] = att.attestor;
            ++validCount;
            
            // Update attestor stats and distribute fees
            ++attestors[att.attestor].verificationCount;
        }
        
        // Check threshold met
        require(validCount >= threshold, "Threshold not met");
        
        // Combine VRF outputs using hash-based combination (more robust than XOR)
        combinedOutput = _combineVRFOutputs(vrfOutputs, validCount);
        
        // Mark UTXO as verified
        verifiedUTXOs[utxoHash] = true;
        
        // Distribute fees to participating attestors
        _distributeFees(validAttestors, validCount);
        
        // Trim array to valid attestors only
        address[] memory finalAttestors = new address[](validCount);
        for (uint256 i = 0; i < validCount; ++i) {
            finalAttestors[i] = validAttestors[i];
        }
        
        emit MultiAttestationVerified(utxoHash, finalAttestors, combinedOutput);
        
        return combinedOutput;
    }
    
    /// @notice Batch verification for multiple UTXOs to save gas
    /// @param bundles Array of multi-attestation bundles
    /// @return combinedOutputs Array of combined VRF outputs
    function batchVerifyMultiAttestation(MultiAttestationBundle[] calldata bundles)
        external
        payable
        nonReentrant
        whenNotPaused
        returns (bytes32[] memory combinedOutputs)
    {
    require(bundles.length > 0 && bundles.length <= 50, "Invalid batch size");
    uint256 upfrontFee = verificationFee * bundles.length;
    require(msg.value >= upfrontFee, "Insufficient upfront fee");
        
        combinedOutputs = new bytes32[](bundles.length);
        uint256 successCount = 0;
        
        uint256 bundlesLength = bundles.length;
        for (uint256 i = 0; i < bundlesLength; ++i) {
            (bool success, bytes32 output) = _tryVerifyMultiAttestationInternal(bundles[i]);
            if (success) {
                combinedOutputs[i] = output;
                ++successCount;
            } else {
                combinedOutputs[i] = bytes32(0);
            }
        }
    // Refund unused fee for failed verifications
    uint256 feeUsed = verificationFee * successCount;
    uint256 refund = msg.value - feeUsed;
        if (refund > 0) {
            (bool ok, ) = msg.sender.call{value: refund}("");
            require(ok, "Refund failed");
        }
        
        emit BatchVerificationCompleted(bundles.length, successCount);
        return combinedOutputs;
    }

    /// @notice Internal verification function for batch processing (returns success flag)
    function _tryVerifyMultiAttestationInternal(MultiAttestationBundle calldata bundle)
        internal
        returns (bool, bytes32)
    {
        // Create UTXO hash
        bytes32 utxoHash = keccak256(abi.encode(
            bundle.bitcoinTxId,
            bundle.vout,
            bundle.blockHeight,
            bundle.value
        ));

        if (verifiedUTXOs[utxoHash]) return (false, bytes32(0));
        if (bundle.attestations.length < threshold) return (false, bytes32(0));

        uint256 validCount = 0;
        bytes32[] memory vrfOutputs = new bytes32[](bundle.attestations.length);
        address[] memory validAttestors = new address[](bundle.attestations.length);

        bytes32 domainSeparator = _domainSeparator();

        uint256 attestationsLength = bundle.attestations.length;
        for (uint256 i = 0; i < attestationsLength; ++i) {
            VRFAttestation calldata att = bundle.attestations[i];

            if (!attestors[att.attestor].active || attestors[att.attestor].slashed) continue;
            if (att.utxoHash != utxoHash) continue;
            if (att.vrfProof.length != 80 || att.signature.length != 65) continue;
            if (att.vrfOutput == bytes32(0)) continue;
            if (!(att.expiresAt == 0 || block.timestamp <= att.expiresAt)) continue;

            bool isDuplicate = false;
            for (uint256 j = 0; j < validCount; ++j) {
                if (validAttestors[j] == att.attestor) {
                    isDuplicate = true;
                    break;
                }
            }
            if (isDuplicate) continue;

            uint256 currentNonce = attestorNonces[att.attestor];
            bytes32 digest = _computeAttestationDigest(att, currentNonce, domainSeparator);

            address recovered = digest.recover(att.signature);
            if (recovered != att.attestor) continue;
            attestorNonces[att.attestor] = currentNonce + 1;

            vrfOutputs[validCount] = att.vrfOutput;
            validAttestors[validCount] = att.attestor;
            ++validCount;

            ++attestors[att.attestor].verificationCount;
        }

        if (validCount < threshold) return (false, bytes32(0));

        bytes32 combinedOutput = _combineVRFOutputs(vrfOutputs, validCount);
        verifiedUTXOs[utxoHash] = true;

        _distributeFees(validAttestors, validCount);

        return (true, combinedOutput);
    }

    // ============ VRF Combination ============
    
    /// @notice Combines multiple VRF outputs into a single output
    /// @dev Iterative hash chaining is gas-efficient for large arrays and robust
    function _combineVRFOutputs(bytes32[] memory outputs, uint256 count) 
        internal 
        pure 
        returns (bytes32 combined) 
    {
        require(count != 0, "No outputs to combine");
        combined = outputs[0];
        for (uint256 i = 1; i < count; ++i) {
            combined = keccak256(abi.encodePacked(combined, outputs[i]));
        }
        return combined;
    }
    
    /// @notice Distributes verification fees to participating attestors
    function _distributeFees(address[] memory validAttestors, uint256 count) internal {
        if (verificationFee == 0 || count == 0) return;

        // Handle precision loss: ensure fee can be distributed fairly.
        // If verificationFee < count, each attestor gets 0 and all fees go to the treasury (handled below).
        uint256 feePerAttestor = verificationFee / count;
        uint256 treasuryFee = verificationFee - (feePerAttestor * count); // Remainder to treasury

        for (uint256 i = 0; i < count; ++i) {
            if (feePerAttestor != 0) {
                attestorFees[validAttestors[i]] += feePerAttestor;
            }
        }

        // Always require treasury to be set if any remainder or all fees go to treasury
        if (treasuryFee != 0 && treasury != address(0)) {
            attestorFees[treasury] += treasuryFee;
        } else if (feePerAttestor == 0 && treasury != address(0)) {
            // All fees go to treasury if division results in 0
            attestorFees[treasury] += verificationFee;
        }
    }

    // ============ Attestor Management ============
    
    /// @notice Adds a new attestor (owner only)
    function addAttestor(address attestor, string memory attestorId) external onlyOwner {
        _addAttestor(attestor, attestorId);
    }
    
    function _addAttestor(address attestor, string memory attestorId) internal {
        require(attestor != address(0), "Zero address");
        require(bytes(attestorId).length > 0, "Empty attestor ID");
        require(!attestors[attestor].active, "Attestor already exists");
        
        attestors[attestor] = AttestorInfo({
            active: true,
            attestorId: attestorId,
            verificationCount: 0,
            addedAt: block.timestamp,
            slashCount: 0,
            slashed: false
        });
        
        attestorList.push(attestor);
        ++attestorCount;
        
        emit AttestorAdded(attestor, attestorId);
    }
    
    /// @notice Stake funds as an attestor (required for participation)
    function stakeAsAttestor() external payable {
        require(attestors[msg.sender].active, "Not a registered attestor");
        require(msg.value >= requiredStake, "Insufficient stake");
        
        attestorStakes[msg.sender] += msg.value;
        
        emit StakeDeposited(msg.sender, msg.value, attestorStakes[msg.sender]);
    }
    
    /// @notice Removes an attestor (owner only)
    function removeAttestor(address attestor) external onlyOwner {
        require(attestors[attestor].active, "Attestor not active");
        uint256 currentCount = attestorCount;
        uint256 currentThreshold = threshold;
        require(currentCount - 1 >= currentThreshold, "Would break threshold");
        
        attestors[attestor].active = false;
        attestorCount = currentCount - 1;
        
        // Remove from list
        uint256 listLength = attestorList.length;
        for (uint256 i = 0; i < listLength; ++i) {
            if (attestorList[i] == attestor) {
                attestorList[i] = attestorList[listLength - 1];
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
    
    /// @notice Slashes an attestor for misbehavior (owner only)
    /// @param attestor Address of misbehaving attestor
    /// @param reason Human-readable reason for slashing
    function slashAttestor(address attestor, string memory reason) external onlyOwner {
        require(attestors[attestor].active, "Attestor not active");
        require(!attestors[attestor].slashed, "Already slashed");
        
        attestors[attestor].slashed = true;
        attestors[attestor].slashCount++;
        
        // Transfer stake to treasury
        uint256 stake = attestorStakes[attestor];
        if (stake != 0 && treasury != address(0)) {
            delete attestorStakes[attestor];
            (bool success, ) = treasury.call{value: stake}("");
            require(success, "Stake transfer failed");
        }
        
        emit AttestorSlashed(attestor, reason);
    }
    
    /// @notice Reinstates a slashed attestor (owner only)
    function reinstateAttestor(address attestor) external onlyOwner {
        require(attestors[attestor].active, "Attestor not active");
        require(attestors[attestor].slashed, "Not slashed");
        
        attestors[attestor].slashed = false;

        emit AttestorReinstated(attestor);
    }
    
    // ============ Emergency Functions ============
    
    /// @notice Emergency pause (owner only)
    function pause() external onlyOwner {
        _pause();
        emit EmergencyPaused(msg.sender);
    }
    
    /// @notice Unpause after emergency (owner only)
    function unpause() external onlyOwner {
        _unpause();
        emit EmergencyUnpaused(msg.sender);
    }
    
    /// @notice Update verification fee (owner only)
    function setVerificationFee(uint256 newFee) external onlyOwner {
        uint256 oldFee = verificationFee;
        verificationFee = newFee;
        emit VerificationFeeUpdated(oldFee, newFee);
    }
    
    /// @notice Update required stake (owner only)
    function setRequiredStake(uint256 newStake) external onlyOwner {
        uint256 oldStake = requiredStake;
        requiredStake = newStake;
        emit RequiredStakeUpdated(oldStake, newStake);
    }
    
    /// @notice Update treasury address (owner only)
    function setTreasury(address newTreasury) external onlyOwner {
        require(newTreasury != address(0), "Invalid treasury");
        address oldTreasury = treasury;
        treasury = newTreasury;
        emit TreasuryUpdated(oldTreasury, newTreasury);
    }
    
    /// @notice Update stake unlock delay (owner only)
    function setStakeUnlockDelay(uint256 newDelay) external onlyOwner {
        require(newDelay >= 1 days && newDelay <= 30 days, "Delay out of range");
        uint256 oldDelay = stakeUnlockDelay;
        stakeUnlockDelay = newDelay;
        emit StakeUnlockDelayUpdated(oldDelay, newDelay);
    }
    
    /// @notice Withdraw accumulated fees (attestor only)
    function withdrawFees() external nonReentrant {
        uint256 amount = attestorFees[msg.sender];
        require(amount != 0, "No fees to withdraw");
        
        delete attestorFees[msg.sender];
        
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Withdrawal failed");
        
        emit FeeDistributed(msg.sender, amount);
    }
    
    /// @notice Request stake withdrawal with unlock delay (attestor only)
    function requestStakeWithdrawal(uint256 amount) external nonReentrant {
        require(attestors[msg.sender].active, "Not an attestor");
        require(!attestors[msg.sender].slashed, "Cannot withdraw while slashed");
        require(amount != 0, "Zero amount");
        require(pendingWithdrawals[msg.sender].amount == 0, "Pending withdrawal exists");
        require(attestorStakes[msg.sender] >= amount, "Insufficient stake");

        // Lock stake for withdrawal
        attestorStakes[msg.sender] -= amount;
        uint256 releaseTime = block.timestamp + stakeUnlockDelay;
        pendingWithdrawals[msg.sender] = WithdrawalRequest({
            amount: amount,
            releaseTime: releaseTime
        });
        
        emit StakeWithdrawalRequested(msg.sender, amount, releaseTime);
    }

    /// @notice Claim previously requested stake withdrawal after unlock delay
    function claimStakeWithdrawal() external nonReentrant {
        WithdrawalRequest memory w = pendingWithdrawals[msg.sender];
        require(w.amount != 0, "No pending withdrawal");
        require(block.timestamp >= w.releaseTime, "Unlock delay not passed");

        // Effects: update state before interaction
        delete pendingWithdrawals[msg.sender];

        // Interactions: transfer ETH after state update
        (bool success, ) = msg.sender.call{value: w.amount}("");
        require(success, "Withdrawal failed");
        
        emit StakeWithdrawalClaimed(msg.sender, w.amount);
    }

    /// @notice Cancel a pending stake withdrawal and re-stake the amount
    function cancelStakeWithdrawal() external nonReentrant {
        WithdrawalRequest memory w = pendingWithdrawals[msg.sender];
        require(w.amount != 0, "No pending withdrawal");
        delete pendingWithdrawals[msg.sender];
        attestorStakes[msg.sender] += w.amount;
        
        emit StakeWithdrawalCancelled(msg.sender, w.amount);
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
    
    /// @notice Gets attestor information (struct return to avoid stack-too-deep)
    function getAttestorInfo(address attestor) external view returns (AttestorDetails memory) {
        AttestorInfo memory info = attestors[attestor];
        return AttestorDetails({
            active: info.active,
            attestorId: info.attestorId,
            verificationCount: info.verificationCount,
            addedAt: info.addedAt,
            slashCount: info.slashCount,
            slashed: info.slashed,
            stake: attestorStakes[attestor],
            accumulatedFees: attestorFees[attestor]
        });
    }
    
    /// @notice Gets attestor reputation score (0-10000 basis points)
    /// @dev Score based on verification count, time active, and slash history
    /// @param attestor Address of attestor to score
    /// @return score Reputation score (0-10000, where 10000 = 100%)
    function getAttestorReputationScore(address attestor) external view returns (uint256 score) {
        AttestorInfo memory info = attestors[attestor];
        if (!info.active) return 0;
        
        // Base score starts at 5000 (50%)
        score = 5000;
        
        // Add points for verification count (capped at +3000 = 30%)
        uint256 verificationBonus = info.verificationCount * 10; // 10 points per verification
        if (verificationBonus > 3000) verificationBonus = 3000;
        score += verificationBonus;
        
        // Add points for time active (capped at +1000 = 10%)
        uint256 timeActive = block.timestamp - info.addedAt;
        uint256 daysActive = timeActive / 1 days;
        uint256 timeBonus = daysActive * 10; // 10 points per day
        if (timeBonus > 1000) timeBonus = 1000;
        score += timeBonus;
        
        // Deduct heavily for slashing (1000 points per slash = -10% each)
        uint256 slashPenalty = info.slashCount * 1000;
        if (slashPenalty >= score) {
            return 0; // Slashed attestors get zero score
        }
        score -= slashPenalty;
        
        // Currently slashed? Zero score
        if (info.slashed) return 0;
        
        // Cap at 10000 (100%)
        if (score > 10000) score = 10000;
        
        return score;
    }
    
    /// @notice Gets contract statistics
    function getContractStats() external view returns (
        uint256 totalAttestors,
        uint256 activeThreshold,
        uint256 totalVerifications,
        uint256 currentFee,
        uint256 requiredStakeAmount
    ) {
        uint256 totalVerifications_ = 0;
        uint256 listLength = attestorList.length;
        for (uint256 i = 0; i < listLength; ++i) {
            totalVerifications_ += attestors[attestorList[i]].verificationCount;
        }
        
        return (
            attestorCount,
            threshold,
            totalVerifications_,
            verificationFee,
            requiredStake
        );
    }

    // ============ Upgradability ============
    
    /// @notice Authorizes contract upgrades (owner only)
    /// @dev Required by UUPSUpgradeable to authorize upgrades
    /// @dev Implements comprehensive safety checks for production use
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {
        // Safety check 1: Contract must be paused during upgrades to prevent mid-flight transactions
        require(paused(), "Contract must be paused for upgrade");
        
        // Safety check 2: New implementation must not be zero address
        require(newImplementation != address(0), "Invalid implementation address");
        
        // Safety check 3: New implementation must be a contract (has code)
        require(newImplementation.code.length > 0, "New implementation is not a contract");
        
        // Safety check 4: Cannot upgrade to the same implementation
        bytes32 implementationSlot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        address currentImplementation;
        assembly {
            currentImplementation := sload(implementationSlot)
        }
        require(newImplementation != currentImplementation, "Cannot upgrade to same implementation");
        
        // Safety check 5: Verify new implementation is UUPS compliant
        try UUPSUpgradeable(newImplementation).proxiableUUID() returns (bytes32 slot) {
            require(slot == implementationSlot, "New implementation not UUPS compliant");
        } catch {
            revert("New implementation not UUPS compliant");
        }
        
        emit ContractUpgraded(currentImplementation, newImplementation);
    }
    
    /// @notice Gets the current implementation address
    /// @return implementation The current implementation contract address
    function getImplementation() external view returns (address implementation) {
        bytes32 implementationSlot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        assembly {
            implementation := sload(implementationSlot)
        }
    }
}
