// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "../interfaces/IFastPathVerification.sol";
import "../SyntheticBTC.sol";
import "../libraries/BitcoinDepositLib.sol";
import "../libraries/RedemptionLib.sol";

/**
 * @title BitcoinDeFi
 * @notice Bridge Bitcoin to Ethereum via VRF proofs
 */
contract BitcoinDeFi is 
    Initializable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    OwnableUpgradeable,
    UUPSUpgradeable 
{
    IFastPathVerification public vrfVerifier;
    SyntheticBTC public syntheticBTC;
    
    // Storage
    mapping(bytes32 => bool) public usedBitcoinTxs; // key = keccak256(txid|vout)
    mapping(address => bytes32[]) public userDeposits;
    mapping(bytes32 => RedemptionLib.RedemptionRequest) public redemptions;
    
    uint256 public redemptionNonce;
    uint256 public minDepositSatoshis;
    uint256 public maxDepositSatoshis;
    uint256 public depositFee;
    uint256 public constant MAX_FEE = 500;
    address public treasury;
    uint256 public totalFeesCollected;
    
    error InvalidProof();
    error InvalidFee(uint256 fee);
    
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }
    
    function initialize(address _vrfVerifier, address _treasury) external initializer {
        __ReentrancyGuard_init();
        __Pausable_init();
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
        
        vrfVerifier = IFastPathVerification(_vrfVerifier);
        treasury = _treasury;
        
        syntheticBTC = new SyntheticBTC();
        syntheticBTC.initialize();
        syntheticBTC.grantRole(syntheticBTC.MINTER_ROLE(), address(this));
        
        minDepositSatoshis = 10000;
        maxDepositSatoshis = 1000000000;
        depositFee = 30;
    }
    
    /**
     * @notice Deposit Bitcoin and mint sBTC
     */
    function depositBitcoin(
        IFastPathVerification.VerificationBundle calldata bundle
    ) external nonReentrant whenNotPaused {
        if (!vrfVerifier.verifyOwnership(bundle)) revert InvalidProof();
        
        BitcoinDepositLib.DepositParams memory params = BitcoinDepositLib.DepositParams({
            sBTC: syntheticBTC,
            treasury: treasury,
            depositFee: depositFee,
            minSatoshis: minDepositSatoshis,
            maxSatoshis: maxDepositSatoshis
        });
        
        (, , uint256 feeAmount) = BitcoinDepositLib.processDeposit(
            params,
            bundle,
            usedBitcoinTxs,
            msg.sender
        );
        
        userDeposits[msg.sender].push(bundle.bitcoinAnchor.txid);
        totalFeesCollected += feeAmount;
    }
    
    /**
     * @notice Request Bitcoin redemption
     */
    function requestRedemption(
        uint256 amount,
        bytes calldata btcAddress
    ) external nonReentrant whenNotPaused returns (bytes32 redemptionId) {
        uint256 satoshis;
        (redemptionId, satoshis) = RedemptionLib.createRedemption(
            syntheticBTC,
            amount,
            btcAddress,
            msg.sender,
            redemptionNonce++
        );
        
        redemptions[redemptionId] = RedemptionLib.RedemptionRequest({
            holder: msg.sender,
            sBTCBurned: amount,
            satoshisToRedeem: satoshis,
            btcAddress: btcAddress,
            requestedAt: block.timestamp,
            isFulfilled: false
        });
    }
    
    /**
     * @notice Fulfill redemption
     */
    function fulfillRedemption(bytes32 redemptionId, bytes32) external onlyOwner {
        redemptions[redemptionId].isFulfilled = true;
    }
    
    // View functions
    function getUserDeposits(address user) external view returns (bytes32[] memory) {
        return userDeposits[user];
    }
    
    function getTVL() external view returns (uint256) {
        return syntheticBTC.totalBitcoinLocked();
    }
    
    // Admin
    function setLimits(uint256 _min, uint256 _max) external onlyOwner {
        require(_min < _max);
        minDepositSatoshis = _min;
        maxDepositSatoshis = _max;
    }
    
    function setDepositFee(uint256 _fee) external onlyOwner {
        depositFee = _fee; // Library validates the fee cap
    }
    
    function setTreasury(address _treasury) external onlyOwner {
        treasury = _treasury;
    }
    
    function pause() external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }
    function _authorizeUpgrade(address) internal override onlyOwner {}
}

