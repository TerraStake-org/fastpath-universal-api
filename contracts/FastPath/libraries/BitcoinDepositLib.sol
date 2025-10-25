// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "../interfaces/IFastPathVerification.sol";
import "../SyntheticBTC.sol";

library BitcoinDepositLib {
    uint256 private constant SATOSHIS_PER_BTC = 1e8;
    uint256 private constant SBCT_DECIMALS = 1e18;
    uint256 private constant BASIS_POINTS = 10000;
    uint256 private constant MAX_DEPOSIT_FEE = 500; // 5% cap to match core contract
    
    struct DepositParams {
        SyntheticBTC sBTC;
        address treasury;
        uint256 depositFee; // in basis points (1/100 of a percent)
        uint256 minSatoshis;
        uint256 maxSatoshis;
    }
    
    event BitcoinDeposited(
        bytes32 indexed btcTxHash,
        uint32 indexed vout,
        address indexed depositor,
        uint256 satoshis,
        uint256 sBTCMinted,
        uint256 fee
    );
    
    error DepositBelowMinimum(uint256 minimum, uint256 actual);
    error DepositAboveMaximum(uint256 maximum, uint256 actual);
    error BitcoinTxAlreadyUsed(bytes32 btcTxHash, uint32 vout);
    error InvalidDepositFee();
    error InvalidTreasuryAddress();
    error InvalidDepositLimits(uint256 min, uint256 max);
    
    function _key(bytes32 txid, uint32 vout) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(txid, vout));
    }
    
    /**
     * @notice Validate deposit parameters
     */
    function validateParams(DepositParams memory params) internal pure {
        if (params.depositFee > MAX_DEPOSIT_FEE) {
            revert InvalidDepositFee();
        }
        if (params.treasury == address(0)) {
            revert InvalidTreasuryAddress();
        }
        if (params.minSatoshis > params.maxSatoshis) {
            revert InvalidDepositLimits(params.minSatoshis, params.maxSatoshis);
        }
    }
    
    /**
     * @notice Process Bitcoin deposit and mint sBTC
     * @return grossAmount Total sBTC amount before fees
     * @return netAmount sBTC amount after fees
     * @return fee Fee amount in sBTC
     */
    function processDeposit(
        DepositParams memory params,
        IFastPathVerification.VerificationBundle calldata bundle,
        mapping(bytes32 => bool) storage usedTxs,
        address depositor
    ) external returns (uint256 grossAmount, uint256 netAmount, uint256 fee) {
        // Validate parameters
        validateParams(params);
        
        bytes32 btcTxHash = bundle.bitcoinAnchor.txid;
        uint32 vout = bundle.bitcoinAnchor.vout;
        uint256 satoshis = bundle.bitcoinAnchor.value;
        
        // Check not already used
        bytes32 utxoKey = _key(btcTxHash, vout);
        if (usedTxs[utxoKey]) {
            revert BitcoinTxAlreadyUsed(btcTxHash, vout);
        }
        
        // Validate amount
        if (satoshis < params.minSatoshis) {
            revert DepositBelowMinimum(params.minSatoshis, satoshis);
        }
        if (satoshis > params.maxSatoshis) {
            revert DepositAboveMaximum(params.maxSatoshis, satoshis);
        }
        
        // Calculate sBTC amounts (18-dec token): 1 sat = 1e10 token units
        grossAmount = (satoshis * SBCT_DECIMALS) / SATOSHIS_PER_BTC;
        fee = (grossAmount * params.depositFee) / BASIS_POINTS;
        netAmount = grossAmount - fee;
        
        // Mark used *before* minting (Checks-Effects-Interactions pattern)
        usedTxs[utxoKey] = true;
        
        // Mint tokens
        params.sBTC.mint(depositor, netAmount, btcTxHash);
        if (fee > 0) {
            params.sBTC.mint(params.treasury, fee, btcTxHash);
        }
        
        emit BitcoinDeposited(btcTxHash, vout, depositor, satoshis, netAmount, fee);
        
        return (grossAmount, netAmount, fee);
    }
}
