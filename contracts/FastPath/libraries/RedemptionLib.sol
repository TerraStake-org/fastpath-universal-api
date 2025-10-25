// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "../SyntheticBTC.sol";

library RedemptionLib {
    uint256 private constant SATOSHIS_PER_BTC = 1e8;
    uint256 private constant SBCT_DECIMALS = 1e18;
    uint256 private constant MIN_REDEMPTION_SATOSHIS = 546; // Bitcoin dust limit
    
    struct RedemptionRequest {
        address holder;
        uint256 sBTCBurned;
        uint256 satoshisToRedeem;
        bytes btcAddress;
        uint256 requestedAt;
        bool isFulfilled;
    }
    
    event RedemptionRequested(
        bytes32 indexed redemptionId,
        address indexed holder,
        uint256 sBTCBurned,
        uint256 satoshisToRedeem,
        bytes btcAddress
    );
    
    error ZeroAmount();
    error InvalidBtcAddress();
    error InsufficientBalance();
    error RedemptionBelowMinimum(uint256 minimum, uint256 actual);
    
    /**
     * @notice Create redemption request
     * @dev Burns sBTC and creates redemption record
     */
    function createRedemption(
        SyntheticBTC sBTC,
        uint256 amount,
        bytes calldata btcAddress,
        address holder,
        uint256 nonce
    ) external returns (bytes32 redemptionId, uint256 satoshis) {
        if (amount == 0) revert ZeroAmount();
        if (btcAddress.length == 0 || btcAddress.length > 34) revert InvalidBtcAddress();
        if (sBTC.balanceOf(holder) < amount) revert InsufficientBalance();
        
        // Convert sBTC to satoshis (accounting for 18 decimals)
        satoshis = (amount * SATOSHIS_PER_BTC) / SBCT_DECIMALS;
        
        // Check minimum redemption amount (Bitcoin dust limit)
        if (satoshis < MIN_REDEMPTION_SATOSHIS) {
            revert RedemptionBelowMinimum(MIN_REDEMPTION_SATOSHIS, satoshis);
        }
        
        // Burn sBTC - use zero bytes32 for expectedBtcTxHash (will be filled later)
        sBTC.burnForRedemption(amount, bytes32(0));
        
        // Generate redemption ID
        redemptionId = keccak256(abi.encodePacked(
            holder,
            amount,
            btcAddress,
            block.timestamp,
            nonce,
            block.prevrandao
        ));
        
        emit RedemptionRequested(redemptionId, holder, amount, satoshis, btcAddress);
    }
}
