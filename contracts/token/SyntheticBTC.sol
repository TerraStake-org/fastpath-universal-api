// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20BurnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title SyntheticBTC (sBTC)
 * @notice 1:1 Bitcoin-backed synthetic token
 * @dev OpenZeppelin 5.4.0 compatible
 */
contract SyntheticBTC is 
    Initializable,
    ERC20Upgradeable,
    ERC20BurnableUpgradeable,
    ERC20PausableUpgradeable,
    AccessControlUpgradeable,
    UUPSUpgradeable 
{
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    
    // Track minting per Bitcoin TX (prevent double-minting)
    mapping(bytes32 => uint256) public mintedPerBitcoinTx;
    
    // Total Bitcoin value locked
    uint256 public totalBitcoinLocked;
    
    event BitcoinMinted(
        bytes32 indexed btcTxHash,
        address indexed recipient,
        uint256 amount,
        uint256 totalLocked
    );
    
    event BitcoinRedeemed(
        address indexed holder,
        uint256 amount,
        bytes32 indexed btcTxHash,
        uint256 totalLocked
    );
    
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }
    
    function initialize() external initializer {
        __ERC20_init("Synthetic Bitcoin", "sBTC");
        __ERC20Burnable_init();
        __ERC20Pausable_init();
        __AccessControl_init();
        __UUPSUpgradeable_init();
        
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);
        _grantRole(UPGRADER_ROLE, msg.sender);
    }
    
    /**
     * @notice Mint sBTC backed by Bitcoin deposit
     * @dev Only callable by BitcoinDeFi contract
     */
    function mint(
        address to,
        uint256 amount,
        bytes32 btcTxHash
    ) external onlyRole(MINTER_ROLE) {
        require(amount > 0, "Zero amount");
        
        // Track minting per Bitcoin TX
        mintedPerBitcoinTx[btcTxHash] += amount;
        totalBitcoinLocked += amount;
        
        _mint(to, amount);
        
        emit BitcoinMinted(btcTxHash, to, amount, totalBitcoinLocked);
    }
    
    /**
     * @notice Burn sBTC to redeem Bitcoin
     */
    function burnForRedemption(uint256 amount, bytes32 expectedBtcTxHash) external {
        require(amount > 0, "Zero amount");
        require(balanceOf(msg.sender) >= amount, "Insufficient balance");
        
        totalBitcoinLocked -= amount;
        
        _burn(msg.sender, amount);
        
        emit BitcoinRedeemed(msg.sender, amount, expectedBtcTxHash, totalBitcoinLocked);
    }
    
    /**
     * @notice Get amount minted for specific Bitcoin TX
     */
    function getMintedAmount(bytes32 btcTxHash) external view returns (uint256) {
        return mintedPerBitcoinTx[btcTxHash];
    }
    
    /**
     * @notice Pause token transfers (emergency)
     */
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }
    
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }
    
    // ============ OpenZeppelin 5.x Override ============
    
    /**
     * @dev Override required by OpenZeppelin 5.x
     * Replaces deprecated _beforeTokenTransfer
     */
    function _update(
        address from,
        address to,
        uint256 value
    ) internal override(ERC20Upgradeable, ERC20PausableUpgradeable) {
        super._update(from, to, value);
    }
    
    function _authorizeUpgrade(address newImplementation) 
        internal 
        override 
        onlyRole(UPGRADER_ROLE) 
    {}
}
