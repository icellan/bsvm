// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Trivial state-churn contract: set(key, value) writes value
///         to a mapping slot derived from the key. Used to stress MPT.
contract Storage {
    mapping(uint256 => uint256) public slots;

    event Set(uint256 indexed key, uint256 value);

    function set(uint256 key, uint256 value) external {
        slots[key] = value;
        emit Set(key, value);
    }
}
