// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Hello — minimal sample contract for the {{PROJECT_NAME}} devnet.
/// @notice Demonstrates that a fresh BSVM devnet can deploy and execute
///         a standard Solidity contract end-to-end.
contract Hello {
    string public greeting;
    address public lastWriter;

    event GreetingChanged(address indexed by, string greeting);

    constructor(string memory initial) {
        greeting = initial;
        lastWriter = msg.sender;
    }

    function setGreeting(string calldata next) external {
        greeting = next;
        lastWriter = msg.sender;
        emit GreetingChanged(msg.sender, next);
    }
}
