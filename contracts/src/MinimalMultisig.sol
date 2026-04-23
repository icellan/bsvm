// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Minimal M-of-N multisig. Owners submit tx proposals; when
///         `required` confirmations are in, anyone can execute.
contract MinimalMultisig {
    address[] public owners;
    mapping(address => bool) public isOwner;
    uint256 public required;

    struct Tx {
        address to;
        uint256 value;
        bytes data;
        bool executed;
        uint256 confirmations;
    }

    Tx[] public txs;
    mapping(uint256 => mapping(address => bool)) public confirmed;

    event Submission(uint256 indexed id, address indexed submitter, address indexed to, uint256 value);
    event Confirmation(uint256 indexed id, address indexed owner);
    event Execution(uint256 indexed id);

    constructor(address[] memory _owners, uint256 _required) {
        require(_owners.length >= _required && _required >= 1, "params");
        for (uint256 i = 0; i < _owners.length; i++) {
            require(_owners[i] != address(0), "zero");
            require(!isOwner[_owners[i]], "dup");
            isOwner[_owners[i]] = true;
            owners.push(_owners[i]);
        }
        required = _required;
    }

    modifier onlyOwner() { require(isOwner[msg.sender], "owner"); _; }

    function submit(address to, uint256 value, bytes calldata data) external onlyOwner returns (uint256 id) {
        id = txs.length;
        txs.push(Tx({ to: to, value: value, data: data, executed: false, confirmations: 0 }));
        emit Submission(id, msg.sender, to, value);
        _confirm(id);
    }

    function confirm(uint256 id) external onlyOwner {
        _confirm(id);
    }

    function execute(uint256 id) external returns (bool ok) {
        Tx storage t = txs[id];
        require(!t.executed, "done");
        require(t.confirmations >= required, "threshold");
        t.executed = true;
        (ok, ) = t.to.call{value: t.value}(t.data);
        require(ok, "call");
        emit Execution(id);
    }

    function _confirm(uint256 id) internal {
        require(!confirmed[id][msg.sender], "once");
        confirmed[id][msg.sender] = true;
        txs[id].confirmations += 1;
        emit Confirmation(id, msg.sender);
    }

    function txCount() external view returns (uint256) { return txs.length; }

    receive() external payable {}
}
