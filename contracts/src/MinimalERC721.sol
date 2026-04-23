// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Minimal ERC-721 with open mint. Sequential token IDs.
contract MinimalERC721 {
    uint256 public totalSupply;
    mapping(uint256 => address) public ownerOf;
    mapping(address => uint256) public balanceOf;
    mapping(uint256 => address) public getApproved;

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed spender, uint256 indexed tokenId);

    /// @notice Mints a new token to `to`. Returns its id.
    function mint(address to) external returns (uint256 id) {
        require(to != address(0), "zero");
        id = totalSupply;
        totalSupply = id + 1;
        ownerOf[id] = to;
        balanceOf[to] += 1;
        emit Transfer(address(0), to, id);
    }

    function approve(address spender, uint256 id) external {
        address owner = ownerOf[id];
        require(msg.sender == owner, "owner");
        getApproved[id] = spender;
        emit Approval(owner, spender, id);
    }

    function transferFrom(address from, address to, uint256 id) external {
        require(ownerOf[id] == from, "from");
        require(to != address(0), "zero");
        require(msg.sender == from || getApproved[id] == msg.sender, "auth");
        balanceOf[from] -= 1;
        balanceOf[to] += 1;
        ownerOf[id] = to;
        getApproved[id] = address(0);
        emit Transfer(from, to, id);
    }
}
