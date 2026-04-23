// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Minimal WETH — wraps native balance 1:1.
contract MinimalWETH {
    string public constant name = "Wrapped BSV";
    string public constant symbol = "wBSV";
    uint8  public constant decimals = 18;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    event Deposit(address indexed dst, uint256 wad);
    event Withdrawal(address indexed src, uint256 wad);
    event Transfer(address indexed from, address indexed to, uint256 wad);
    event Approval(address indexed owner, address indexed spender, uint256 wad);

    receive() external payable { _deposit(msg.sender, msg.value); }

    function deposit() external payable { _deposit(msg.sender, msg.value); }

    function withdraw(uint256 wad) external {
        require(balanceOf[msg.sender] >= wad, "balance");
        balanceOf[msg.sender] -= wad;
        totalSupply -= wad;
        (bool ok, ) = msg.sender.call{value: wad}("");
        require(ok, "send");
        emit Withdrawal(msg.sender, wad);
    }

    function approve(address spender, uint256 wad) external returns (bool) {
        allowance[msg.sender][spender] = wad;
        emit Approval(msg.sender, spender, wad);
        return true;
    }

    function transfer(address to, uint256 wad) external returns (bool) {
        _transfer(msg.sender, to, wad);
        return true;
    }

    function transferFrom(address from, address to, uint256 wad) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        require(a >= wad, "allowance");
        if (a != type(uint256).max) { allowance[from][msg.sender] = a - wad; }
        _transfer(from, to, wad);
        return true;
    }

    function _deposit(address dst, uint256 wad) internal {
        balanceOf[dst] += wad;
        totalSupply += wad;
        emit Deposit(dst, wad);
    }

    function _transfer(address from, address to, uint256 wad) internal {
        require(balanceOf[from] >= wad, "balance");
        unchecked { balanceOf[from] -= wad; }
        balanceOf[to] += wad;
        emit Transfer(from, to, wad);
    }
}
