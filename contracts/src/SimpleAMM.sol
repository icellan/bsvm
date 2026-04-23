// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IMinimalERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

/// @notice Uniswap V2-style constant-product pair for two ERC20s. No LP tokens.
///         addLiquidity is owner-only to keep the sim deterministic; swap is
///         open. Fee is fixed at 30 bps.
contract SimpleAMM {
    address public immutable token0;
    address public immutable token1;
    address public immutable owner;
    uint112 public reserve0;
    uint112 public reserve1;

    event Sync(uint112 reserve0, uint112 reserve1);
    event Swap(address indexed sender, uint256 amount0In, uint256 amount1In, uint256 amount0Out, uint256 amount1Out);

    constructor(address _token0, address _token1) {
        token0 = _token0;
        token1 = _token1;
        owner = msg.sender;
    }

    /// @notice Called by the deployer after transferring amounts to this
    ///         contract; snapshots the reserves.
    function addLiquidity(uint112 amount0, uint112 amount1) external {
        require(msg.sender == owner, "owner");
        reserve0 += amount0;
        reserve1 += amount1;
        emit Sync(reserve0, reserve1);
    }

    /// @notice Swap an exact `amountIn` of `tokenIn` for the other token.
    ///         Caller must have approved this contract for `amountIn`.
    function swap(address tokenIn, uint256 amountIn, uint256 minOut) external returns (uint256 out) {
        require(tokenIn == token0 || tokenIn == token1, "token");
        bool zeroForOne = tokenIn == token0;
        (uint112 rIn, uint112 rOut) = zeroForOne ? (reserve0, reserve1) : (reserve1, reserve0);
        require(IMinimalERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn), "pull");
        // x*y=k with 30 bps fee.
        uint256 amountInWithFee = amountIn * 997;
        uint256 numerator = amountInWithFee * rOut;
        uint256 denominator = uint256(rIn) * 1000 + amountInWithFee;
        out = numerator / denominator;
        require(out >= minOut, "slippage");
        address tokenOut = zeroForOne ? token1 : token0;
        require(IMinimalERC20(tokenOut).transfer(msg.sender, out), "push");
        if (zeroForOne) {
            reserve0 = rIn + uint112(amountIn);
            reserve1 = rOut - uint112(out);
        } else {
            reserve1 = rIn + uint112(amountIn);
            reserve0 = rOut - uint112(out);
        }
        emit Swap(msg.sender, zeroForOne ? amountIn : 0, zeroForOne ? 0 : amountIn,
                  zeroForOne ? 0 : out, zeroForOne ? out : 0);
    }
}
