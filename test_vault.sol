// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TestVault {
    uint256 public totalAssets;
    uint256 public totalShares;

    function badMath(uint256 a, uint256 b, uint256 c) public pure returns (uint256) {
        return (a / b) * c;
    }

    function previewWithdraw(uint256 assets) public view returns (uint256) {
        return (assets * totalShares) / totalAssets;
    }
}
EOFcat << 'EOF' > test_vault.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TestVault {
    uint256 public totalAssets;
    uint256 public totalShares;

    function badMath(uint256 a, uint256 b, uint256 c) public pure returns (uint256) {
        return (a / b) * c;
    }

    function previewWithdraw(uint256 assets) public view returns (uint256) {
        return (assets * totalShares) / totalAssets;
    }
}
