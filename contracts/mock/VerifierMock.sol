// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

contract PositiveVerifierMock {
    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[3] calldata
    ) public pure returns (bool) {
        return true;
    }
}

contract NegativeVerifierMock {
    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[3] calldata
    ) public pure returns (bool) {
        return false;
    }
}
