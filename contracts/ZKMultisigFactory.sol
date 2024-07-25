// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {Paginator} from "@solarity/solidity-lib/libs/arrays/Paginator.sol";

import {IZKMultisigFactory} from "./interfaces/IZKMultisigFactory.sol";
import {IZKMultisig} from "./interfaces/IZKMultisig.sol";

contract ZKMultisigFactory is EIP712, IZKMultisigFactory {
    using EnumerableSet for EnumerableSet.AddressSet;
    using Paginator for EnumerableSet.AddressSet;

    bytes32 private constant KDF_MESSAGE_TYPEHASH = keccak256("KDF(address zkMultisigAddress)");

    EnumerableSet.AddressSet private _zkMultisigs;

    address public immutable PARTICIPANT_VERIFIER;
    address public immutable ZK_MULTISIG_IMPL;

    constructor(
        address zkMultisigImplementation_,
        address participantVerifier_
    ) EIP712("ZKMultisigFactory", "1") {
        require(
            zkMultisigImplementation_ != address(0) && participantVerifier_ != address(0),
            "ZKMultisigFactory: Invalid implementation or verifier address"
        );

        PARTICIPANT_VERIFIER = participantVerifier_;
        ZK_MULTISIG_IMPL = zkMultisigImplementation_;
    }

    function createMultisig(
        uint256[] calldata participants_,
        uint256 quorumPercentage_,
        uint256 salt_
    ) external returns (address) {
        address zkMultisigAddress_ = address(
            new ERC1967Proxy{salt: keccak256(abi.encode(msg.sender, salt_))}(ZK_MULTISIG_IMPL, "")
        );

        IZKMultisig(zkMultisigAddress_).initialize(
            participants_,
            quorumPercentage_,
            PARTICIPANT_VERIFIER
        );

        _zkMultisigs.add(zkMultisigAddress_);

        emit ZKMutlisigCreated(zkMultisigAddress_, participants_, quorumPercentage_);

        return zkMultisigAddress_;
    }

    function computeZKMultisigAddress(
        address deployer_,
        uint256 salt_
    ) external view returns (address) {
        return
            Create2.computeAddress(
                keccak256(abi.encode(deployer_, salt_)),
                keccak256(
                    abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(ZK_MULTISIG_IMPL))
                )
            );
    }

    function getZKMultisigsCount() external view returns (uint256) {
        return _zkMultisigs.length();
    }

    function getZKMultisigs(
        uint256 offset_,
        uint256 limit_
    ) external view returns (address[] memory) {
        return _zkMultisigs.part(offset_, limit_);
    }

    function isZKMultisig(address multisigAddress_) external view returns (bool) {
        return _zkMultisigs.contains(multisigAddress_);
    }

    function getDefaultKDFMSGToSign() external view returns (bytes32) {
        return _hashTypedDataV4(getKDFMSGHash(address(0)));
    }

    function getKDFMSGToSign(address zkMutlisigAddress_) public view returns (bytes32) {
        return _hashTypedDataV4(getKDFMSGHash(zkMutlisigAddress_));
    }

    function getKDFMSGHash(address zkMutlisigAddress_) private pure returns (bytes32) {
        return keccak256(abi.encode(KDF_MESSAGE_TYPEHASH, zkMutlisigAddress_));
    }
}
