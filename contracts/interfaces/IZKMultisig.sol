// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {SparseMerkleTree} from "@solarity/solidity-lib/libs/data-structures/SparseMerkleTree.sol";

interface IZKMultisig {
    enum ProposalStatus {
        NONE,
        VOTING,
        ACCEPTED,
        EXPIRED,
        EXECUTED
    }

    struct ZKParams {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
        uint256[] inputs; // 0 -> blinder, 1 -> challenge, 2 -> SMT root
    }

    struct ProposalContent {
        address target;
        uint256 value;
        bytes data;
    }

    struct ProposalData {
        ProposalContent content;
        uint256 proposalEndTime;
        EnumerableSet.UintSet blinders;
        bool executed;
    }

    struct ProposalInfoView {
        ProposalContent content;
        uint256 proposalEndTime;
        ProposalStatus status;
        uint256 votesCount;
        uint256 requiredQuorum;
    }

    event ProposalCreated(uint256 indexed proposalId, ProposalContent content);

    event ProposalVoted(uint256 indexed proposalId, uint256 voterBlinder);

    event ProposalExecuted(uint256 indexed proposalId);

    function initialize(
        uint256[] memory participants_,
        uint256 quorumPercentage_,
        address participantVerifier_
    ) external;

    function addParticipants(uint256[] calldata participantsToAdd) external;

    function removeParticipants(uint256[] calldata participantsToRemove) external;

    function updateQuorumPercentage(uint256 newQuorumPercentage) external;

    function create(
        ProposalContent calldata content,
        uint256 duration,
        uint256 salt,
        ZKParams calldata proofData
    ) external returns (uint256);

    function vote(uint256 proposalId, ZKParams calldata proofData) external;

    function execute(uint256 proposalId) external payable;

    function getParticipantsSMTRoot() external view returns (bytes32);

    function getParticipantsSMTProof(
        bytes32 publicKeyHash
    ) external view returns (SparseMerkleTree.Proof memory);

    function getParticipantsCount() external view returns (uint256);

    function getParticipants() external view returns (uint256[] memory);

    function getProposalsCount() external view returns (uint256);

    function getProposalsIds(
        uint256 offset,
        uint256 limit
    ) external view returns (uint256[] memory);

    function getQuorumPercentage() external view returns (uint256);

    function getProposalInfo(uint256 proposalId) external view returns (ProposalInfoView memory);

    function getProposalStatus(uint256 proposalId) external view returns (ProposalStatus);

    function getProposalChallenge(uint256 proposalId) external view returns (uint256);

    function computeProposalId(
        ProposalContent calldata content,
        uint256 salt
    ) external view returns (uint256);

    function isBlinderVoted(
        uint256 proposalId,
        uint256 blinderToCheck
    ) external view returns (bool);
}
