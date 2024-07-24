// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {IZKMultisig} from "./interfaces/IZKMultisig.sol";

import {SparseMerkleTree} from "@solarity/solidity-lib/libs/data-structures/SparseMerkleTree.sol";
import {PRECISION, PERCENTAGE_100} from "@solarity/solidity-lib/utils/Globals.sol";
import {Paginator} from "@solarity/solidity-lib/libs/arrays/Paginator.sol";

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

import {PoseidonUnit1L} from "@iden3/contracts/lib/Poseidon.sol";

contract ZKMultisig is UUPSUpgradeable, IZKMultisig {
    using SparseMerkleTree for SparseMerkleTree.Bytes32SMT;
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using EnumerableSet for EnumerableSet.UintSet;
    using Paginator for EnumerableSet.UintSet;
    using Math for uint256;

    enum ParticipantsAction {
        ADD,
        REMOVE
    }

    uint256 public constant TREE_SIZE = 20;

    SparseMerkleTree.Bytes32SMT internal _bytes32Tree;
    EnumerableSet.Bytes32Set internal _participants;
    EnumerableSet.UintSet internal _proposalIds;

    uint256 private _quorumPercentage;

    mapping(uint256 => ProposalInfoView) private _proposals;
    mapping(uint256 => uint256) private _blinders;

    event Initialized(uint256 participantsAmount, uint256 quorumPercentage);
    event RootUpdated(bytes32 indexed root);
    event QuorumPercentageUpdated(uint256 indexed newQuorumPercentage);

    modifier onlyThis() {
        require(msg.sender == address(this), "ZKMultisig: Not authorized call");
        _;
    }

    modifier withRootUpdate() {
        _;
        _notifyRoot();
    }

    modifier withQuorumUpdate() {
        _;
        _notifyQourumPercentage();
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(
        uint256[] memory participants_,
        uint256 quorumPercentage_
    ) external initializer {
        __ZKMultisig_init(participants_, quorumPercentage_);
    }

    function __ZKMultisig_init(
        uint256[] memory participants_,
        uint256 quorumPercentage_
    ) internal {
        _updateQourumPercentage(quorumPercentage_);
        _bytes32Tree.initialize(uint32(TREE_SIZE));
        _addParticipants(participants_);
    }

    function addParticipants(
        uint256[] calldata participantsToAdd_
    ) external onlyThis withRootUpdate {
        _addParticipants(participantsToAdd_);
    }

    function removeParticipants(
        uint256[] calldata participantsToRemove_
    ) external onlyThis withRootUpdate {
        _removeParticipants(participantsToRemove_);
    }

    function updateQuorumPercentage(
        uint256 newQuorumPercentage_
    ) external onlyThis withQuorumUpdate {
        _updateQourumPercentage(newQuorumPercentage_);
    }

    function create(
        ProposalContent calldata content_,
        uint256 duration_,
        uint256 salt_,
        ZKParams calldata proofData_
    ) external returns (uint256) {
        uint256 proposalId_ = _computeProposalId(content_, salt_);

        require(
            _proposals[proposalId_].status == ProposalStatus.NONE,
            "ZKMultisig: Proposal already exists"
        );

        require(duration_ > 0, "ZKMultisig: Invalid duration");

        uint256 votesCount_ = 1; // 1 vote from creator
        uint256 requiredQuorum_ = ((_participants.length() * _quorumPercentage) / PERCENTAGE_100)
            .max(1);

        _proposals[proposalId_] = ProposalInfoView({
            content: content_,
            proposalEndTime: block.timestamp + duration_,
            status: votesCount_ >= requiredQuorum_
                ? ProposalStatus.ACCEPTED
                : ProposalStatus.VOTING,
            votesCount: votesCount_,
            requiredQuorum: requiredQuorum_
        });

        _proposalIds.add(proposalId_);
        // assign proposalId to blinder
        _blinders[proofData_.inputs[0]] = proposalId_;

        emit ProposalCreated(proposalId_, content_);

        return proposalId_;
    }

    function vote(uint256 proposalId_, ZKParams calldata proofData_) external {
        ProposalInfoView storage _proposal = _proposals[proposalId_];
        uint256 blinder_ = proofData_.inputs[0];

        require(
            _proposal.status == ProposalStatus.VOTING,
            "ZKMultisig: Proposal is not in voting state"
        );

        require(block.timestamp < _proposal.proposalEndTime, "ZKMultisig: Proposal expired");

        require(!_isBlinderVoted(proposalId_, blinder_), "ZKMultisig: Already voted");

        _blinders[blinder_] = proposalId_;

        _proposal.votesCount += 1;

        if (_proposal.votesCount >= _proposal.requiredQuorum) {
            _proposal.status = ProposalStatus.ACCEPTED;
        }

        emit ProposalVoted(proposalId_, blinder_);
    }

    function execute(uint256 proposalId_) external {
        ProposalInfoView storage _proposal = _proposals[proposalId_];

        require(
            _proposal.status == ProposalStatus.ACCEPTED,
            "ZKMultisig: Proposal is not accepted"
        );

        (bool success, ) = _proposal.content.target.call{value: _proposal.content.value}(
            _proposal.content.data
        );

        require(success, "ZKMultisig: Proposal execution failed");

        _proposal.status = ProposalStatus.EXECUTED;

        emit ProposalExecuted(proposalId_);
    }

    function getParticipantsSMTRoot() external view returns (bytes32) {
        return _bytes32Tree.getRoot();
    }

    function getParticipantsSMTProof(
        bytes32 publicKeyHash_
    ) external view override returns (SparseMerkleTree.Proof memory) {
        return _bytes32Tree.getProof(publicKeyHash_);
    }

    function getParticipantsCount() external view returns (uint256) {
        return _participants.length();
    }

    function getParticipants() external view returns (bytes32[] memory) {
        return _participants.values();
    }

    function getProposalsCount() external view returns (uint256) {
        return _proposalIds.length();
    }

    function getProposalsIds(
        uint256 offset,
        uint256 limit
    ) external view override returns (uint256[] memory) {
        return _proposalIds.part(offset, limit);
    }

    function getQuorumPercentage() external view returns (uint256) {
        return _quorumPercentage;
    }

    function getProposalInfo(uint256 proposalId_) external view returns (ProposalInfoView memory) {
        return _proposals[proposalId_];
    }

    function getProposalStatus(uint256 proposalId_) external view returns (ProposalStatus) {
        return _proposals[proposalId_].status;
    }

    // double check doc, bc there uint248(keccak256(abi.encode(block.chainid, address(this), proposalId_))) is used
    function getProposalChallenge(uint256 proposalId_) external view returns (uint256) {
        return
            uint256(
                PoseidonUnit1L.poseidon(
                    [uint256(keccak256(abi.encode(block.chainid, address(this), proposalId_)))]
                )
            );
    }

    function computeProposalId(
        ProposalContent calldata content_,
        uint256 salt_
    ) external pure returns (uint256) {
        return _computeProposalId(content_, salt_);
    }

    function isBlinderVoted(
        uint256 proposalId_,
        uint256 blinderToCheck_
    ) external view returns (bool) {
        return _isBlinderVoted(proposalId_, blinderToCheck_);
    }

    function _authorizeUpgrade(address newImplementation_) internal override onlyThis {}

    function _addParticipants(uint256[] memory participantsToAdd_) internal {
        require(
            _participants.length() + participantsToAdd_.length <= 2 ** TREE_SIZE,
            "ZKMultisig: Too many participants"
        );
        _processParticipants(participantsToAdd_, ParticipantsAction.ADD);

        // require(participantsToAdd.length > 0, "ZKMultisig: No participants to add");
        // for (uint256 i = 0; i < participantsToAdd.length; i++) {
        //     uint256 participant_ = participantsToAdd[i];
        //     bytes32 participantKey_ = keccak256(abi.encodePacked(participant_));
        //     if (_uintTree.getProof(participantKey_).existence) {
        //         continue;
        //         // or revert?
        //     }
        //     _uintTree.add(participantKey_, participant_);
        // }
    }

    function _removeParticipants(uint256[] memory participantsToRemove_) internal {
        require(
            _participants.length() > participantsToRemove_.length,
            "ZKMultisig: Cannot remove all participants"
        );
        _processParticipants(participantsToRemove_, ParticipantsAction.REMOVE);

        // require(participantsToRemove.length > 0, "ZKMultisig: No participants to remove");
        // for (uint256 i = 0; i < participantsToRemove.length; i++) {
        //     uint256 participant_ = participantsToRemove[i];
        //     bytes32 participantKey_ = keccak256(abi.encodePacked(participant_));
        //     if (_uintTree.getProof(participantKey_).existence) {
        //         _uintTree.remove(participantKey_);
        //         // should revert if false?
        //     }
        // }
    }

    function _updateQourumPercentage(uint256 newQuorumPercentage_) internal {
        require(
            newQuorumPercentage_ > 0 &&
                newQuorumPercentage_ <= 100 &&
                newQuorumPercentage_ != _quorumPercentage,
            "ZKMultisig: Invalid quorum percentage"
        );

        _quorumPercentage = newQuorumPercentage_;
    }

    function _computeProposalId(
        ProposalContent calldata content_,
        uint256 salt_
    ) internal pure returns (uint256) {
        return
            uint256(keccak256(abi.encode(content_.target, content_.value, content_.data, salt_)));
    }

    function _isBlinderVoted(
        uint256 proposalId_,
        uint256 blinderToCheck_
    ) internal view returns (bool) {
        return _blinders[blinderToCheck_] == proposalId_;
    }

    function _notifyRoot() internal {
        emit RootUpdated(_bytes32Tree.getRoot());
    }

    function _notifyQourumPercentage() internal {
        emit QuorumPercentageUpdated(_quorumPercentage);
    }

    function _processParticipants(
        uint256[] memory participants_,
        ParticipantsAction action_
    ) private {
        require(participants_.length > 0, "Multisig: No participants to process");

        for (uint256 i = 0; i < participants_.length; i++) {
            bytes32 participant_ = bytes32(participants_[i]);
            bytes32 participantKey_ = keccak256(abi.encodePacked(participant_));

            bool nodeExists = _bytes32Tree.getProof(participantKey_).existence;

            // revert in false case?
            if (!nodeExists && action_ == ParticipantsAction.ADD) {
                _bytes32Tree.add(participantKey_, participant_);
                _participants.add(participant_);
            }

            // revert in false case?
            if (nodeExists && action_ == ParticipantsAction.REMOVE) {
                _bytes32Tree.remove(participantKey_);
                _participants.remove(participant_);
            }
        }
    }
}
