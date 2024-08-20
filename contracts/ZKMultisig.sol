// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";

import {SparseMerkleTree} from "@solarity/solidity-lib/libs/data-structures/SparseMerkleTree.sol";
import {PRECISION, PERCENTAGE_100} from "@solarity/solidity-lib/utils/Globals.sol";
import {Paginator} from "@solarity/solidity-lib/libs/arrays/Paginator.sol";
import {VerifierHelper} from "@solarity/solidity-lib/libs/zkp/snarkjs/VerifierHelper.sol";

import {IZKMultisig} from "./interfaces/IZKMultisig.sol";
import {PoseidonUnit1L} from "./libs/Poseidon.sol";

contract ZKMultisig is UUPSUpgradeable, IZKMultisig {
    using EnumerableSet for *;
    using Paginator for EnumerableSet.UintSet;
    using SparseMerkleTree for SparseMerkleTree.UintSMT;
    using VerifierHelper for address;
    using Address for address;
    using Math for uint256;

    uint256 public constant PARTICIPANTS_TREE_DEPTH = 20;
    uint256 public constant MIN_QUORUM_SIZE = 1;

    address public participantVerifier;

    SparseMerkleTree.UintSMT internal _participantsSMT;
    EnumerableSet.UintSet internal _participants;
    EnumerableSet.UintSet internal _proposalIds;

    uint256 private _quorumPercentage;

    mapping(uint256 => ProposalData) private _proposals;

    modifier onlyThis() {
        _validateMsgSender();
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(
        uint256[] memory participants_,
        uint256 quorumPercentage_,
        address participantVerifier_
    ) external initializer {
        _participantsSMT.initialize(uint32(PARTICIPANTS_TREE_DEPTH));

        _updateParticipantVerifier(participantVerifier_);
        _updateQuorumPercentage(quorumPercentage_);
        _addParticipants(participants_);
    }

    function addParticipants(uint256[] calldata participantsToAdd_) external onlyThis {
        _addParticipants(participantsToAdd_);
    }

    function removeParticipants(uint256[] calldata participantsToRemove_) external onlyThis {
        _removeParticipants(participantsToRemove_);
    }

    function updateQuorumPercentage(uint256 newQuorumPercentage_) external onlyThis {
        _updateQuorumPercentage(newQuorumPercentage_);
    }

    function updateParticipantVerifier(address participantVerifier_) external onlyThis {
        _updateParticipantVerifier(participantVerifier_);
    }

    function create(
        ProposalContent calldata content_,
        uint256 duration_,
        uint256 salt_,
        ZKParams calldata proofData_
    ) external returns (uint256) {
        // validate inputs
        require(duration_ > 0, "ZKMultisig: Invalid duration");
        require(content_.target != address(0), "ZKMultisig: Invalid target");

        uint256 proposalId_ = computeProposalId(content_, salt_);

        // validate proposal state
        require(
            getProposalStatus(proposalId_) == ProposalStatus.NONE,
            "ZKMultisig: Proposal already exists"
        );

        // create proposal
        ProposalData storage _proposal = _proposals[proposalId_];
        _proposalIds.add(proposalId_);

        _proposal.content = content_;
        _proposal.proposalEndTime = block.timestamp + duration_;

        // vote on behalf of the creator
        // zk validation is processed inside _vote
        _vote(proposalId_, proofData_);

        emit ProposalCreated(proposalId_, content_);

        return proposalId_;
    }

    function vote(uint256 proposalId_, ZKParams calldata proofData_) external {
        _vote(proposalId_, proofData_);
    }

    function execute(uint256 proposalId_) external payable {
        require(
            getProposalStatus(proposalId_) == ProposalStatus.ACCEPTED,
            "ZKMultisig: Proposal is not accepted"
        );

        ProposalData storage _proposal = _proposals[proposalId_];

        require(msg.value == _proposal.content.value, "ZKMultisig: Invalid value");

        _proposal.content.target.functionCallWithValue(
            _proposal.content.data,
            _proposal.content.value
        );

        _proposal.executed = true;

        emit ProposalExecuted(proposalId_);
    }

    function getParticipantsSMTRoot() external view returns (bytes32) {
        return _participantsSMT.getRoot();
    }

    function getParticipantsSMTProof(
        bytes32 publicKeyHash_
    ) external view override returns (SparseMerkleTree.Proof memory) {
        return _participantsSMT.getProof(publicKeyHash_);
    }

    function getParticipantsCount() external view returns (uint256) {
        return _participants.length();
    }

    function getParticipants() external view returns (uint256[] memory) {
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
        ProposalData storage _proposal = _proposals[proposalId_];

        return
            ProposalInfoView({
                content: _proposal.content,
                proposalEndTime: _proposal.proposalEndTime,
                status: getProposalStatus(proposalId_),
                votesCount: _proposal.blinders.length(),
                requiredQuorum: getRequiredQuorum()
            });
    }

    function computeProposalId(
        ProposalContent calldata content_,
        uint256 salt_
    ) public pure returns (uint256) {
        return
            uint256(keccak256(abi.encode(content_.target, content_.value, content_.data, salt_)));
    }

    function getProposalChallenge(uint256 proposalId_) public view returns (uint256) {
        return
            uint256(
                PoseidonUnit1L.poseidon(
                    [
                        uint256(
                            uint248(
                                uint256(
                                    keccak256(
                                        abi.encode(block.chainid, address(this), proposalId_)
                                    )
                                )
                            )
                        )
                    ]
                )
            );
    }

    function isBlinderVoted(
        uint256 proposalId_,
        uint256 blinderToCheck_
    ) public view returns (bool) {
        return _proposals[proposalId_].blinders.contains(blinderToCheck_);
    }

    function getProposalStatus(uint256 proposalId_) public view returns (ProposalStatus) {
        ProposalData storage _proposal = _proposals[proposalId_];

        // Check if the proposal exists by verifying the end time
        if (_proposal.proposalEndTime == 0) {
            return ProposalStatus.NONE;
        }

        // Check if the proposal has been executed
        if (_proposal.executed) {
            return ProposalStatus.EXECUTED;
        }

        // Check if the proposal has met the quorum requirement
        if (_proposal.blinders.length() >= getRequiredQuorum()) {
            return ProposalStatus.ACCEPTED;
        }

        // Check if the proposal is still within the voting period
        if (_proposal.proposalEndTime > block.timestamp) {
            return ProposalStatus.VOTING;
        }

        // If the proposal has not met the quorum and the voting period has expired
        return ProposalStatus.EXPIRED;
    }

    // return the required quorum amount (not percentage) for a given number of participants
    function getRequiredQuorum() public view returns (uint256) {
        return
            ((_participants.length() * _quorumPercentage) / PERCENTAGE_100).max(MIN_QUORUM_SIZE);
    }

    function _authorizeUpgrade(address newImplementation_) internal override onlyThis {}

    function _addParticipants(uint256[] memory participantsToAdd_) internal {
        require(
            _participants.length() + participantsToAdd_.length <= 2 ** PARTICIPANTS_TREE_DEPTH,
            "ZKMultisig: Too many participants"
        );

        _processParticipants(participantsToAdd_, true);
    }

    function _removeParticipants(uint256[] memory participantsToRemove_) internal {
        _processParticipants(participantsToRemove_, false);

        require(_participants.length() > 0, "ZKMultisig: Cannot remove all participants");
    }

    function _updateQuorumPercentage(uint256 newQuorumPercentage_) internal {
        require(
            newQuorumPercentage_ > 0 &&
                newQuorumPercentage_ <= PERCENTAGE_100 &&
                newQuorumPercentage_ != _quorumPercentage,
            "ZKMultisig: Invalid quorum percentage"
        );

        _quorumPercentage = newQuorumPercentage_;
    }

    function _updateParticipantVerifier(address participantVerifier_) internal {
        require(participantVerifier_ != address(0), "ZKMultisig: Invalid verifier address");
        require(
            participantVerifier_ != participantVerifier,
            "ZKMultisig: The same verifier address"
        );
        require(participantVerifier_.code.length > 0, "ZKMultisig: Not a contract");

        participantVerifier = participantVerifier_;
    }

    function _vote(uint256 proposalId_, ZKParams calldata proofData_) internal {
        require(
            getProposalStatus(proposalId_) == ProposalStatus.VOTING,
            "ZKMultisig: Proposal is not in voting state"
        );

        _validateZKParams(proposalId_, proofData_);

        _proposals[proposalId_].blinders.add(proofData_.inputs[0]);

        emit ProposalVoted(proposalId_, proofData_.inputs[0]);
    }

    function _validateZKParams(uint256 proposalId_, ZKParams calldata proofData_) internal view {
        require(proofData_.inputs.length == 3, "ZKMultisig: Invalid proof data");

        require(
            !isBlinderVoted(proposalId_, proofData_.inputs[0]),
            "ZKMultisig: Blinder already voted"
        );

        require(
            proofData_.inputs[1] == getProposalChallenge(proposalId_),
            "ZKMultisig: Invalid challenge"
        );

        require(
            proofData_.inputs[2] == uint256(_participantsSMT.getRoot()),
            "ZKMultisig: Invalid SMT root"
        );

        require(
            participantVerifier.verifyProof(
                proofData_.inputs,
                VerifierHelper.ProofPoints({a: proofData_.a, b: proofData_.b, c: proofData_.c})
            ),
            "ZKMultisig: Invalid proof"
        );
    }

    function _processParticipants(uint256[] memory participants_, bool isAdding_) private {
        require(participants_.length > 0, "Multisig: No participants to process");

        for (uint256 i = 0; i < participants_.length; i++) {
            uint256 participant_ = participants_[i];

            if (isAdding_) {
                if (!_participants.contains(participant_)) {
                    _participantsSMT.add(bytes32(participant_), participant_);
                    _participants.add(participant_);
                }
            } else {
                if (_participants.contains(participant_)) {
                    _participantsSMT.remove(bytes32(participant_));
                    _participants.remove(participant_);
                }
            }
        }
    }

    function _validateMsgSender() private view {
        require(msg.sender == address(this), "ZKMultisig: Not authorized call");
    }
}
