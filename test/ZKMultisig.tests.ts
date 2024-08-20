import { PRECISION, ZERO_ADDR } from "@/scripts/utils/constants";
import { Reverter } from "@/test/helpers/reverter";
import {
  IZKMultisig,
  NegativeVerifierMock,
  PositiveVerifierMock,
  ZKMultisig,
  ZKMultisig__factory,
  ZKMultisigFactory,
} from "@ethers-v6";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { expect } from "chai";
import { randomBytes } from "crypto";
import { AbiCoder, BytesLike } from "ethers";
import { ethers } from "hardhat";
import { getPoseidon } from "./helpers";

type ZKParams = IZKMultisig.ZKParamsStruct;
type ProposalContent = IZKMultisig.ProposalContentStruct;

enum ProposalStatus {
  NONE,
  VOTING,
  ACCEPTED,
  EXPIRED,
  EXECUTED,
}

describe("ZKMultisig", () => {
  const reverter = new Reverter();
  const randomNumber = () => BigInt("0x" + randomBytes(32).toString("hex"));

  const MIN_QUORUM = BigInt(80) * PRECISION;
  const DAY_IN_SECONDS = 60 * 60 * 24;

  let alice: SignerWithAddress;

  let positiveParticipantVerifier: PositiveVerifierMock;
  let negativeParticipantVerifier: NegativeVerifierMock;

  let zkMultisig: ZKMultisig;
  let zkMultisigFactory: ZKMultisigFactory;

  let initialParticipants: bigint[];

  let zkParams: ZKParams;

  let proposalContent: ProposalContent;

  const encode = (types: ReadonlyArray<string>, values: ReadonlyArray<any>): string => {
    return AbiCoder.defaultAbiCoder().encode(types, values);
  };

  const generateParticipants = (length: number) => {
    const participants: bigint[] = [];
    for (let i = 0; i < length; i++) {
      participants.push(randomNumber());
    }

    return participants;
  };

  before(async () => {
    [alice] = await ethers.getSigners();

    const positiveVerifier__factory = await ethers.getContractFactory("PositiveVerifierMock");
    positiveParticipantVerifier = await positiveVerifier__factory.deploy();

    await positiveParticipantVerifier.waitForDeployment();

    const negativeVerifier__factory = await ethers.getContractFactory("NegativeVerifierMock");
    negativeParticipantVerifier = await negativeVerifier__factory.deploy();

    await negativeParticipantVerifier.waitForDeployment();

    const zkMultisig__factory = await ethers.getContractFactory("ZKMultisig", {
      libraries: {
        PoseidonUnit1L: await (await getPoseidon(1)).getAddress(),
      },
    });
    const zkMultisigImpl = await zkMultisig__factory.deploy();

    await zkMultisigImpl.waitForDeployment();

    var zkMultisigFactory__factory = await ethers.getContractFactory("ZKMultisigFactory");
    zkMultisigFactory = await zkMultisigFactory__factory.deploy(
      await zkMultisigImpl.getAddress(),
      await positiveParticipantVerifier.getAddress(),
    );

    await zkMultisigFactory.waitForDeployment();

    const salt = randomNumber();
    initialParticipants = generateParticipants(5);

    // create multisig
    await zkMultisigFactory.connect(alice).createMultisig(initialParticipants, MIN_QUORUM, salt);
    // get deployed proxy
    const address = await zkMultisigFactory.computeZKMultisigAddress(alice.address, salt);
    // attach proxy address to zkMultisig
    zkMultisig = zkMultisigImpl.attach(address) as ZKMultisig;

    // default proposal content
    proposalContent = {
      target: await zkMultisig.getAddress(),
      value: 0,
      data: "0x",
    };

    // default zk params
    zkParams = {
      a: [randomNumber(), randomNumber()],
      b: [
        [randomNumber(), randomNumber()],
        [randomNumber(), randomNumber()],
      ],
      c: [randomNumber(), randomNumber()],
      inputs: [randomNumber(), randomNumber(), randomNumber()],
    };

    await reverter.snapshot();
  });

  afterEach(reverter.revert);

  describe("initial", async () => {
    it("should have correct initial state", async () => {
      expect(await zkMultisig.getParticipantsSMTRoot()).to.be.ok;

      expect(await zkMultisig.getParticipantsCount()).to.be.eq(initialParticipants.length);
      expect(await zkMultisig.getParticipants()).to.be.deep.eq(initialParticipants);

      expect((await zkMultisig.getParticipantsSMTProof(ethers.toBeHex(initialParticipants[0]))).existence).to.be.true;
      expect((await zkMultisig.getParticipantsSMTProof(ethers.toBeHex(randomNumber()))).existence).to.be.false;

      expect(await zkMultisig.getProposalsCount()).to.be.eq(0);
      expect(await zkMultisig.getProposalsIds(0, 10)).to.be.deep.eq([]);

      expect(await zkMultisig.getQuorumPercentage()).to.be.eq(MIN_QUORUM);
    });

    it("should not allow to initialize twice", async () => {
      await expect(
        zkMultisig.initialize(initialParticipants, MIN_QUORUM, positiveParticipantVerifier),
      ).to.be.revertedWithCustomError({ interface: ZKMultisig__factory.createInterface() }, "InvalidInitialization");
    });

    it("should not allow to call proposals functions directly", async () => {
      await expect(zkMultisig.addParticipants(generateParticipants(3))).to.be.revertedWith(
        "ZKMultisig: Not authorized call",
      );

      await expect(zkMultisig.removeParticipants(generateParticipants(3))).to.be.revertedWith(
        "ZKMultisig: Not authorized call",
      );

      await expect(zkMultisig.updateQuorumPercentage(MIN_QUORUM)).to.be.revertedWith("ZKMultisig: Not authorized call");

      await expect(zkMultisig.updateParticipantVerifier(ZERO_ADDR)).to.be.revertedWith(
        "ZKMultisig: Not authorized call",
      );
    });
  });

  describe("proposal flow", async () => {
    const createProposal = async (data: BytesLike): Promise<{ proposalId: bigint; zkParams: ZKParams }> => {
      proposalContent.data = data;
      const salt = randomNumber();

      // blinder
      zkParams.inputs[0] = randomNumber();
      // challange
      const proposalId = await zkMultisig.computeProposalId(proposalContent, salt);
      zkParams.inputs[1] = await zkMultisig.getProposalChallenge(proposalId);
      // root
      zkParams.inputs[2] = await zkMultisig.getParticipantsSMTRoot();

      const tx = await zkMultisig.create(proposalContent, DAY_IN_SECONDS, salt, zkParams);

      expect(tx).to.emit(zkMultisigFactory, "ZKMultisigCreated").withArgs(proposalId, proposalContent);
      expect(tx).to.emit(zkMultisig, "ProposalCreated").withArgs(proposalId, proposalContent);
      expect(tx).to.emit(zkMultisig, "ProposalVoted").withArgs(proposalId, zkParams.inputs[0]);

      expect(await zkMultisig.getProposalsCount()).to.be.eq(1);
      expect(await zkMultisig.getProposalsIds(0, 10)).to.be.deep.eq([proposalId]);

      expect(await zkMultisig.getProposalStatus(proposalId)).to.be.eq(BigInt(ProposalStatus.VOTING));

      return { proposalId, zkParams };
    };

    const vote = async (proposalId: bigint, zkParams: ZKParams) => {
      const tx = await zkMultisig.vote(proposalId, zkParams);

      expect(tx).to.emit(zkMultisig, "ProposalVoted").withArgs(proposalId, zkParams.inputs[0]);
      expect(await zkMultisig.isBlinderVoted(proposalId, zkParams.inputs[0])).to.be.true;
      expect(await zkMultisig.getProposalStatus(proposalId)).to.be.oneOf([
        BigInt(ProposalStatus.VOTING),
        BigInt(ProposalStatus.ACCEPTED),
      ]);
    };

    const execute = async (proposalId: bigint) => {
      const tx = await zkMultisig.execute(proposalId);

      expect(tx).to.emit(zkMultisig, "ProposalExecuted").withArgs(proposalId);
      expect(await zkMultisig.getProposalStatus(proposalId)).to.be.eq(BigInt(ProposalStatus.EXECUTED));
    };

    describe("add particpants", async () => {
      it("create", async () => {
        const newParticipants = generateParticipants(2);
        const data = ZKMultisig__factory.createInterface().encodeFunctionData("addParticipants(uint256[])", [
          newParticipants,
        ]);

        await createProposal(data);
      });

      it("vote", async () => {
        const newParticipants = generateParticipants(2);
        const data = ZKMultisig__factory.createInterface().encodeFunctionData("addParticipants(uint256[])", [
          newParticipants,
        ]);

        const { proposalId, zkParams } = await createProposal(data);

        //update blinder as af
        zkParams.inputs[0] = randomNumber();
        await vote(proposalId, zkParams);
      });

      it("execute", async () => {
        const newParticipants = generateParticipants(2);
        const data = ZKMultisig__factory.createInterface().encodeFunctionData("addParticipants(uint256[])", [
          newParticipants,
        ]);

        const { proposalId, zkParams } = await createProposal(data);

        while ((await zkMultisig.getProposalStatus(proposalId)) != BigInt(ProposalStatus.ACCEPTED)) {
          //update blinder as af
          zkParams.inputs[0] = randomNumber();
          await vote(proposalId, zkParams);
        }

        await execute(proposalId);

        expect(await zkMultisig.getParticipantsCount()).to.be.eq(initialParticipants.length + newParticipants.length);
        expect(await zkMultisig.getParticipants()).to.be.deep.eq([...initialParticipants, ...newParticipants]);

        expect((await zkMultisig.getParticipantsSMTProof(ethers.toBeHex(newParticipants[0]))).existence).to.be.true;
        expect((await zkMultisig.getParticipantsSMTProof(ethers.toBeHex(newParticipants[1]))).existence).to.be.true;
      });
    });

    describe("remove particpants", async () => {
      it("create", async () => {
        const participantsToDelete = (await zkMultisig.getParticipants()).slice(0, 2);
        const data = ZKMultisig__factory.createInterface().encodeFunctionData("removeParticipants(uint256[])", [
          participantsToDelete,
        ]);

        await createProposal(data);
      });

      it("vote", async () => {
        const participantsToDelete = (await zkMultisig.getParticipants()).slice(0, 2);
        const data = ZKMultisig__factory.createInterface().encodeFunctionData("removeParticipants(uint256[])", [
          participantsToDelete,
        ]);

        const { proposalId, zkParams } = await createProposal(data);

        //update blinder as af
        zkParams.inputs[0] = randomNumber();
        await vote(proposalId, zkParams);
      });

      it("execute", async () => {
        const participantsToDelete = (await zkMultisig.getParticipants()).slice(0, 2);
        const data = ZKMultisig__factory.createInterface().encodeFunctionData("removeParticipants(uint256[])", [
          participantsToDelete,
        ]);

        const { proposalId, zkParams } = await createProposal(data);

        while ((await zkMultisig.getProposalStatus(proposalId)) != BigInt(ProposalStatus.ACCEPTED)) {
          //update blinder as af
          zkParams.inputs[0] = randomNumber();
          await vote(proposalId, zkParams);
        }

        await execute(proposalId);

        expect(await zkMultisig.getParticipantsCount()).to.be.eq(
          initialParticipants.length - participantsToDelete.length,
        );

        expect((await zkMultisig.getParticipantsSMTProof(ethers.toBeHex(initialParticipants[0]))).existence).to.be
          .false;
        expect((await zkMultisig.getParticipantsSMTProof(ethers.toBeHex(initialParticipants[4]))).existence).to.be.true;
      });
    });

    describe("update quorum percentage", async () => {
      it("create", async () => {
        const newQuorum = MIN_QUORUM + BigInt(10) * PRECISION;
        const data = ZKMultisig__factory.createInterface().encodeFunctionData("updateQuorumPercentage(uint256)", [
          newQuorum,
        ]);

        await createProposal(data);
      });

      it("vote", async () => {
        const newQuorum = MIN_QUORUM + BigInt(10) * PRECISION;
        const data = ZKMultisig__factory.createInterface().encodeFunctionData("updateQuorumPercentage(uint256)", [
          newQuorum,
        ]);

        const { proposalId, zkParams } = await createProposal(data);

        //update blinder as af
        zkParams.inputs[0] = randomNumber();
        await vote(proposalId, zkParams);
      });

      it("execute", async () => {
        const newQuorum = MIN_QUORUM + BigInt(10) * PRECISION;
        const data = ZKMultisig__factory.createInterface().encodeFunctionData("updateQuorumPercentage(uint256)", [
          newQuorum,
        ]);

        const { proposalId, zkParams } = await createProposal(data);

        while ((await zkMultisig.getProposalStatus(proposalId)) != BigInt(ProposalStatus.ACCEPTED)) {
          //update blinder as af
          zkParams.inputs[0] = randomNumber();
          await vote(proposalId, zkParams);
        }

        await execute(proposalId);

        expect(await zkMultisig.getQuorumPercentage()).to.be.eq(newQuorum);
      });
    });

    describe("update participant verifier", async () => {
      it("create", async () => {
        const data = ZKMultisig__factory.createInterface().encodeFunctionData("updateParticipantVerifier(address)", [
          await negativeParticipantVerifier.getAddress(),
        ]);

        await createProposal(data);
      });

      it("vote", async () => {
        const data = ZKMultisig__factory.createInterface().encodeFunctionData("updateParticipantVerifier(address)", [
          await negativeParticipantVerifier.getAddress(),
        ]);

        const { proposalId, zkParams } = await createProposal(data);

        //update blinder as af
        zkParams.inputs[0] = randomNumber();
        await vote(proposalId, zkParams);
      });

      it("execute", async () => {
        const data = ZKMultisig__factory.createInterface().encodeFunctionData("updateParticipantVerifier(address)", [
          await negativeParticipantVerifier.getAddress(),
        ]);

        const { proposalId, zkParams } = await createProposal(data);

        while ((await zkMultisig.getProposalStatus(proposalId)) != BigInt(ProposalStatus.ACCEPTED)) {
          //update blinder as af
          zkParams.inputs[0] = randomNumber();
          await vote(proposalId, zkParams);
        }

        await execute(proposalId);

        expect(await zkMultisig.participantVerifier()).to.be.eq(await negativeParticipantVerifier.getAddress());
      });
    });
  });
});
