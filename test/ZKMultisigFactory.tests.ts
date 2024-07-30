import { PRECISION, ZERO_ADDR } from "@/scripts/utils/constants";
import { Reverter } from "@/test/helpers/reverter";
import {
  ERC1967Proxy__factory,
  NegativeVerifierMock,
  PositiveVerifierMock,
  ZKMultisig,
  ZKMultisigFactory,
} from "@ethers-v6";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { expect } from "chai";
import { randomBytes } from "crypto";
import { AbiCoder, solidityPacked as encodePacked, keccak256, TypedDataDomain } from "ethers";
import { ethers } from "hardhat";
import { getPoseidon } from "./helpers";

describe("ZKMultisig Factory", () => {
  const reverter = new Reverter();

  let alice: SignerWithAddress;

  let participantVerifier: PositiveVerifierMock | NegativeVerifierMock;
  let zkMultisig: ZKMultisig;
  let zkMultisigFactory: ZKMultisigFactory;

  const encode = (types: ReadonlyArray<string>, values: ReadonlyArray<any>): string => {
    return AbiCoder.defaultAbiCoder().encode(types, values);
  };

  const randomNumber = () => BigInt("0x" + randomBytes(32).toString("hex"));

  before(async () => {
    [alice] = await ethers.getSigners();

    var verifier__factory = await ethers.getContractFactory("PositiveVerifierMock");
    participantVerifier = await verifier__factory.deploy();

    await participantVerifier.waitForDeployment();

    var zkMultisig__factory = await ethers.getContractFactory("ZKMultisig", {
      libraries: {
        PoseidonUnit1L: await (await getPoseidon(1)).getAddress(),
      },
    });
    zkMultisig = await zkMultisig__factory.deploy();

    await zkMultisig.waitForDeployment();

    var zkMultisigFactory__factory = await ethers.getContractFactory("ZKMultisigFactory");
    zkMultisigFactory = await zkMultisigFactory__factory.deploy(
      await zkMultisig.getAddress(),
      await participantVerifier.getAddress(),
    );

    await zkMultisigFactory.waitForDeployment();

    await reverter.snapshot();
  });

  afterEach(reverter.revert);

  describe("initial", () => {
    it("should set parameters correctly", async () => {
      expect(await zkMultisigFactory.ZK_MULTISIG_IMPL()).to.eq(await zkMultisig.getAddress());
      expect(await zkMultisigFactory.PARTICIPANT_VERIFIER()).to.eq(await participantVerifier.getAddress());
    });

    it("should have correct initial state", async () => {
      expect(await zkMultisigFactory.getZKMultisigsCount()).to.be.eq(0);
      expect(await zkMultisigFactory.getZKMultisigs(0, 1)).to.be.deep.eq([]);
    });

    it("should revert if contructor parameters are incorrect", async () => {
      const factory = await ethers.getContractFactory("ZKMultisigFactory");
      const err = "ZKMultisigFactory: Invalid implementation or verifier address";

      // deploy multisig factory with zero address
      await expect(factory.deploy(ZERO_ADDR, await participantVerifier.getAddress())).to.be.revertedWith(err);
      await expect(factory.deploy(await zkMultisig.getAddress(), ZERO_ADDR)).to.be.revertedWith(err);
    });
  });

  describe("KDF message", () => {
    it("should return correct KDF messages", async () => {
      const domain = {
        name: "ZKMultisigFactory",
        version: "1",
        chainId: (await ethers.provider.getNetwork()).chainId,
        verifyingContract: await zkMultisigFactory.getAddress(),
      } as TypedDataDomain;

      const types = { KDF: [{ name: "zkMultisigAddress", type: "address" }] };

      let values = { zkMultisigAddress: await zkMultisig.getAddress() };
      const msgHash = ethers.TypedDataEncoder.hash(domain, types, values);

      values = { zkMultisigAddress: ZERO_ADDR };
      const defaultMsgHash = ethers.TypedDataEncoder.hash(domain, types, values);

      expect(await zkMultisigFactory.getKDFMSGToSign(await zkMultisig.getAddress())).to.be.eq(msgHash);
      expect(await zkMultisigFactory.getDefaultKDFMSGToSign()).to.be.eq(defaultMsgHash);
    });
  });

  describe("zkMultisig factory", () => {
    it("should correctly calculate address of create2", async () => {
      const salt = randomNumber();

      const multisigAddress = await zkMultisigFactory.computeZKMultisigAddress(alice.address, salt);

      const calculatedAddress = ethers.getCreate2Address(
        await zkMultisigFactory.getAddress(),
        keccak256(encode(["address", "uint256"], [alice.address, salt])),
        keccak256(
          encodePacked(
            ["bytes", "bytes"],
            [ERC1967Proxy__factory.bytecode, encode(["address", "bytes"], [await zkMultisig.getAddress(), "0x"])],
          ),
        ),
      );

      expect(multisigAddress).to.be.eq(calculatedAddress);
    });

    it("should create zkMultisig contract", async () => {
      const salt = randomNumber();
      const multisigAddress = await zkMultisigFactory.computeZKMultisigAddress(alice.address, salt);

      expect(await zkMultisigFactory.isZKMultisig(multisigAddress)).to.be.eq(false);
      expect(await zkMultisigFactory.getZKMultisigsCount()).to.be.eq(0);
      expect(await zkMultisigFactory.getZKMultisigs(0, 1)).to.be.deep.eq([]);

      // add participants
      let participants: bigint[] = [];
      for (let i = 0; i < 5; i++) {
        participants.push(randomNumber());
      }

      const quorum = BigInt(80) * PRECISION;

      const tx = zkMultisigFactory.connect(alice).createMultisig(participants, quorum, salt);

      await expect(tx).to.emit(zkMultisigFactory, "ZKMultisigCreated").withArgs(multisigAddress, participants, quorum);

      expect(await zkMultisigFactory.isZKMultisig(multisigAddress)).to.be.eq(true);
      expect(await zkMultisigFactory.getZKMultisigsCount()).to.be.eq(1);
      expect(await zkMultisigFactory.getZKMultisigs(0, 1)).to.be.deep.eq([multisigAddress]);
    });
  });
});
