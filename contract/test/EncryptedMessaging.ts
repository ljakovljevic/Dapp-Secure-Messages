import { expect } from "chai";
import { ethers } from "hardhat";
import { Signer } from "ethers";
import { randomBytes } from "crypto";
import type { EncryptedMessaging } from "../../typechain-types";

describe("EncryptedMessaging", function () {
  let messaging: EncryptedMessaging;
  let deployer: Signer;
  let alice: Signer;
  let bob: Signer;
  let charlie: Signer;

  beforeEach(async () => {
    [deployer, alice, bob, charlie] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("EncryptedMessaging", deployer);
    messaging = (await Factory.deploy() as unknown as EncryptedMessaging);
    await messaging.waitForDeployment();
  });

  const sha256 = ethers.sha256;
  const toUtf8Bytes = ethers.toUtf8Bytes;
  const keccak256 = ethers.keccak256;

  async function getAddress(s: Signer): Promise<string> {
    return await s.getAddress();
  }

  function buildCommitPacked(
    sender: string,
    recipient: string,
    timestamp: bigint,
    sha256Hash: string,  
    iv: string,          
    contentCID: string,
    keyCID: string,
    nonce: bigint
  ): string {
    const contentCidHash = keccak256(toUtf8Bytes(contentCID));
    const keyCidHash = keccak256(toUtf8Bytes(keyCID));

    return ethers.solidityPackedKeccak256(
      [
        "bytes1",   
        "bytes1",   
        "string",   
        "address",
        "address",
        "uint64",
        "bytes32",
        "bytes12",
        "bytes32",
        "bytes32",
        "uint128",
      ],
      [
        "0x19",
        "0x45",
        "MSG:",
        sender,
        recipient,
        timestamp,
        sha256Hash,
        iv,
        contentCidHash,
        keyCidHash,
        nonce,
      ]
    );

  }

  async function signCommit(
    signer: Signer,
    commit: string
  ): Promise<{ v: number; r: string; s: string }> {
    const sig = await signer.signMessage(ethers.getBytes(commit));

    const { v, r, s } = ethers.Signature.from(sig);
    return { v, r, s };
  }

  async function incTime(seconds: number) {
    await ethers.provider.send("evm_increaseTime", [seconds]);
    await ethers.provider.send("evm_mine", []);
  }

  // ------- Tests -------

  it("Key registry: register RSA public key fingerprint + URI", async () => {
    const a = await getAddress(alice);
    const fp = "0x" + "11".repeat(32); 
    const uri = "ipfs://bafyrsapubkey";
    await expect(messaging.connect(alice).registerRSAPublicKey(fp, uri))
      .to.emit(messaging, "KeyRegistered")
      .withArgs(a, fp, uri, anyUint64());
    const rec = await messaging.keyRegistry(a);
    expect(rec.rsaPubKeySha256).to.eq(fp);
    expect(rec.rsaPubKeyURI).to.eq(uri);
  });

  it("Happy path: send message WITHOUT signature (zeros for v/r/s)", async () => {
    const sender = await getAddress(alice);
    const recipient = await getAddress(bob);

    const contentCID = "ipfs://bafycontent1";
    const keyCID = "ipfs://bafykey1";
    const ciphertext = "ciphertext bytes here";
    const sha = sha256(toUtf8Bytes(ciphertext)); // bytes32
    const ivBytes = randomBytes(12);
    const ivHex = "0x" + ivBytes.toString("hex"); // bytes12
    const last = await messaging.lastNonce(sender);
    const nonce = (last + 1n) as bigint;
    const nowTs = BigInt(Math.floor(Date.now() / 1000));

    // without signature: v=0, r=0x0, s=0x0
    await expect(
      messaging.connect(alice).sendMessage(
        recipient,
        contentCID,
        keyCID,
        sha,
        ivHex,
        nonce,
        0, // v
        ethers.ZeroHash, // r
        ethers.ZeroHash  // s
      )
    ).to.emit(messaging, "MessageSent");

    const inboxIds = await messaging.getInboxIds(recipient);
    const outboxIds = await messaging.getOutboxIds(sender);
    expect(inboxIds.length).to.eq(1);
    expect(outboxIds.length).to.eq(1);

    const used = await messaging.isIVUsed(sender, recipient, ivHex);
    expect(used).to.eq(true);
  });

  it("Happy path: send message WITH signature", async () => {
    const sender = await getAddress(alice);
    const recipient = await getAddress(bob);

    const contentCID = "ipfs://bafycontent2";
    const keyCID = "ipfs://bafykey2";
    const ciphertext = "ciphertext 2";
    const sha = sha256(toUtf8Bytes(ciphertext));
    const ivHex = "0x" + randomBytes(12).toString("hex");
    const last = await messaging.lastNonce(sender);
    const nonce = (last + 1n) as bigint;

    const latest = await ethers.provider.getBlock("latest");
    const nowTs = BigInt(latest!.timestamp + 1);
    await ethers.provider.send("evm_setNextBlockTimestamp", [Number(nowTs)]);

    const commit = buildCommitPacked(
      sender,
      recipient,
      nowTs,
      sha,
      ivHex,
      contentCID,
      keyCID,
      nonce
    );
    const { v, r, s } = await signCommit(alice, commit);

    // First call: OK
    await expect(
      messaging.connect(alice).sendMessage(
        recipient,
        contentCID,
        keyCID,
        sha,
        ivHex,
        nonce,
        v, r, s
      )
    ).to.emit(messaging, "MessageSent");

    // Second call should fall immediately because of rate-limit (default 10s)
    const ivHex2 = "0x" + randomBytes(12).toString("hex");
    const nonce2 = nonce + 1n;

    const nowTs2 = nowTs + 5n;
    const commit2 = buildCommitPacked(
      sender,
      recipient,
      nowTs2, 
      sha,
      ivHex2,
      contentCID,
      keyCID,
      nonce2
    );
    const sig2 = await signCommit(alice, commit2);

    await ethers.provider.send("evm_setNextBlockTimestamp", [Number(nowTs2)]);
    await expect(
      messaging.connect(alice).sendMessage(
        recipient,
        contentCID,
        keyCID,
        sha,
        ivHex2,
        nonce2,
        sig2.v, sig2.r, sig2.s
      )
    ).to.be.revertedWith("rate-limited");
  });

  it("Rate limit: after increasing time, second message passes", async () => {
    const sender = await getAddress(alice);
    const recipient = await getAddress(bob);

    const contentCID = "ipfs://bafycontent3";
    const keyCID = "ipfs://bafykey3";
    const sha = sha256(toUtf8Bytes("c3"));
    const iv1 = "0x" + randomBytes(12).toString("hex");
    const iv2 = "0x" + randomBytes(12).toString("hex");

    // #1 
    let nonce = (await messaging.lastNonce(sender)) + 1n;
    await expect(
      messaging.connect(alice).sendMessage(recipient, contentCID, keyCID, sha, iv1, nonce, 0, ethers.ZeroHash, ethers.ZeroHash)
    ).to.emit(messaging, "MessageSent");

    // immediately #2 — should fall
    nonce = nonce + 1n;
    await expect(
      messaging.connect(alice).sendMessage(recipient, contentCID, keyCID, sha, iv2, nonce, 0, ethers.ZeroHash, ethers.ZeroHash)
    ).to.be.revertedWith("rate-limited");

    //increase limit for 10s (default minIntervalSeconds)
    await incTime(10);

    // #2 now pass
    await expect(
      messaging.connect(alice).sendMessage(recipient, contentCID, keyCID, sha, iv2, nonce, 0, ethers.ZeroHash, ethers.ZeroHash)
    ).to.emit(messaging, "MessageSent");
  });

  it("IV reuse is forbidden for the same (sender, recipient)", async () => {
    const sender = await getAddress(alice);
    const recipient = await getAddress(bob);

    const contentCID = "ipfs://bafycontent4";
    const keyCID = "ipfs://bafykey4";
    const sha = sha256(toUtf8Bytes("c4"));
    const iv = "0x" + randomBytes(12).toString("hex");

    let nonce = (await messaging.lastNonce(sender)) + 1n;

    await expect(
      messaging.connect(alice).sendMessage(recipient, contentCID, keyCID, sha, iv, nonce, 0, ethers.ZeroHash, ethers.ZeroHash)
    ).to.emit(messaging, "MessageSent");

    // avoid rate limit
    await incTime(10);

    // same IV --> revert
    nonce = nonce + 1n;
    await expect(
      messaging.connect(alice).sendMessage(recipient, contentCID, keyCID, sha, iv, nonce, 0, ethers.ZeroHash, ethers.ZeroHash)
    ).to.be.revertedWith("IV already used");
  });

  it("Bad nonce is rejected", async () => {
    const sender = await getAddress(alice);
    const recipient = await getAddress(bob);

    const contentCID = "ipfs://bafycontent5";
    const keyCID = "ipfs://bafykey5";
    const sha = sha256(toUtf8Bytes("c5"));
    const iv = "0x" + randomBytes(12).toString("hex");

    const last = await messaging.lastNonce(sender);
    const wrong = last + 2n; 

    await expect(
      messaging.connect(alice).sendMessage(recipient, contentCID, keyCID, sha, iv, wrong, 0, ethers.ZeroHash, ethers.ZeroHash)
    ).to.be.revertedWith("bad nonce");
  });

  it("Bad signature (signed by someone else) is rejected", async () => {
    const sender = await getAddress(alice);
    const recipient = await getAddress(bob);

    const contentCID = "ipfs://bafycontent6";
    const keyCID = "ipfs://bafykey6";
    const sha = sha256(toUtf8Bytes("c6"));
    const iv = "0x" + randomBytes(12).toString("hex");
    const nonce = (await messaging.lastNonce(sender)) + 1n;
    const nowTs = BigInt(Math.floor(Date.now() / 1000));

    const commit = buildCommitPacked(
      sender,
      recipient,
      nowTs,
      sha,
      iv,
      contentCID,
      keyCID,
      nonce
    );

    // charlie instead of alice -> should fall
    const badSig = await signCommit(charlie, commit);

    await expect(
      messaging.connect(alice).sendMessage(
        recipient,
        contentCID,
        keyCID,
        sha,
        iv,
        nonce,
        badSig.v, badSig.r, badSig.s
      )
    ).to.be.revertedWith("bad signature");
  });

  it("Inbox/Outbox indexing and read-back MessageMeta", async () => {
    const sender = await getAddress(alice);
    const recipient = await getAddress(bob);

    const contentCID = "ipfs://bafycontent7";
    const keyCID = "ipfs://bafykey7";
    const sha = sha256(toUtf8Bytes("c7"));
    const iv = "0x" + randomBytes(12).toString("hex");

    const nonce = (await messaging.lastNonce(sender)) + 1n;

    const tx = await messaging.connect(alice).sendMessage(
      recipient, contentCID, keyCID, sha, iv, nonce, 0, ethers.ZeroHash, ethers.ZeroHash
    );
    const rc = await tx.wait();
    const ev = rc!.logs.find(l => (l as any).fragment?.name === "MessageSent") as any;
    const id = ev?.args?.id as bigint;

    const msg = await messaging.messages(id);
    expect(msg.sender).to.eq(sender);
    expect(msg.recipient).to.eq(recipient);
    expect(msg.sha256Hash).to.eq(sha);
    expect(msg.iv.toLowerCase()).to.eq(iv.toLowerCase());

    const inbox = await messaging.getInboxIds(recipient);
    const outbox = await messaging.getOutboxIds(sender);
    expect(inbox.map((x: bigint) => x.toString())).to.include(id.toString());
    expect(outbox.map((x: bigint) => x.toString())).to.include(id.toString());
  });
});

// Matcher for uint64 in event (timestamp often changes)
function anyUint64() {
  return (val: any) => {
    try {
      const b = BigInt(val);
      return b >= 0n && b < (1n << 64n);
    } catch {
      return false;
    }
  };
}