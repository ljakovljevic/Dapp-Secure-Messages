// src/pages/Send.tsx
import { useState } from "react";
import { ethers } from "ethers";
import { getSignerAndContract } from "../lib/eth";
import { ipfsPutJson, ipfsGetJson } from "../lib/ipfs";
import {
  aesGenKey, aesEncrypt, aesExportRaw, sha256Bytes,
  bytesToHex, bytesToBase64,
  importRsaPublicKeyJwk, rsaOaepEncrypt
} from "../lib/crypto";

export default function Send() {
  const [recipient, setRecipient] = useState("");
  const [message, setMessage] = useState("");
  const [status, setStatus] = useState("");

  async function onSend() {
    setStatus("");
    try {
      if (!recipient || !message) { setStatus("Recipient and message are required."); return; }
      const { provider, signer, contract } = await getSignerAndContract();

      const addr = typeof (contract as any).getAddress === "function"
        ? await (contract as any).getAddress()
        : ((contract as any).target ?? (contract as any).address);
      const code = await (provider as any).getCode(addr);
      if (!code || code === "0x") { setStatus(`Contract not deployed at ${addr}.`); return; }

      setStatus("Encrypting message...");
      const aesKey = await aesGenKey();
      const { ciphertext, iv } = await aesEncrypt(message, aesKey);
      const sha = await sha256Bytes(ciphertext);

      setStatus(s => s + "\nFetching recipient key (if any)...");
      let keyCID = "local://no-key";
      try {
        const rec = await contract.keyRegistry(recipient);
        const uri: string = rec?.rsaPubKeyURI ?? rec?.[1] ?? "";
        if (uri && uri !== "local://no-key") {
          try {
            const jwk = await ipfsGetJson(uri);
            const pub = await importRsaPublicKeyJwk(jwk);
            const raw = await aesExportRaw(aesKey);
            const encKey = await rsaOaepEncrypt(pub, raw);
            keyCID = await ipfsPutJson({ scheme:"RSA-OAEP-256", v:1, encrypted_key_b64: bytesToBase64(encKey) });
          } catch (e) {
            setStatus(s => s + `\nCannot access recipient key at ${uri} — sending without encrypted data key.`);
          }
        } else {
          setStatus(s => s + "\nRecipient has no registered public key — sending without encrypted data key.");
        }
      } catch {
        setStatus(s => s + "\nCould not read key registry — sending without encrypted data key.");
      }

      setStatus(s => s + "\nUploading content...");
      const contentCID = await ipfsPutJson({ algo:"AES-256-GCM", v:1, iv: bytesToHex(iv), ciphertext_b64: bytesToBase64(ciphertext) });

      const me = await signer.getAddress();
      const last: bigint = await contract.lastNonce(me);
      const nonce = last + 1n;

      setStatus(s => s + "\nSending on-chain...");
      const tx = await contract.sendMessage(
        recipient,
        contentCID,
        keyCID,
        sha,
        bytesToHex(iv),
        nonce,
        0,
        ethers.ZeroHash,
        ethers.ZeroHash
      );
      const rc = await tx.wait();

      let id: bigint | null = null;
      for (const log of rc.logs ?? []) {
        try {
          const parsed = (contract as any).interface.parseLog(log);
          if (parsed?.name === "MessageSent") { id = parsed.args?.id as bigint; break; }
        } catch {}
      }
      if (id != null) localStorage.setItem(`msgmap:${id.toString()}`, JSON.stringify({ contentCID, keyCID }));

      setStatus(`Sent! contentCID=${contentCID} keyCID=${keyCID}`);
    } catch (e: any) {
      console.error(e); setStatus(`Send failed: ${e?.message ?? e}`);
    }
  }

  return (
    <div className="section">
      <h3 style={{marginTop: 6}}>Send</h3>
      <div style={{display:"grid", gap: 10}}>
        <input className="input" placeholder="Recipient address 0x..." value={recipient} onChange={e=>setRecipient(e.target.value)} />
        <textarea className="textarea" placeholder="Message..." value={message} onChange={e=>setMessage(e.target.value)} />
        <button className="btn-primary" onClick={onSend}>Send</button>
      </div>
      <pre className="status">{status}</pre>
    </div>
  );
}