// src/pages/Inbox.tsx
import { useEffect, useState } from "react";
import { ethers } from "ethers";
import { getSignerAndContract } from "../lib/eth";
import { ipfsGetJson } from "../lib/ipfs";
import {
  importRsaPrivateKeyJwk, rsaOaepDecrypt,
  aesImportRaw, aesDecrypt,
  base64ToBytes, hexToBytes, sha256Bytes
} from "../lib/crypto";

type Item = {
  id: bigint;
  sender: string;
  recipient: string;
  timestamp: bigint;
  sha256Hash: string;
  iv: string;
  contentCID: string; 
  keyCID: string;     
  plaintext?: string; 
  note?: string;      
};

export default function Inbox() {
  const [addr, setAddr] = useState("");
  const [status, setStatus] = useState("");
  const [privJwkText, setPrivJwkText] = useState("");
  const [items, setItems] = useState<Item[]>([]);

  function savePriv() {
    if (!addr) { alert("Connect first"); return; }
    try {
      const jwk = JSON.parse(privJwkText);
      localStorage.setItem(`rsa:priv:${addr}`, JSON.stringify(jwk));
      alert("Private key saved locally for " + addr);
    } catch { alert("Invalid JWK"); }
  }

  async function preloadFromLogs(me: string, contract: any): Promise<Item[]> {
    try {
      const filter = contract.filters.MessageSent(null, null, me);
      const logs = await contract.queryFilter(filter, 0, "latest");
      const out: Item[] = [];
      for (const log of logs) {
        const a = log.args as any;
        out.push({
          id: a.id, sender: a.sender, recipient: a.recipient, timestamp: a.timestamp,
          sha256Hash: a.sha256Hash, iv: a.iv,
          contentCID: "(off-chain)", keyCID: "(off-chain)"
        });
      }
      return out.sort((a,b)=> Number(b.id - a.id));
    } catch (e) {
      console.warn("preloadFromLogs failed", e); return [];
    }
  }

  async function tryDecrypt(me: string, it: Item): Promise<Item> {
    const mapRaw = localStorage.getItem(`msgmap:${it.id.toString()}`);
    if (!mapRaw) return { ...it, note: "Off-chain CIDs unknown on this device (ask sender or use shared backend/IPFS)." };
    const { contentCID, keyCID } = JSON.parse(mapRaw);

    const privRaw = localStorage.getItem(`rsa:priv:${me}`);
    if (!privRaw) return { ...it, contentCID, keyCID, note: "Private JWK not imported for this address." };

    try {
      const priv = await importRsaPrivateKeyJwk(JSON.parse(privRaw));
      const keyJson = await ipfsGetJson(keyCID);
      if (keyJson.encrypted_key_b64 === undefined) return { ...it, contentCID, keyCID, note: "No encrypted data key (message sent when you had no public key)." };

      const encKey = base64ToBytes(keyJson.encrypted_key_b64);
      const rawKey = await rsaOaepDecrypt(priv, encKey);
      const aesKey = await aesImportRaw(rawKey);

      const contentJson = await ipfsGetJson(contentCID);
      const iv = hexToBytes(contentJson.iv);
      const ct = base64ToBytes(contentJson.ciphertext_b64);
      const sha = await sha256Bytes(ct);
      if (sha.toLowerCase() !== it.sha256Hash.toLowerCase()) {
        return { ...it, contentCID, keyCID, note: "Integrity mismatch (on-chain hash != ciphertext hash)." };
      }

      const plaintext = await aesDecrypt(ct, aesKey, iv);
      return { ...it, contentCID, keyCID, plaintext };
    } catch (e: any) {
      console.warn("decrypt failed", e);
      return { ...it, contentCID, keyCID, note: e?.message ?? "Decrypt failed" };
    }
  }

  useEffect(() => {
    let unsub: (()=>void)|null = null;
    let alive = true;

    (async () => {
      setStatus("");
      const { provider, signer, contract } = await getSignerAndContract();
      const me = await signer.getAddress(); if (!alive) return;
      setAddr(me);

      const addr = typeof (contract as any).getAddress === "function"
        ? await (contract as any).getAddress()
        : ((contract as any).target ?? (contract as any).address);
      const code = await (provider as any).getCode(addr);
      if (!code || code === "0x") { setStatus(`Contract not deployed at ${addr}.`); return; }

      setStatus("Loading messages...");
      const base = await preloadFromLogs(me, contract);
      const enriched: Item[] = [];
      for (const it of base) enriched.push(await tryDecrypt(me, it));
      if (!alive) return;
      setItems(enriched);
      setStatus(enriched.length ? "" : "No messages found for this address.");

      const filter = contract.filters.MessageSent(null, null, me);
      const handler = async (...args: any[]) => {
        const a = args[args.length-1].args ?? args as any;
        const baseIt: Item = {
          id: a.id, sender: a.sender, recipient: a.recipient, timestamp: a.timestamp,
          sha256Hash: a.sha256Hash, iv: a.iv, contentCID:"(off-chain)", keyCID:"(off-chain)"
        };
        const enriched = await tryDecrypt(me, baseIt);
        if (!alive) return;
        setItems(prev => [enriched, ...prev]);
        setStatus("");
      };
      contract.on(filter, handler);
      unsub = () => contract.off(filter, handler);
    })();

    return () => { alive=false; if (unsub) unsub(); };
  }, []);

  return (
  <div className="section">
    <h3 style={{marginTop: 6}}>Inbox for {addr || "..."}</h3>
    {status && <p className="status">{status}</p>}

    <div style={{border:"1px solid #eee", padding:12, borderRadius:10, marginBottom:12, background:"#fafafa"}}>
      <div><b>Import PRIVATE RSA key (JWK) for this address</b></div>
      <textarea className="textarea" placeholder='{"kty":"RSA","n":"...","e":"AQAB","d":"...","p":"...","q":"...","dp":"...","dq":"...","qi":"...","alg":"RSA-OAEP-256","ext":true}' value={privJwkText} onChange={e=>setPrivJwkText(e.target.value)} />
      <button className="btn-primary" onClick={savePriv}>Save private key locally</button>
    </div>

    {items.map(it => (
      <div key={it.id.toString()} className="message-card">
        <div><b>ID:</b> {it.id.toString()}</div>
        <div><b>From:</b> {it.sender}</div>
        <div><b>Timestamp:</b> {it.timestamp.toString()}</div>
        <div><b>IV:</b> {it.iv}</div>
        <div><b>SHA-256:</b> {it.sha256Hash}</div>
        <div><b>ContentCID:</b> {it.contentCID}</div>
        <div><b>KeyCID:</b> {it.keyCID}</div>
        {it.note && <div className="note">{it.note}</div>}
        {it.plaintext && (
          <div style={{marginTop:8}}>
            <b>Plaintext:</b>
            <div style={{whiteSpace:"pre-wrap"}}>{it.plaintext}</div>
          </div>
        )}
      </div>
    ))}
  </div>
);
}