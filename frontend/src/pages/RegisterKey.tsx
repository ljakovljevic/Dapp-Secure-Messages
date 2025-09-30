// src/pages/RegisterKey.tsx
import { useState } from "react";
import { getSignerAndContract } from "../lib/eth";
import { ipfsPutJson } from "../lib/ipfs";
import { sha256HexOfString } from "../lib/crypto";

export default function RegisterKey() {
  const [jwkText, setJwkText] = useState("");
  const [status, setStatus] = useState("");

  async function onRegister() {
    setStatus("");
    try {
      const { provider, contract } = await getSignerAndContract();      

      
      const addr = typeof (contract as any).getAddress === "function"
        ? await (contract as any).getAddress()
        : ((contract as any).target ?? (contract as any).address);
      const code = await (provider as any).getCode(addr);
      if (!code || code === "0x") {
        setStatus(`Contract not deployed at ${addr} on this network.`);
        return;
      }

      
      setStatus("Parsing JWK...");
      const jwk = JSON.parse(jwkText);

      const canonical = JSON.stringify(jwk);
      setStatus("Computing fingerprint...");
      const fp = await sha256HexOfString(canonical);

      setStatus("Saving public key (local://)...");
      const uri = await ipfsPutJson(jwk);

      if (!/^0x[0-9a-fA-F]{64}$/.test(fp)) {
        setStatus(`Invalid fingerprint (expected 0x + 64 hex chars): ${fp}`);
        return;
      }
      if (!uri || !uri.startsWith("local://")) {
        setStatus(`Invalid or unsupported URI: ${uri} (expected local://...)`);
        return;
      }
      if (!localStorage.getItem(uri)) {
        setStatus(`Public JWK not found at ${uri} in this browser. Save failed?`);
        return;
      }

      try {
        const me = await (await getSignerAndContract()).signer.getAddress();
        await contract.keyRegistry(me);
      } catch (e) {
        console.warn("keyRegistry read failed (non-fatal):", e);
      }

      setStatus("Submitting on-chain...");
      const tx = await contract.registerRSAPublicKey(fp, uri, { gasLimit: 200000n });
      const rc = await tx.wait();

      setStatus(`Registered!\nfp=${fp}\nuri=${uri}`);
    } catch (e: any) {
      console.error(e);
      setStatus(e?.shortMessage ?? e?.message ?? String(e));
    }
  }

  return (
    <div className="section">
      <h3 style={{marginTop: 6}}>Register public RSA key</h3>
      <p>Paste <b>PUBLIC</b> JWK (e.g. kty, n, e, alg: RSA-OAEP-256, ext: true)</p>
      <textarea className="textarea" value={jwkText} onChange={e=>setJwkText(e.target.value)} />
      <div style={{marginTop:8}}>
        <button className="btn-primary" onClick={onRegister}>Register Key</button>
      </div>
      <pre className="status">{status}</pre>
    </div>
  );
}