import { useEffect, useState } from "react";
import { connectWallet, getWalletStatus, onWalletEvents, shorten } from "../lib/eth";

const CHAINS: Record<number, string> = {
  31337: "Hardhat (localhost)",
  11155111: "Sepolia",
};

export default function Connect() {
  const [address, setAddress] = useState<string | null>(null);
  const [chainId, setChainId] = useState<number | null>(null);
  const [err, setErr] = useState<string>("");

  useEffect(() => {
    getWalletStatus()
      .then(s => { setAddress(s.address); setChainId(s.chainId); })
      .catch(e => setErr(e?.message ?? String(e)));
    const off = onWalletEvents({
      onAccountsChanged: a => setAddress(a),
      onChainChanged: id => setChainId(id),
    });
    return off;
  }, []);

  async function onConnect() {
    setErr("");
    try {
      const s = await connectWallet();
      setAddress(s.address);
      setChainId(s.chainId);
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    }
  }

  const label = chainId != null ? (CHAINS[chainId] ?? `Chain ${chainId}`) : "…";

  return (
    <div style={{display:"flex", alignItems:"center", gap:12, flexWrap:"wrap"}}>
      <button onClick={onConnect}>Connect Wallet</button>
      <div style={{fontSize:14, color:"#333"}}>
        {address ? (
          <>
            <b>Account:</b> {shorten(address)} &nbsp;|&nbsp; <b>Network:</b> {label}
          </>
        ) : (
          <span style={{color:"#888"}}>Not connected</span>
        )}
      </div>
      {err && <div style={{color:"#a00", fontSize:12}}>{err}</div>}
    </div>
  );
}