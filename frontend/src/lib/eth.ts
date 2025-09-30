import { BrowserProvider, Contract } from "ethers";
import artifact from "../contracts/EncryptedMessaging.json";

declare global { interface Window { ethereum?: any } }

function waitForEthereum(timeoutMs = 3000): Promise<any> {
  return new Promise((resolve, reject) => {
    if (window.ethereum) return resolve(window.ethereum);
    const onInit = () => window.ethereum && resolve(window.ethereum);
    window.addEventListener("ethereum#initialized", onInit, { once: true });
    setTimeout(() => {
      window.removeEventListener("ethereum#initialized", onInit);
      window.ethereum ? resolve(window.ethereum) : reject(new Error("Wallet not found"));
    }, timeoutMs);
  });
}

async function ensureAccounts(eth: any): Promise<string[]> {
  const acc = await eth.request({ method: "eth_accounts" });
  if (acc?.length) return acc;
  try {
    return await eth.request({ method: "eth_requestAccounts" });
  } catch (e: any) {
    if (e?.code === -32002) throw new Error("Connection request pending in MetaMask—open extension and approve.");
    throw e;
  }
}

export async function getSignerAndContract() {
  const eth = await waitForEthereum();
  await ensureAccounts(eth);
  const provider = new BrowserProvider(eth);
  const signer = await provider.getSigner();
  const contract = new Contract(artifact.address, artifact.abi, signer);
  return { provider, signer, contract };
}

export async function connectWallet(): Promise<{ address: string; chainId: number }> {
  const eth = await waitForEthereum();
  const accounts = await eth.request({ method: "eth_requestAccounts" });
  const address = accounts?.[0];
  if (!address) throw new Error("No account returned by wallet");
  const chainHex: string = await eth.request({ method: "eth_chainId" });
  const chainId = parseInt(chainHex, 16);
  return { address, chainId };
}

export async function getWalletStatus(): Promise<{ address: string | null; chainId: number | null }> {
  const eth = await waitForEthereum();
  const accounts = await eth.request({ method: "eth_accounts" });
  const address = accounts?.[0] ?? null;
  const chainHex: string = await eth.request({ method: "eth_chainId" });
  const chainId = parseInt(chainHex, 16);
  return { address, chainId };
}

export function onWalletEvents(opts: {
  onAccountsChanged?: (addr: string | null) => void;
  onChainChanged?: (chainId: number) => void;
}) {
  if (!window.ethereum) return () => {};
  const { onAccountsChanged, onChainChanged } = opts;
  const accHandler = (accs: string[]) => onAccountsChanged?.(accs?.[0] ?? null);
  const chainHandler = (hex: string) => onChainChanged?.(parseInt(hex, 16));
  window.ethereum.on?.("accountsChanged", accHandler);
  window.ethereum.on?.("chainChanged", chainHandler);
  return () => {
    window.ethereum?.removeListener?.("accountsChanged", accHandler);
    window.ethereum?.removeListener?.("chainChanged", chainHandler);
  };
}

export function shorten(addr?: string | null, left = 6, right = 4) {
  if (!addr) return "";
  return addr.slice(0, left) + "…" + addr.slice(-right);
}