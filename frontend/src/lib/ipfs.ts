function randHex(len = 32) {
  const arr = new Uint8Array(len/2);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b=>b.toString(16).padStart(2,"0")).join("");
}

export async function ipfsPutJson(obj: any): Promise<string> {
  const key = "local://" + randHex(40);
  localStorage.setItem(key, JSON.stringify(obj));
  return key;
}

export async function ipfsGetJson(uri: string): Promise<any> {
  if (!uri) throw new Error("empty URI");
  if (uri.startsWith("local://")) {
    const raw = localStorage.getItem(uri);
    if (!raw) throw new Error(`local URI not found in this browser: ${uri}`);
    return JSON.parse(raw);
  }
  throw new Error("Only local:// is implemented for this project demo");
}