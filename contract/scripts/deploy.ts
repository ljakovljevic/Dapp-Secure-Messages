import { ethers } from "hardhat";
import hre from "hardhat";
import { writeFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying with:", await deployer.getAddress());
  const Factory = await ethers.getContractFactory("EncryptedMessaging");
  const contract = await Factory.deploy();
  await contract.waitForDeployment();
  const address = await contract.getAddress();
  console.log("EncryptedMessaging deployed at:", address);

  // Sačuvaj ABI + adresu za frontend
  const artifact = await hre.artifacts.readArtifact("EncryptedMessaging");
  const outDir = join(__dirname, "..", "..", "frontend", "src", "contracts");
  if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });
  writeFileSync(
    join(outDir, "EncryptedMessaging.json"),
    JSON.stringify({ address, abi: artifact.abi }, null, 2),
    "utf-8"
  );
  console.log("Wrote frontend artifact to frontend/src/contracts/EncryptedMessaging.json");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});