import { ethers } from "hardhat";
import constants from "../../config/constants.json";


async function main() {
const [deployer] = await ethers.getSigners();
const Verifier = await ethers.getContractFactory("FastPathVRFVerifier");
const attestor = process.env.ATTESTOR_ADDR!;
const verifier = await Verifier.deploy();
await verifier.waitForDeployment();
await (await verifier.initialize(attestor)).wait();
console.log("Verifier:", await verifier.getAddress());
}
main().catch((e)=>{ console.error(e); process.exit(1); });
