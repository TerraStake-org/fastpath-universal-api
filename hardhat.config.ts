import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import * as dotenv from "dotenv";


dotenv.config();


const config: HardhatUserConfig = {
solidity: {
version: "0.8.30",
settings: { optimizer: { enabled: true, runs: 200 } }
},
networks: {
sepolia: { url: process.env.RPC_URL || "", accounts: process.env.DEPLOYER_KEY ? [process.env.DEPLOYER_KEY] : [] },
}
};
export default config;
