import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "hardhat-bsvm";

// Hardhat default test accounts. The BSVM devnet pre-funds these with
// 1000 wBSV each, matching the Hardhat / Foundry developer experience.
const HARDHAT_PRIVATE_KEYS = [
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
  "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
];

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: { enabled: true, runs: 200 },
    },
  },
  bsvm: {
    devnet: {
      url: "http://localhost:8545",
      chainId: {{CHAIN_ID}},
      proveMode: "{{PROVE_MODE}}",
      accounts: HARDHAT_PRIVATE_KEYS,
    },
{{EXTRA_NETWORKS}}  },
  defaultNetwork: "devnet",
};

export default config;
