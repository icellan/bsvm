// hardhat-bsvm — Hardhat plugin for BSVM.
//
// Usage:
//   require("hardhat-bsvm");
//
// Adds:
//   - A `bsvm` block in HardhatUserConfig where users declare BSVM
//     networks with optional chainId + proveMode.
//   - For each declared `bsvm` network, a sibling Hardhat HTTP network
//     of the same name so `--network <name>` Just Works with ethers,
//     `cast`, and existing scripts.
//   - `hre.bsvm`, a typed namespace exposing the bsv_* JSON-RPC methods.
//   - Tasks: bsvm:status, bsvm:deposits, bsvm:withdrawals, bsvm:fee-wallet.

import { extendConfig, extendEnvironment } from "hardhat/config";
import type {
  HardhatConfig,
  HardhatUserConfig,
  HttpNetworkUserConfig,
} from "hardhat/types";

import { makeHelpers } from "./helpers";
import { registerTasks } from "./tasks";
import "./type-extensions";
import type { BsvmNetworkConfig, BsvmProveMode } from "./type-extensions";

const VALID_PROVE_MODES: ReadonlyArray<BsvmProveMode> = [
  "mock",
  "execute",
  "prove",
];

extendConfig(
  (config: HardhatConfig, userConfig: Readonly<HardhatUserConfig>) => {
    const userBsvm = userConfig.bsvm ?? {};
    const resolved: Record<string, BsvmNetworkConfig> = {};

    for (const [name, raw] of Object.entries(userBsvm)) {
      if (!raw || typeof raw.url !== "string" || raw.url.length === 0) {
        throw new Error(
          `hardhat-bsvm: network "${name}" is missing required "url" field`,
        );
      }

      const proveMode: BsvmProveMode = raw.proveMode ?? "mock";
      if (!VALID_PROVE_MODES.includes(proveMode)) {
        throw new Error(
          `hardhat-bsvm: network "${name}" has invalid proveMode "${proveMode}". ` +
            `Expected one of: ${VALID_PROVE_MODES.join(", ")}`,
        );
      }

      const chainId = raw.chainId ?? 31337;

      resolved[name] = {
        url: raw.url,
        chainId,
        proveMode,
        accounts: raw.accounts,
        timeout: raw.timeout,
      };

      // Mirror the BSVM network as a standard Hardhat HTTP network of
      // the same name, unless the user already declared one explicitly.
      // This is what makes `--network <name>` work without extra wiring.
      if (config.networks[name] === undefined) {
        const httpNet: HttpNetworkUserConfig = {
          url: raw.url,
          chainId,
          accounts: raw.accounts as HttpNetworkUserConfig["accounts"],
          timeout: raw.timeout,
        };
        // Hardhat expects HttpNetworkConfig (resolved) not the user
        // shape, but the only required field beyond the user config is
        // a few defaults; cast and Hardhat will accept it as a network
        // entry at runtime.
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (config.networks as any)[name] = {
          ...httpNet,
          httpHeaders: {},
          gas: "auto",
          gasPrice: "auto",
          gasMultiplier: 1,
        };
      }
    }

    config.bsvm = resolved;
  },
);

extendEnvironment((hre) => {
  hre.bsvm = makeHelpers(hre);
});

registerTasks();
