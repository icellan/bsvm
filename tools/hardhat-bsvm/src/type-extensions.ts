// type-extensions.ts — augment Hardhat's runtime and config types so
// users can declare a `bsvm` network with proveMode, and reach for the
// `hre.bsvm` namespace in scripts and tasks.

import "hardhat/types/config";
import "hardhat/types/runtime";

import type { BsvmHelpers } from "./helpers";

/** Proving mode declared on a BSVM network. Mirrors spec 16. */
export type BsvmProveMode = "mock" | "execute" | "prove";

/**
 * User-facing config for a BSVM network. Deliberately a thin extension
 * of Hardhat's HttpNetworkUserConfig so users can keep using the
 * standard `accounts`, `gas`, `gasPrice`, etc.
 */
export interface BsvmNetworkUserConfig {
  url: string;
  chainId?: number;
  proveMode?: BsvmProveMode;
  accounts?: string[] | { mnemonic: string };
  timeout?: number;
}

/** Resolved BSVM network config — same shape with defaults filled in. */
export interface BsvmNetworkConfig {
  url: string;
  chainId: number;
  proveMode: BsvmProveMode;
  accounts?: string[] | { mnemonic: string };
  timeout?: number;
}

declare module "hardhat/types/config" {
  interface HardhatUserConfig {
    bsvm?: Record<string, BsvmNetworkUserConfig>;
  }

  interface HardhatConfig {
    bsvm: Record<string, BsvmNetworkConfig>;
  }
}

declare module "hardhat/types/runtime" {
  interface HardhatRuntimeEnvironment {
    bsvm: BsvmHelpers;
  }
}
