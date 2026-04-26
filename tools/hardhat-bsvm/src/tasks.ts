// tasks.ts — Hardhat tasks exposed by the plugin. Each task defers to
// the helpers attached at `hre.bsvm`, so they share the active network
// provider (selected with --network on the CLI).

import { task, types } from "hardhat/config";

export function registerTasks(): void {
  task("bsvm:status", "Print BSVM proving status from the active network")
    .setAction(async (_args, hre) => {
      const status = await hre.bsvm.provingStatus();
      console.log(JSON.stringify(status, null, 2));
    });

  task("bsvm:deposits", "List bridge deposits credited to an L2 address")
    .addPositionalParam(
      "address",
      "L2 address to filter for (case-insensitive 0x… hex)",
      undefined,
      types.string,
    )
    .addOptionalParam(
      "fromBlock",
      "Earliest BSV block height to include",
      0,
      types.int,
    )
    .addOptionalParam(
      "toBlock",
      "Latest BSV block height (0 = no upper bound)",
      0,
      types.int,
    )
    .setAction(async (args, hre) => {
      const wanted = args.address.toLowerCase();
      const all = await hre.bsvm.bridgeDeposits(args.fromBlock, args.toBlock);
      const matching = all.filter(
        (d) => (d.l2Address || "").toLowerCase() === wanted,
      );
      console.log(JSON.stringify(matching, null, 2));
    });

  task("bsvm:withdrawals", "List recent bridge withdrawals for an address")
    .addPositionalParam(
      "address",
      "BSV destination address to filter for",
      undefined,
      types.string,
    )
    .addOptionalParam(
      "fromNonce",
      "Earliest L2 withdrawal nonce (inclusive)",
      0,
      types.int,
    )
    .addOptionalParam(
      "toNonce",
      "Exclusive upper bound for L2 withdrawal nonce (0 = default page)",
      0,
      types.int,
    )
    .setAction(async (args, hre) => {
      const wanted = args.address;
      const all = await hre.bsvm.bridgeWithdrawals(
        args.fromNonce,
        args.toNonce,
      );
      const matching = all.filter((w) => w.bsvAddress === wanted);
      console.log(JSON.stringify(matching, null, 2));
    });

  task("bsvm:fee-wallet", "Print the prover fee wallet balance")
    .setAction(async (_args, hre) => {
      const balance = await hre.bsvm.feeWalletBalance();
      console.log(JSON.stringify(balance, null, 2));
    });
}
