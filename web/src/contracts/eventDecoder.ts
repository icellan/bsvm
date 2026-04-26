// eventDecoder — pull recent logs for a contract and decode them
// against its ABI. The contract-interaction page renders this below
// the read/write method lists so users can see the contract's
// activity without leaving the page.
//
// We constrain the lookback to a small window (default 1000 blocks
// or chain head, whichever is smaller) to keep the eth_getLogs
// payload small. Larger windows would need server-side pagination.

import { Interface } from "ethers";

import { eth, hexToNumber, LogEntry } from "@/rpc/client";
import { AbiFragment } from "@/contracts/abiStore";
import { prettyValue } from "@/contracts/methodCaller";

export type DecodedLog = {
  address: string;
  blockNumber: number;
  txHash: string;
  logIndex: number;
  // name is undefined when the topic[0] doesn't match any event in
  // the supplied ABI (e.g. a Transfer log on a contract whose ABI
  // wasn't uploaded).
  name?: string;
  args?: { name: string; type: string; value: string; indexed: boolean }[];
  raw: LogEntry;
};

// fetchAndDecode reads the most recent N blocks of logs for the
// address and decodes each one against the ABI. Returns most recent
// first.
export async function fetchAndDecode(opts: {
  address: string;
  abi: AbiFragment[];
  // window is the block lookback. Default 1000.
  window?: number;
}): Promise<DecodedLog[]> {
  const window = opts.window ?? 1000;
  const headHex = await eth.blockNumber();
  const head = hexToNumber(headHex);
  const fromBlock = Math.max(0, head - window);
  const logs = await eth.getLogs({
    address: opts.address,
    fromBlock: `0x${fromBlock.toString(16)}`,
    toBlock: "latest",
  });

  const iface = new Interface(opts.abi as unknown as never[]);
  const decoded: DecodedLog[] = [];
  for (const log of logs) {
    const out: DecodedLog = {
      address: log.address,
      blockNumber: hexToNumber(log.blockNumber),
      txHash: log.transactionHash,
      logIndex: hexToNumber(log.logIndex),
      raw: log,
    };
    try {
      const parsed = iface.parseLog({
        topics: log.topics,
        data: log.data,
      });
      if (parsed) {
        out.name = parsed.name;
        out.args = parsed.fragment.inputs.map((input, i) => ({
          name: input.name || `arg${i}`,
          type: input.type,
          value: prettyValue(parsed.args[i]),
          indexed: !!input.indexed,
        }));
      }
    } catch {
      // Unmatched log — leave name undefined; the UI renders the
      // raw topics + data as a fallback.
    }
    decoded.push(out);
  }
  // Newest first.
  decoded.sort((a, b) => {
    if (a.blockNumber !== b.blockNumber) return b.blockNumber - a.blockNumber;
    return b.logIndex - a.logIndex;
  });
  return decoded;
}
