// create-bsvm-devnet — scaffold a local BSVM devnet directory.
//
// Entry point for the npx CLI. Prompts the user for chain ID, proving
// mode, and node count, then materialises a target directory with
// docker-compose.yml, bsvm.json, hardhat.config.ts, contracts/Hello.sol,
// scripts/deploy.ts, .env.example, package.json, and README.md.
//
// Templates live under ../templates/. They use simple {{PLACEHOLDER}}
// substitution so the package has zero runtime template-engine deps.

import * as fs from "fs";
import * as path from "path";
import prompts from "prompts";

const VALID_PROVE_MODES = ["mock", "execute", "prove"] as const;
type ProveMode = (typeof VALID_PROVE_MODES)[number];

interface Answers {
  projectName: string;
  chainId: number;
  proveMode: ProveMode;
  nodeCount: 1 | 3;
}

interface CliFlags {
  yes: boolean;
  positional: string[];
}

/**
 * run is the public entry point. Splits parsing from execution so tests
 * can drive it programmatically without spawning a subprocess.
 */
export async function run(argv: string[]): Promise<void> {
  const flags = parseArgs(argv);

  if (flags.positional.includes("--help") || flags.positional[0] === "help") {
    printUsage();
    return;
  }

  const projectName = flags.positional[0];
  if (!projectName) {
    printUsage();
    throw new Error("project name is required (e.g. `create-bsvm-devnet my-shard`)");
  }

  validateProjectName(projectName);

  const targetDir = path.resolve(process.cwd(), projectName);
  if (fs.existsSync(targetDir)) {
    const stat = fs.statSync(targetDir);
    if (!stat.isDirectory() || fs.readdirSync(targetDir).length > 0) {
      throw new Error(
        `target directory "${projectName}" already exists and is not empty`,
      );
    }
  }

  const answers = await collectAnswers(projectName, flags.yes);

  console.log(`\nScaffolding BSVM devnet in ./${projectName} ...`);
  scaffold(targetDir, answers);

  printSuccess(projectName, answers);
}

function parseArgs(argv: string[]): CliFlags {
  const flags: CliFlags = { yes: false, positional: [] };
  for (const arg of argv) {
    if (arg === "-y" || arg === "--yes") {
      flags.yes = true;
    } else {
      flags.positional.push(arg);
    }
  }
  return flags;
}

function validateProjectName(name: string): void {
  if (!/^[a-z0-9][a-z0-9._-]*$/i.test(name)) {
    throw new Error(
      `invalid project name "${name}": must start with a letter or digit and ` +
        `contain only letters, digits, dots, dashes, or underscores`,
    );
  }
}

async function collectAnswers(
  projectName: string,
  skipPrompts: boolean,
): Promise<Answers> {
  if (skipPrompts) {
    return {
      projectName,
      chainId: 9001,
      proveMode: "mock",
      nodeCount: 3,
    };
  }

  const responses = await prompts(
    [
      {
        type: "number",
        name: "chainId",
        message: "Chain ID for the L2",
        initial: 9001,
        validate: (v: number) =>
          Number.isInteger(v) && v > 0 ? true : "must be a positive integer",
      },
      {
        type: "select",
        name: "proveMode",
        message: "Proving mode",
        choices: [
          { title: "mock — fast, no proof verification", value: "mock" },
          { title: "execute — runs SP1 guest, no STARK", value: "execute" },
          { title: "prove — real STARKs (slow, GPU recommended)", value: "prove" },
        ],
        initial: 0,
      },
      {
        type: "select",
        name: "nodeCount",
        message: "Number of BSVM nodes",
        choices: [
          { title: "3 (two provers + one follower) — recommended", value: 3 },
          { title: "1 (single prover) — minimal", value: 1 },
        ],
        initial: 0,
      },
    ],
    {
      onCancel: () => {
        throw new Error("aborted");
      },
    },
  );

  return {
    projectName,
    chainId: responses.chainId as number,
    proveMode: responses.proveMode as ProveMode,
    nodeCount: responses.nodeCount as 1 | 3,
  };
}

function templatesDir(): string {
  // dist/index.js sits one level below the package root, so templates/
  // is reachable via ../templates from this compiled file.
  return path.resolve(__dirname, "..", "templates");
}

function readTemplate(name: string): string {
  return fs.readFileSync(path.join(templatesDir(), name), "utf8");
}

function applyVars(content: string, vars: Record<string, string>): string {
  return content.replace(/\{\{(\w+)\}\}/g, (_match, key: string) => {
    if (key in vars) {
      return vars[key];
    }
    throw new Error(`template referenced unknown variable "${key}"`);
  });
}

function writeFile(target: string, content: string): void {
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, content);
}

function scaffold(targetDir: string, answers: Answers): void {
  fs.mkdirSync(targetDir, { recursive: true });

  const nodeDescription =
    answers.nodeCount === 3
      ? "node1=prover, node2=prover, node3=follower"
      : "node1=prover only";

  const baseVars: Record<string, string> = {
    PROJECT_NAME: answers.projectName,
    CHAIN_ID: String(answers.chainId),
    PROVE_MODE: answers.proveMode,
    NODE_COUNT: String(answers.nodeCount),
    NODE_DESCRIPTION: nodeDescription,
  };

  // docker-compose.yml — extra nodes / volumes only when nodeCount > 1.
  let extraNodes = "";
  let extraVolumes = "";
  let node2Peers = "";
  if (answers.nodeCount === 3) {
    extraNodes = readTemplate("extra-nodes.yml.tpl");
    extraVolumes = "  node2-data:\n  node3-data:";
    node2Peers = "node2:9945,node3:9945";
  } else {
    node2Peers = ""; // single-node: no peers
  }

  const compose = applyVars(readTemplate("docker-compose.yml.tpl"), {
    ...baseVars,
    EXTRA_NODES: extraNodes,
    EXTRA_VOLUMES: extraVolumes,
    NODE2_PEERS: node2Peers,
  });
  writeFile(path.join(targetDir, "docker-compose.yml"), compose);

  // bsvm.json
  writeFile(
    path.join(targetDir, "bsvm.json"),
    applyVars(readTemplate("bsvm.json.tpl"), baseVars),
  );

  // hardhat.config.ts — node2/node3 entries only when relevant.
  const extraNetworks =
    answers.nodeCount === 3
      ? `    devnet_node2: {
      url: "http://localhost:8546",
      chainId: ${answers.chainId},
      proveMode: "${answers.proveMode}",
      accounts: HARDHAT_PRIVATE_KEYS,
    },
    devnet_node3: {
      url: "http://localhost:8547",
      chainId: ${answers.chainId},
      proveMode: "${answers.proveMode}",
      accounts: HARDHAT_PRIVATE_KEYS,
    },
`
      : "";
  writeFile(
    path.join(targetDir, "hardhat.config.ts"),
    applyVars(readTemplate("hardhat.config.ts.tpl"), {
      ...baseVars,
      EXTRA_NETWORKS: extraNetworks,
    }),
  );

  // contracts/Hello.sol
  writeFile(
    path.join(targetDir, "contracts", "Hello.sol"),
    applyVars(readTemplate("Hello.sol.tpl"), baseVars),
  );

  // scripts/deploy.ts
  writeFile(
    path.join(targetDir, "scripts", "deploy.ts"),
    applyVars(readTemplate("deploy.ts.tpl"), baseVars),
  );

  // .env.example
  writeFile(
    path.join(targetDir, ".env.example"),
    applyVars(readTemplate("env.example.tpl"), baseVars),
  );

  // package.json
  writeFile(
    path.join(targetDir, "package.json"),
    applyVars(readTemplate("package.json.tpl"), baseVars),
  );

  // README.md
  writeFile(
    path.join(targetDir, "README.md"),
    applyVars(readTemplate("README.md.tpl"), baseVars),
  );

  // .gitignore
  writeFile(
    path.join(targetDir, ".gitignore"),
    [
      "node_modules/",
      "artifacts/",
      "cache/",
      "typechain-types/",
      ".env",
      "*.log",
    ].join("\n") + "\n",
  );
}

function printUsage(): void {
  console.log(`Usage:
  npx create-bsvm-devnet <project-name> [--yes]

Scaffolds a BSVM devnet directory with docker-compose, a sample
contract, and a Hardhat config wired to the hardhat-bsvm plugin.

Flags:
  -y, --yes    Skip prompts and use defaults (chainId=9001, proveMode=mock, 3 nodes)
  --help       Show this message`);
}

function printSuccess(projectName: string, answers: Answers): void {
  console.log(`
Done. Next steps:

  cd ${projectName}
  npm install
  npm run up        # boots BSV regtest + ${answers.nodeCount} BSVM node(s)

  In another terminal:
    npm run deploy  # deploys contracts/Hello.sol via Hardhat

  Configuration:
    Chain ID:   ${answers.chainId}
    Prove mode: ${answers.proveMode}
    Nodes:      ${answers.nodeCount}
`);
}
