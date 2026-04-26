#!/usr/bin/env node
// Thin shebang launcher. The real CLI lives in dist/index.js (compiled
// from src/index.ts). Keeping this file dependency-free means `npx
// create-bsvm-devnet` works without an extra resolution step.
"use strict";

require("../dist/index.js").run(process.argv.slice(2)).catch((err) => {
  if (err && err.message) {
    console.error("create-bsvm-devnet: " + err.message);
  } else {
    console.error("create-bsvm-devnet: unexpected error", err);
  }
  process.exit(1);
});
