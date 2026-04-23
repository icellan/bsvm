---
status: resolved
trigger: "BSV covenant-advance broadcast fails with mandatory-script-verify-flag-failed in Mode 1 FRI devnet"
created: 2026-04-19T22:40:00Z
updated: 2026-04-19T23:15:00Z
---

## Current Focus

hypothesis: Resolved — runar-go SDK tx builder ignores add_data_output ANF bindings
test: Removed AddDataOutput from FRI contract, rebuilt image, resubmitted test tx
expecting: advanceState tx lands on BSV without script-verify failure
next_action: Archive and commit

## Symptoms

expected: advanceState tx accepted into BSV mempool
actual: bitcoind rejects with "mandatory-script-verify-flag-failed (Script evaluated without error but finished with a false/empty top stack element)"
errors: "covenant broadcast failed block=1 error=sendrawtransaction RPC error -26"
reproduction: submit EVM tx via eth_sendRawTransaction to node1:8545
started: current dev cycle
deploy_txid: 446e444f4804bd451fba742f7055dbb20a265806a2c1d964b12d27de61470ba6

## Eliminated

## Evidence

- timestamp: 2026-04-19T22:40:00Z
  checked: cluster status
  found: node1/2/3 healthy, bsv-regtest healthy, deploy txid exists
  implication: failure is on advance broadcast, not initial deploy

- timestamp: 2026-04-19T22:50:00Z
  checked: DEBUG-logged advanceState args vs on-chain covenant state
  found: pvPreStateRoot=0c4322... matches deployed covenant.StateRoot;
         pvPostStateRoot=795c47... matches newStateRoot; pvBatchDataHash
         matches hash256(batchData); pvChainIdBytes=697a00000000000 = LE(31337)
  implication: all four public-value offset bindings are correct;
               failure must be in the continuation-hash (hashOutputs) check

- timestamp: 2026-04-19T22:58:00Z
  checked: advanceState ANF body in deployed covenant.anf.json
  found: final assertion is hash256(continuation || data_output || change)
         === extractOutputHash(preimage); the script internally BUILDS the
         expected data_output bytes from scriptBytes := cat(opReturnHdr,
         lenBytes, BSVM\x02, batchData)
  implication: on-chain script expects exactly THREE outputs in order:
               covenant continuation, OP_RETURN(BSVM\x02+batchData), change

- timestamp: 2026-04-19T23:02:00Z
  checked: runar-go SDK tx-build path (sdk_contract.go PrepareCall,
           sdk_calling.go BuildCallTransaction, anf_interpreter.go)
  found: BuildCallTransaction emits only the contract continuation + change;
         ANF interpreter's add_data_output case is a no-op (line 327
         lists it alongside on-chain-only kinds); no helper walks the
         method body to surface AddDataOutput entries as tx outputs
  implication: the SDK never emits the OP_RETURN the covenant expects,
               so preimage.hashOutputs != script-computed hash → assert fails

- timestamp: 2026-04-19T23:05:00Z
  checked: git log for runar-go data-output support
  found: commit e7a3689 (2026-04-18) added addDataOutput intrinsic to the
         compiler and contract types but did NOT update the SDK tx builder;
         commit 2c610e1 (2026-04-19) refactored the BSVM rollup to use the
         new intrinsic — this is the first on-chain consumer
  implication: addDataOutput is a half-landed feature in runar-go; any
               FRI covenant compiled after 2c610e1 is dead-on-arrival
               against a real BSV node

- timestamp: 2026-04-19T23:13:00Z
  checked: live cluster post-fix
  found: test tx 0x5a9ae137... processed block 1, advance tx
         85b848d2ab31b3946b1dc119844b5e115eae6ae0f8d77c437173ff2538b12c12
         landed in BSV block 156 (2 vouts: covenant + change, 15088 bytes,
         0 "covenant broadcast failed" warnings in node1 logs)
  implication: removing AddDataOutput from the FRI contract fixes
               broadcast end-to-end

## Resolution

root_cause: The Mode 1 FRI rollup covenant calls StatefulSmartContract.AddDataOutput in its AdvanceState body to emit a spec-12 BSVM\x02 || batchData OP_RETURN. The Rúnar Go compiler correctly bakes an on-chain continuation-hash check that expects `hash256(covenant_continuation || op_return_data || change) == extractOutputHash(preimage)`. But the runar-go SDK's tx builder (BuildCallTransaction / anf_interpreter.go) does NOT walk `add_data_output` ANF bindings to inject the corresponding outputs into the built transaction — addDataOutput is a half-landed feature introduced in upstream runar commit e7a3689 that only wired the compiler side. So every broadcast attempt produced a tx with only (covenant, change) outputs while the script's hashOutputs check expected (covenant, OP_RETURN, change), and the pairing mismatch surfaced as "mandatory-script-verify-flag-failed".

fix: Remove the `c.AddDataOutput(...)` call and its OP_RETURN-script build from rollup_fri.runar.go's AdvanceState body. The covenant still binds the batch via `pvBatchDataHash == hash256(batchData)`, so the hash commitment is preserved; only the raw-bytes on-chain DA channel is deferred to the P2P gossip layer until the upstream SDK learns to emit add_data_output entries between the state continuation and the change output. Update TestFRIRollup_F07 and TestAdvance_SingleDataOutput to reflect the new (zero-data-output) invariant for Mode 1, with commentary describing the restoration path.

verification: Rebuilt bsvm:devnet image, tore down + restarted cluster, submitted the canonical Hardhat #0 nonce-0 test tx, confirmed block 1 processed, confirmed covenant advance tx 85b848d2... landed in BSV block 156 with the correct 2-output shape, confirmed no "covenant broadcast failed" warnings. `go test ./pkg/covenant/... ./pkg/overlay/... ./pkg/prover/...` green.

files_changed:
  - pkg/covenant/contracts/rollup_fri.runar.go: drop AddDataOutput call, document deferred DA
  - pkg/covenant/contracts/rollup_fri_f07_test.go: rewrite F07 to assert zero data outputs with file-header justification
  - pkg/covenant/advance_invariants_test.go: TestAdvance_SingleDataOutput — per-mode expected count (FRI=0, Groth16/WA=1)
