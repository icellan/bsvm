//! BSVM Host — EVM Transfer Proof Generator (Gate 0b Step 4)
//!
//! Generates and verifies an SP1 proof for a single balance transfer,
//! measures all relevant metrics, and saves artifacts.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sp1_sdk::{include_elf, Elf, HashableKey, Prover, ProveRequest, ProvingKey, ProverClient, SP1Proof, SP1Stdin};
use std::fs;
use std::time::Instant;

/// The ELF binary of the EVM guest program, built by sp1_build in build.rs.
const GUEST_ELF: Elf = include_elf!("bsvm-guest-evm");

// --- Types (must match the guest exactly) ---

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Account {
    address: [u8; 20],
    nonce: u64,
    balance: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Transfer {
    from: [u8; 20],
    to: [u8; 20],
    value: u64,
    nonce: u64,
    gas_limit: u64,
    gas_price: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct BatchInput {
    accounts: Vec<Account>,
    transfer: Transfer,
    chain_id: u64,
}

#[tokio::main]
async fn main() {
    // -- 1. Set up test scenario ---
    // Sender: 1 ETH (1e18 wei, but we use u64 so 1_000_000_000 as a stand-in)
    // Recipient: 0 balance
    // Transfer: 500_000_000 (0.5 ETH equivalent)
    // Gas: 21000 * 1 = 21000

    let sender_addr: [u8; 20] = [
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
    ];
    let recipient_addr: [u8; 20] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
        0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55,
    ];

    let accounts = vec![
        Account {
            address: sender_addr,
            nonce: 0,
            balance: 1_000_000_000, // 1 "ETH" in simplified units
        },
        Account {
            address: recipient_addr,
            nonce: 0,
            balance: 0,
        },
    ];

    let transfer = Transfer {
        from: sender_addr,
        to: recipient_addr,
        value: 500_000_000, // 0.5 "ETH"
        nonce: 0,
        gas_limit: 21000,
        gas_price: 1,
    };

    let chain_id: u64 = 0xB5ED; // BSVM-like hex chain ID for testing

    let input = BatchInput {
        accounts: accounts.clone(),
        transfer: transfer.clone(),
        chain_id,
    };

    // -- 2. Compute expected values on the host side ---
    let expected_pre_root = compute_state_root(&accounts);
    let mut post_accounts = accounts.clone();
    let gas_cost = transfer.gas_limit * transfer.gas_price;
    post_accounts[0].balance -= transfer.value + gas_cost;
    post_accounts[0].nonce += 1;
    post_accounts[1].balance += transfer.value;
    let expected_post_root = compute_state_root(&post_accounts);
    let expected_gas_used: u64 = 21000;
    let expected_batch_hash = sha256_bytes(&encode_transfer(&transfer));

    println!("BSVM Gate 0b Step 4: EVM Transfer Proof");
    println!("=======================================");
    println!("Sender:    0x{}", hex::encode(sender_addr));
    println!("Recipient: 0x{}", hex::encode(recipient_addr));
    println!("Value:     {}", transfer.value);
    println!("Gas:       {} * {} = {}", transfer.gas_limit, transfer.gas_price, gas_cost);
    println!("Chain ID:  {}", chain_id);
    println!();
    println!("Expected pre-state root:  {}", hex::encode(expected_pre_root));
    println!("Expected post-state root: {}", hex::encode(expected_post_root));
    println!("Expected gas used:        {}", expected_gas_used);
    println!("Expected batch data hash: {}", hex::encode(expected_batch_hash));

    // -- 3. Prepare SP1 stdin ---
    let client = ProverClient::builder().cpu().build().await;
    let mut stdin = SP1Stdin::new();
    stdin.write(&input);

    // -- 4. Execute (no proof) — get cycle count and verify correctness --
    println!("\n--- Execution (no proof) ---");
    let exec_start = Instant::now();
    let (public_values, report) = client
        .execute(GUEST_ELF.clone(), stdin.clone())
        .await
        .expect("execution failed");
    let exec_duration = exec_start.elapsed();

    let pv = public_values.as_slice();
    println!("Execution completed in {:?}", exec_duration);
    println!("Total RISC-V cycles: {}", report.total_instruction_count());
    println!("Public values size:  {} bytes", pv.len());

    // Verify public values layout
    assert_eq!(pv.len(), 112, "public values must be exactly 112 bytes");
    verify_public_values(
        pv,
        &expected_pre_root,
        &expected_post_root,
        expected_gas_used,
        &expected_batch_hash,
        chain_id,
    );
    println!("Public values layout verified (112 bytes, spec 12 format)");

    // -- 5. Set up keys ---
    let pk = client.setup(GUEST_ELF.clone()).await.expect("setup failed");
    let vk = pk.verifying_key().clone();

    let artifacts_dir = "artifacts";
    fs::create_dir_all(artifacts_dir).expect("failed to create artifacts directory");

    // -- 6. Core proof ---
    println!("\n--- CORE Proof ---");
    println!("Generating CORE proof...");
    let core_start = Instant::now();
    let core_proof = client
        .prove(&pk, stdin.clone())
        .await
        .expect("core proof generation failed");
    let core_duration = core_start.elapsed();
    println!("CORE proof generated in {:?}", core_duration);

    println!("Verifying CORE proof...");
    let core_verify_start = Instant::now();
    client
        .verify(&core_proof, &vk, None)
        .expect("core proof verification failed");
    let core_verify_duration = core_verify_start.elapsed();
    println!("CORE proof verified in {:?}", core_verify_duration);

    let core_bytes = bincode::serialize(&core_proof).expect("serialize core proof");
    fs::write(format!("{}/core_proof.bin", artifacts_dir), &core_bytes)
        .expect("write core proof");
    println!(
        "CORE proof size: {} bytes ({:.1} KB)",
        core_bytes.len(),
        core_bytes.len() as f64 / 1024.0
    );

    // Count shards in core proof
    let num_shards = match &core_proof.proof {
        SP1Proof::Core(shard_proofs) => shard_proofs.len(),
        _ => 0, // should not happen for core proof
    };
    println!("Number of shards (core): {}", num_shards);

    // -- 7. Compressed proof ---
    println!("\n--- COMPRESSED Proof ---");
    println!("Generating COMPRESSED proof...");
    let comp_start = Instant::now();
    let comp_proof = client
        .prove(&pk, stdin.clone())
        .compressed()
        .await
        .expect("compressed proof generation failed");
    let comp_duration = comp_start.elapsed();
    println!("COMPRESSED proof generated in {:?}", comp_duration);

    println!("Verifying COMPRESSED proof...");
    let comp_verify_start = Instant::now();
    client
        .verify(&comp_proof, &vk, None)
        .expect("compressed proof verification failed");
    let comp_verify_duration = comp_verify_start.elapsed();
    println!("COMPRESSED proof verified in {:?}", comp_verify_duration);

    let comp_bytes = bincode::serialize(&comp_proof).expect("serialize compressed proof");
    fs::write(format!("{}/compressed_proof.bin", artifacts_dir), &comp_bytes)
        .expect("write compressed proof");
    println!(
        "COMPRESSED proof size: {} bytes ({:.1} KB)",
        comp_bytes.len(),
        comp_bytes.len() as f64 / 1024.0
    );

    // -- 8. Save artifacts ---
    let vk_bytes = bincode::serialize(&vk).expect("serialize vk");
    fs::write(format!("{}/vk.bin", artifacts_dir), &vk_bytes).expect("write vk");

    let vk_hash = vk.bytes32();
    fs::write(format!("{}/vk_hash.hex", artifacts_dir), &vk_hash).expect("write vk hash");

    let pv_bytes = comp_proof.public_values.as_slice();
    fs::write(format!("{}/public_values.bin", artifacts_dir), pv_bytes)
        .expect("write public values");

    fs::write(format!("{}/guest_evm.elf", artifacts_dir), &*GUEST_ELF)
        .expect("write guest ELF");

    // Save public values as hex for inspection
    fs::write(
        format!("{}/public_values.hex", artifacts_dir),
        hex::encode(pv_bytes),
    )
    .expect("write public values hex");

    // -- 9. Summary ---
    let cycle_count = report.total_instruction_count();
    let elf_size = GUEST_ELF.len();

    println!("\n================================================================");
    println!("  Gate 0b Step 4: EVM Transfer Proof — Summary");
    println!("================================================================");
    println!("Guest program:          Simplified balance transfer");
    println!("SP1 version:            {}", core_proof.sp1_version);
    println!("Chain ID:               {}", chain_id);
    println!();
    println!("  Execution:");
    println!("    Time:               {:?}", exec_duration);
    println!("    RISC-V cycles:      {}", cycle_count);
    println!("    Guest ELF size:     {} bytes ({:.1} KB)", elf_size, elf_size as f64 / 1024.0);
    println!();
    println!("  CORE proof:");
    println!("    Proving time:       {:?}", core_duration);
    println!("    Verification time:  {:?}", core_verify_duration);
    println!("    Proof size:         {} bytes ({:.1} KB)", core_bytes.len(), core_bytes.len() as f64 / 1024.0);
    println!("    Shards:             {}", num_shards);
    println!();
    println!("  COMPRESSED proof:");
    println!("    Proving time:       {:?}", comp_duration);
    println!("    Verification time:  {:?}", comp_verify_duration);
    println!("    Proof size:         {} bytes ({:.1} KB)", comp_bytes.len(), comp_bytes.len() as f64 / 1024.0);
    println!();
    println!("  Artifacts:");
    println!("    VK size:            {} bytes", vk_bytes.len());
    println!("    VK hash:            {}", vk_hash);
    println!("    Public values:      {} bytes", pv_bytes.len());
    println!();
    println!("  Public values (hex):");
    println!("    preStateRoot:       {}", hex::encode(&pv_bytes[0..32]));
    println!("    postStateRoot:      {}", hex::encode(&pv_bytes[32..64]));
    println!("    gasUsed:            {}", hex::encode(&pv_bytes[64..72]));
    println!("    batchDataHash:      {}", hex::encode(&pv_bytes[72..104]));
    println!("    chainId:            {}", hex::encode(&pv_bytes[104..112]));
    println!("================================================================");

    // -- 10. Gate 0b threshold evaluation ---
    let comp_kb = comp_bytes.len() as f64 / 1024.0;
    println!("\nGate 0b proof size evaluation (compressed proof):");
    if comp_kb < 200.0 {
        println!("  ACCEPTABLE: {:.1} KB < 200 KB threshold", comp_kb);
    } else if comp_kb < 500.0 {
        println!("  MARGINAL: {:.1} KB (200-500 KB range)", comp_kb);
    } else {
        println!("  UNACCEPTABLE: {:.1} KB > 500 KB threshold", comp_kb);
    }

    // -- 11. Write metrics report ---
    let report_content = format!(
        r#"# SP1 EVM Transfer Proof Metrics — Gate 0b Step 4

Generated: (run timestamp in program output)

## Test Scenario

- **Guest program**: Simplified balance transfer (not full revm)
- **SP1 version**: {}
- **Chain ID**: {}
- **Sender**: `0x{}`
- **Recipient**: `0x{}`
- **Transfer value**: {} (simplified units)
- **Gas**: {} * {} = {}

## Execution Metrics

| Metric | Value |
|--------|-------|
| RISC-V cycle count | {} |
| Execution time (no proof) | {:?} |
| Guest ELF size | {} bytes ({:.1} KB) |

## Proof Metrics

### Core Proof

| Metric | Value |
|--------|-------|
| Proving time | {:?} |
| Verification time | {:?} |
| Proof size | {} bytes ({:.1} KB) |
| Shards | {} |

### Compressed Proof

| Metric | Value |
|--------|-------|
| Proving time | {:?} |
| Verification time | {:?} |
| Proof size | {} bytes ({:.1} KB) |

## Public Values (112 bytes)

| Offset | Size | Field | Value |
|--------|------|-------|-------|
| 0 | 32 | preStateRoot | `{}` |
| 32 | 32 | postStateRoot | `{}` |
| 64 | 8 | gasUsed | `{}` (= {}) |
| 72 | 32 | batchDataHash | `{}` |
| 104 | 8 | chainId | `{}` (= {}) |

## Artifacts

| File | Size |
|------|------|
| `core_proof.bin` | {} bytes ({:.1} KB) |
| `compressed_proof.bin` | {} bytes ({:.1} KB) |
| `vk.bin` | {} bytes |
| `guest_evm.elf` | {} bytes ({:.1} KB) |
| `public_values.bin` | {} bytes |

## Gate 0b Evaluation

| Metric | Value | Threshold | Status |
|--------|-------|-----------|--------|
| Compressed proof size | {:.1} KB | < 200 KB acceptable, < 500 KB marginal | {} |

## VK Hash

```
{}
```
"#,
        core_proof.sp1_version,
        chain_id,
        hex::encode(sender_addr),
        hex::encode(recipient_addr),
        transfer.value,
        transfer.gas_limit,
        transfer.gas_price,
        transfer.gas_limit * transfer.gas_price,
        cycle_count,
        exec_duration,
        elf_size,
        elf_size as f64 / 1024.0,
        // Core proof
        core_duration,
        core_verify_duration,
        core_bytes.len(),
        core_bytes.len() as f64 / 1024.0,
        num_shards,
        // Compressed proof
        comp_duration,
        comp_verify_duration,
        comp_bytes.len(),
        comp_bytes.len() as f64 / 1024.0,
        // Public values
        hex::encode(&pv_bytes[0..32]),
        hex::encode(&pv_bytes[32..64]),
        hex::encode(&pv_bytes[64..72]),
        u64::from_be_bytes(pv_bytes[64..72].try_into().unwrap()),
        hex::encode(&pv_bytes[72..104]),
        hex::encode(&pv_bytes[104..112]),
        u64::from_be_bytes(pv_bytes[104..112].try_into().unwrap()),
        // Artifacts
        core_bytes.len(),
        core_bytes.len() as f64 / 1024.0,
        comp_bytes.len(),
        comp_bytes.len() as f64 / 1024.0,
        vk_bytes.len(),
        elf_size,
        elf_size as f64 / 1024.0,
        pv_bytes.len(),
        // Gate evaluation
        comp_kb,
        if comp_kb < 200.0 {
            "ACCEPTABLE"
        } else if comp_kb < 500.0 {
            "MARGINAL"
        } else {
            "UNACCEPTABLE"
        },
        vk_hash,
    );

    // Write to docs/
    let docs_dir = "../../docs";
    fs::create_dir_all(docs_dir).expect("failed to create docs directory");
    fs::write(
        format!("{}/sp1-evm-proof-metrics.md", docs_dir),
        &report_content,
    )
    .expect("failed to write metrics report");
    println!("\nMetrics report saved to docs/sp1-evm-proof-metrics.md");

    println!("\nAll artifacts saved to {}/", artifacts_dir);
}

// --- Helper functions (mirror the guest logic exactly) ---

fn compute_state_root(accounts: &[Account]) -> [u8; 32] {
    let mut sorted = accounts.to_vec();
    sorted.sort_by_key(|a| a.address);

    let mut data = Vec::new();
    for acct in &sorted {
        data.extend_from_slice(&acct.address);
        data.extend_from_slice(&acct.nonce.to_be_bytes());
        data.extend_from_slice(&acct.balance.to_be_bytes());
    }
    sha256_bytes(&data)
}

fn encode_transfer(tx: &Transfer) -> Vec<u8> {
    let mut data = Vec::with_capacity(20 + 20 + 8 + 8 + 8 + 8);
    data.extend_from_slice(&tx.from);
    data.extend_from_slice(&tx.to);
    data.extend_from_slice(&tx.value.to_be_bytes());
    data.extend_from_slice(&tx.nonce.to_be_bytes());
    data.extend_from_slice(&tx.gas_limit.to_be_bytes());
    data.extend_from_slice(&tx.gas_price.to_be_bytes());
    data
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn verify_public_values(
    pv: &[u8],
    expected_pre_root: &[u8; 32],
    expected_post_root: &[u8; 32],
    expected_gas_used: u64,
    expected_batch_hash: &[u8; 32],
    expected_chain_id: u64,
) {
    // [0..32] preStateRoot
    assert_eq!(
        &pv[0..32],
        expected_pre_root,
        "preStateRoot mismatch"
    );
    // [32..64] postStateRoot
    assert_eq!(
        &pv[32..64],
        expected_post_root,
        "postStateRoot mismatch"
    );
    // [64..72] gasUsed (big-endian u64)
    let gas_used = u64::from_be_bytes(pv[64..72].try_into().unwrap());
    assert_eq!(gas_used, expected_gas_used, "gasUsed mismatch");
    // [72..104] batchDataHash
    assert_eq!(
        &pv[72..104],
        expected_batch_hash,
        "batchDataHash mismatch"
    );
    // [104..112] chainId (big-endian u64)
    let chain_id = u64::from_be_bytes(pv[104..112].try_into().unwrap());
    assert_eq!(chain_id, expected_chain_id, "chainId mismatch");
}
