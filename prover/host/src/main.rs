use sp1_sdk::{include_elf, Elf, HashableKey, Prover, ProveRequest, ProvingKey, ProverClient, SP1Stdin};
use std::fs;
use std::time::Instant;

/// The ELF binary of the guest program, included at compile time by sp1_build.
const GUEST_ELF: Elf = include_elf!("bsvm-guest-minimal");

#[tokio::main]
async fn main() {
    // Set up the SP1 prover client (CPU-based local proving).
    let client = ProverClient::builder().cpu().build().await;

    // Prepare inputs: a = 10, b = 20, expected sum = 30.
    let mut stdin = SP1Stdin::new();
    stdin.write(&10u32);
    stdin.write(&20u32);

    // Execute first (fast, no proof) to verify correctness and get cycle count.
    println!("Executing guest program (no proof)...");
    let exec_start = Instant::now();
    let (public_values, report) = client
        .execute(GUEST_ELF.clone(), stdin.clone())
        .await
        .expect("execution failed");
    let exec_duration = exec_start.elapsed();
    println!("Execution completed in {:?}", exec_duration);
    println!("Total cycles: {}", report.total_instruction_count());

    // Verify the public output.
    let sum: u32 = public_values.as_slice()[..4]
        .try_into()
        .map(u32::from_le_bytes)
        .expect("failed to read sum from public values");
    assert_eq!(sum, 30, "expected 10 + 20 = 30, got {}", sum);
    println!("Execution result verified: 10 + 20 = {}", sum);

    // Set up proving and verifying keys.
    let pk = client.setup(GUEST_ELF.clone()).await.expect("setup failed");
    let vk = pk.verifying_key().clone();

    let artifacts_dir = "artifacts";
    fs::create_dir_all(artifacts_dir).expect("failed to create artifacts directory");

    // =========================================================================
    // CORE proof (real STARK proof, scales linearly with cycles)
    // =========================================================================
    println!("\n--- CORE Proof ---");
    println!("Generating CORE proof...");
    let core_prove_start = Instant::now();
    let core_proof = client
        .prove(&pk, stdin.clone())
        .await
        .expect("core proof generation failed");
    let core_prove_duration = core_prove_start.elapsed();
    println!("CORE proof generated in {:?}", core_prove_duration);

    println!("Verifying CORE proof locally...");
    let core_verify_start = Instant::now();
    client
        .verify(&core_proof, &vk, None)
        .expect("core verification failed");
    let core_verify_duration = core_verify_start.elapsed();
    println!("CORE proof verified in {:?}", core_verify_duration);

    let core_proof_bytes =
        bincode::serialize(&core_proof).expect("failed to serialize core proof");
    fs::write(
        format!("{}/core_proof.bin", artifacts_dir),
        &core_proof_bytes,
    )
    .expect("failed to write core proof");
    println!(
        "CORE proof size: {} bytes ({:.1} KB)",
        core_proof_bytes.len(),
        core_proof_bytes.len() as f64 / 1024.0
    );

    // =========================================================================
    // COMPRESSED proof (constant size, recursive STARK compression)
    // =========================================================================
    println!("\n--- Compressed Proof ---");
    println!("Generating COMPRESSED proof...");
    let comp_prove_start = Instant::now();
    let comp_proof = client
        .prove(&pk, stdin.clone())
        .compressed()
        .await
        .expect("compressed proof generation failed");
    let comp_prove_duration = comp_prove_start.elapsed();
    println!("COMPRESSED proof generated in {:?}", comp_prove_duration);

    println!("Verifying COMPRESSED proof locally...");
    let comp_verify_start = Instant::now();
    client
        .verify(&comp_proof, &vk, None)
        .expect("compressed verification failed");
    let comp_verify_duration = comp_verify_start.elapsed();
    println!("COMPRESSED proof verified in {:?}", comp_verify_duration);

    let comp_proof_bytes =
        bincode::serialize(&comp_proof).expect("failed to serialize compressed proof");
    fs::write(
        format!("{}/compressed_proof.bin", artifacts_dir),
        &comp_proof_bytes,
    )
    .expect("failed to write compressed proof");
    println!(
        "COMPRESSED proof size: {} bytes ({:.1} KB)",
        comp_proof_bytes.len(),
        comp_proof_bytes.len() as f64 / 1024.0
    );

    // =========================================================================
    // Save common artifacts
    // =========================================================================

    // Save verifying key.
    let vk_bytes = bincode::serialize(&vk).expect("failed to serialize vk");
    fs::write(format!("{}/vk.bin", artifacts_dir), &vk_bytes).expect("failed to write vk");

    // Save VK hash.
    let vk_hash = vk.bytes32();
    fs::write(format!("{}/vk_hash.hex", artifacts_dir), &vk_hash)
        .expect("failed to write vk hash");

    // Save public values (same for both proof modes).
    let pv = comp_proof.public_values.as_slice();
    fs::write(format!("{}/public_values.bin", artifacts_dir), pv)
        .expect("failed to write public values");

    // Save the guest ELF.
    fs::write(format!("{}/guest.elf", artifacts_dir), &*GUEST_ELF).expect("failed to write ELF");

    // =========================================================================
    // Summary
    // =========================================================================
    println!("\n================================================================");
    println!("  Gate 0b Step 1: SP1 Proof Generation Summary");
    println!("================================================================");
    println!("Guest program:          a + b = sum (10 + 20 = 30)");
    println!("SP1 version:            {}", core_proof.sp1_version);
    println!("Execution time:         {:?}", exec_duration);
    println!("Total RISC-V cycles:    {}", report.total_instruction_count());
    println!("Guest ELF size:         {} bytes", GUEST_ELF.len());
    println!("VK size:                {} bytes", vk_bytes.len());
    println!("VK hash:                {}", vk_hash);
    println!("Public values:          {} bytes (hex: {})", pv.len(), hex::encode(pv));
    println!();
    println!("  CORE proof:");
    println!("    Proving time:       {:?}", core_prove_duration);
    println!("    Verification time:  {:?}", core_verify_duration);
    println!(
        "    Proof size:         {} bytes ({:.1} KB)",
        core_proof_bytes.len(),
        core_proof_bytes.len() as f64 / 1024.0
    );
    println!();
    println!("  COMPRESSED proof:");
    println!("    Proving time:       {:?}", comp_prove_duration);
    println!("    Verification time:  {:?}", comp_verify_duration);
    println!(
        "    Proof size:         {} bytes ({:.1} KB)",
        comp_proof_bytes.len(),
        comp_proof_bytes.len() as f64 / 1024.0
    );
    println!("================================================================");

    // Gate 0b threshold evaluation (using compressed proof, which is what
    // we will use for BSV on-chain verification).
    let relevant_size_kb = comp_proof_bytes.len() as f64 / 1024.0;
    println!("\nGate 0b proof size evaluation (compressed proof):");
    if relevant_size_kb < 200.0 {
        println!(
            "  ACCEPTABLE: {:.1} KB < 200 KB threshold",
            relevant_size_kb
        );
    } else if relevant_size_kb < 500.0 {
        println!(
            "  MARGINAL: {:.1} KB (200-500 KB range)",
            relevant_size_kb
        );
    } else {
        println!(
            "  UNACCEPTABLE: {:.1} KB > 500 KB threshold",
            relevant_size_kb
        );
    }

    println!("\nAll artifacts saved to {}/", artifacts_dir);
}
