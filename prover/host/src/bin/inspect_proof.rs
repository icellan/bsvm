//! Deserializes SP1 proofs and prints their internal structure.
//!
//! Usage:
//!   cargo run --bin inspect_proof -- <artifacts_dir>
//!
//! SP1 v6 uses KoalaBear field with StackedBasefold commitment scheme.
//! The internal proof structure is different from v4 (which used BabyBear + FRI).

use sp1_sdk::proof::{SP1Proof, SP1ProofWithPublicValues};
use sp1_sdk::HashableKey;
use std::fs;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let artifacts_dir = if args.len() > 1 {
        &args[1]
    } else {
        "artifacts"
    };

    // =========================================================================
    // Core proof inspection
    // =========================================================================
    let core_path = format!("{}/core_proof.bin", artifacts_dir);
    if let Ok(core_bytes) = fs::read(&core_path) {
        println!("================================================================");
        println!("  CORE PROOF INSPECTION");
        println!("================================================================");
        println!("File: {}", core_path);
        println!(
            "File size: {} bytes ({:.1} KB)",
            core_bytes.len(),
            core_bytes.len() as f64 / 1024.0
        );
        println!();

        match bincode::deserialize::<SP1ProofWithPublicValues>(&core_bytes) {
            Ok(proof_with_pv) => {
                println!("SP1 version: {}", proof_with_pv.sp1_version);
                println!(
                    "Public values: {} bytes (hex: {})",
                    proof_with_pv.public_values.as_slice().len(),
                    hex::encode(proof_with_pv.public_values.as_slice())
                );

                match &proof_with_pv.proof {
                    SP1Proof::Core(shard_proofs) => {
                        println!("Proof type: Core (KoalaBear + StackedBasefold)");
                        println!("Number of shard proofs: {}", shard_proofs.len());
                        println!();

                        for (i, shard) in shard_proofs.iter().enumerate() {
                            let shard_bytes = bincode::serialize(shard).unwrap_or_default();
                            println!("--- Shard {} ---", i);
                            println!(
                                "  Serialized size: {} bytes ({:.1} KB)",
                                shard_bytes.len(),
                                shard_bytes.len() as f64 / 1024.0
                            );

                            // Main commitment
                            println!("  Main commitment: {:?}", shard.main_commitment);

                            // Public values
                            println!("  Public values count: {}", shard.public_values.len());

                            // Opened values (now a BTreeMap<String, ChipOpenedValues>)
                            println!(
                                "  Opened values ({} chips):",
                                shard.opened_values.chips.len()
                            );
                            for (name, chip_ov) in &shard.opened_values.chips {
                                println!("    {} :", name);
                                println!(
                                    "        preprocessed: local={}",
                                    chip_ov.preprocessed.local.len()
                                );
                                println!(
                                    "        main:         local={}",
                                    chip_ov.main.local.len()
                                );
                                println!("        degree:       {:?}", chip_ov.degree);
                            }

                            // Size breakdown estimate
                            let opened_bytes =
                                bincode::serialize(&shard.opened_values).unwrap_or_default();
                            let eval_proof_bytes =
                                bincode::serialize(&shard.evaluation_proof).unwrap_or_default();
                            let pv_bytes =
                                bincode::serialize(&shard.public_values).unwrap_or_default();

                            println!("  Size breakdown:");
                            println!(
                                "    opened_values:    {} bytes ({:.1} KB)",
                                opened_bytes.len(),
                                opened_bytes.len() as f64 / 1024.0
                            );
                            println!(
                                "    evaluation_proof: {} bytes ({:.1} KB)",
                                eval_proof_bytes.len(),
                                eval_proof_bytes.len() as f64 / 1024.0
                            );
                            println!("    public_values:    {} bytes", pv_bytes.len());
                            println!();
                        }
                    }
                    other => println!("Unexpected proof type: {}", other),
                }
            }
            Err(e) => println!("Failed to deserialize core proof: {}", e),
        }
    } else {
        println!("Core proof not found at {}", core_path);
    }

    println!();
    println!();

    // =========================================================================
    // Compressed proof inspection
    // =========================================================================
    let comp_path = format!("{}/compressed_proof.bin", artifacts_dir);
    if let Ok(comp_bytes) = fs::read(&comp_path) {
        println!("================================================================");
        println!("  COMPRESSED PROOF INSPECTION");
        println!("================================================================");
        println!("File: {}", comp_path);
        println!(
            "File size: {} bytes ({:.1} KB)",
            comp_bytes.len(),
            comp_bytes.len() as f64 / 1024.0
        );
        println!();

        match bincode::deserialize::<SP1ProofWithPublicValues>(&comp_bytes) {
            Ok(proof_with_pv) => {
                println!("SP1 version: {}", proof_with_pv.sp1_version);
                println!(
                    "Public values: {} bytes (hex: {})",
                    proof_with_pv.public_values.as_slice().len(),
                    hex::encode(proof_with_pv.public_values.as_slice())
                );

                match &proof_with_pv.proof {
                    SP1Proof::Compressed(recursion_proof) => {
                        println!("Proof type: Compressed (SP1RecursionProof, KoalaBear + StackedBasefold)");
                        println!();

                        // Verifying key for recursion circuit
                        let vk = &recursion_proof.vk;
                        println!("Recursion VK:");
                        println!("  preprocessed_commit: {:?}", vk.preprocessed_commit);
                        println!("  pc_start: {:?}", vk.pc_start);

                        // The single shard proof
                        let shard = &recursion_proof.proof;
                        println!();
                        println!("--- Compressed Shard Proof ---");

                        let shard_bytes = bincode::serialize(shard).unwrap_or_default();
                        println!(
                            "  Serialized size: {} bytes ({:.1} KB)",
                            shard_bytes.len(),
                            shard_bytes.len() as f64 / 1024.0
                        );

                        // Main commitment
                        println!("  Main commitment: {:?}", shard.main_commitment);

                        // Public values
                        println!("  Public values count: {}", shard.public_values.len());

                        // Opened values (BTreeMap<String, ChipOpenedValues>)
                        println!(
                            "  Opened values ({} chips):",
                            shard.opened_values.chips.len()
                        );
                        for (name, chip_ov) in &shard.opened_values.chips {
                            println!("    {} :", name);
                            println!(
                                "        preprocessed: local={}",
                                chip_ov.preprocessed.local.len()
                            );
                            println!("        main:         local={}", chip_ov.main.local.len());
                            println!("        degree:       {:?}", chip_ov.degree);
                        }

                        // Size breakdown
                        let vk_bytes = bincode::serialize(vk).unwrap_or_default();
                        let opened_bytes =
                            bincode::serialize(&shard.opened_values).unwrap_or_default();
                        let eval_proof_bytes =
                            bincode::serialize(&shard.evaluation_proof).unwrap_or_default();
                        let pv_bytes = bincode::serialize(&shard.public_values).unwrap_or_default();

                        println!();
                        println!("--- Size Breakdown ---");
                        println!("  Recursion VK:       {} bytes", vk_bytes.len());
                        println!(
                            "  Shard proof:        {} bytes ({:.1} KB)",
                            shard_bytes.len(),
                            shard_bytes.len() as f64 / 1024.0
                        );
                        println!(
                            "    opened_values:    {} bytes ({:.1} KB)",
                            opened_bytes.len(),
                            opened_bytes.len() as f64 / 1024.0
                        );
                        println!(
                            "    evaluation_proof: {} bytes ({:.1} KB)",
                            eval_proof_bytes.len(),
                            eval_proof_bytes.len() as f64 / 1024.0
                        );
                        println!("    public_values:    {} bytes", pv_bytes.len());
                    }
                    other => println!("Unexpected proof type: {}", other),
                }
            }
            Err(e) => println!("Failed to deserialize compressed proof: {}", e),
        }
    } else {
        println!("Compressed proof not found at {}", comp_path);
    }

    // =========================================================================
    // VK inspection
    // =========================================================================
    let vk_path = format!("{}/vk.bin", artifacts_dir);
    if let Ok(vk_bytes) = fs::read(&vk_path) {
        println!();
        println!();
        println!("================================================================");
        println!("  VERIFYING KEY INSPECTION");
        println!("================================================================");
        println!("File: {}", vk_path);
        println!("File size: {} bytes", vk_bytes.len());

        match bincode::deserialize::<sp1_sdk::SP1VerifyingKey>(&vk_bytes) {
            Ok(vk) => {
                println!("VK hash (bytes32): {}", vk.bytes32());
                println!("VK preprocessed_commit: {:?}", vk.vk.preprocessed_commit);
                println!("VK pc_start: {:?}", vk.vk.pc_start);
            }
            Err(e) => println!("Failed to deserialize VK: {}", e),
        }
    }

    println!();
    println!("================================================================");
    println!("  SP1 v6 PROOF SYSTEM INFO");
    println!("================================================================");
    println!("SP1 v6 uses KoalaBear field with StackedBasefold commitment scheme.");
    println!("This is a major change from v4 which used BabyBear + FRI (Poseidon2).");
    println!();
    println!("Key differences from v4:");
    println!("  - Field: KoalaBear (not BabyBear)");
    println!("  - Commitment: StackedBasefold (not FRI/Poseidon2)");
    println!("  - Proof uses LogupGKR + ZeroCheck instead of FRI queries");
    println!("  - ShardProof fields: main_commitment, opened_values, evaluation_proof");
    println!("  - Chips indexed by BTreeMap<String, ...> instead of HashMap+ordering");
}
