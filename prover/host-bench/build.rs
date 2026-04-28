// Re-builds the production SP1 guest (../guest) so the bench harness
// measures cycle counts against the SAME ELF that host-bridge ships in
// production. Drift between the two would defeat the purpose of the
// bench — we'd measure something other than what mainnet runs.
fn main() {
    sp1_build::build_program("../guest");
}
