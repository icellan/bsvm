// Re-builds the production SP1 guest (../guest) so the bench harness
// measures cycle counts against the SAME ELF that host-bridge ships in
// production. Drift between the two would defeat the purpose of the
// bench — we'd measure something other than what mainnet runs.
//
// Docker mode pins the build to the SP1 reference image so the
// resulting ELF is bit-identical across operators (see
// docs/decisions/sp1-reproducible-build-2026-05.md).
fn main() {
    sp1_build::build_program_with_args(
        "../guest",
        sp1_build::BuildArgs {
            docker: true,
            tag: "v6.0.2".into(),
            locked: true,
            ..Default::default()
        },
    );
}
