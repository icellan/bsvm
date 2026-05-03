// Reproducible-build mode for the dual-EVM equivalence guest. See
// docs/decisions/sp1-reproducible-build-2026-05.md.
fn main() {
    sp1_build::build_program_with_args(
        "../guest-evm",
        sp1_build::BuildArgs {
            docker: true,
            tag: "v6.0.2".into(),
            locked: true,
            ..Default::default()
        },
    );
}
