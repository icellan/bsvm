// Reproducible-build mode: compile the SP1 guest inside the SP1 docker
// image so the resulting ELF (and therefore the verifying key) is
// bit-identical across operators. See
// docs/decisions/sp1-reproducible-build-2026-05.md for the rationale
// and measured A/B verdict. Set SP1_SKIP_PROGRAM_BUILD=true to bypass
// the build entirely (handy for fast cargo-check loops without docker
// installed).
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
