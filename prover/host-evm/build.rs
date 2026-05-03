// Reproducible-build mode for the dual-EVM equivalence guest. See
// docs/decisions/sp1-reproducible-build-2026-05.md.
//
// host-evm builds `../guest-evm`, not the production `../guest`, so
// there is no in-tree pinned ELF to fast-path against (Path C only
// applies to the production guest). Always docker-builds, with the
// SP1 image pinned by content digest (Phase 3).

use std::env;

const SP1_IMAGE_DIGEST: &str =
    "ghcr.io/succinctlabs/sp1@sha256:61bbcdb0cd096004303f25f042813f4b947571c454fb5247197a1bd9c91e01ad";

fn main() {
    env::set_var("SP1_DOCKER_IMAGE", SP1_IMAGE_DIGEST);
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
