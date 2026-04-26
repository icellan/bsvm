# Copy to .env and edit as needed. The devnet reads these via
# docker compose --env-file or process env.

# Override the proving mode without editing docker-compose.yml.
# Values: mock | execute | prove
BSVM_PROVE_MODE={{PROVE_MODE}}

# L2 chain ID — must match the one baked into the genesis.
BSVM_CHAIN_ID={{CHAIN_ID}}
