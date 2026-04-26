{
  "data_dir": "/data/bsvm",
  "genesis": "genesis.json",
  "overlay": {
    "coinbase": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    "block_gas_limit": 30000000,
    "max_batch_size": 16,
    "max_batch_flush_delay": "1s",
    "min_gas_price": "1000000000",
    "max_speculative_depth": 16
  },
  "rpc": {
    "http_addr": ":8545",
    "ws_addr": ":8546",
    "cors_origins": ["*"],
    "get_logs_max_range": 1000
  },
  "prover": {
    "mode": "{{PROVE_MODE}}",
    "workers": 1
  },
  "network": {
    "listen_addr": "/ip4/0.0.0.0/tcp/9945",
    "bootstrap_peers": [],
    "max_peers": 50
  },
  "bridge": {
    "min_deposit_satoshis": 10000,
    "min_withdrawal_satoshis": 10000,
    "bsv_confirmations": 1
  },
  "log": {
    "level": "info",
    "format": "text"
  }
}
