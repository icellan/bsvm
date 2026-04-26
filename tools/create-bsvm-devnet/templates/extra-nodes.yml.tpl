  node2:
    <<: *bsvm-common
    environment:
      <<: *bsvm-env
      BSVM_NODE_NAME: node2
      BSVM_RPC_PORT: "8545"
      BSVM_P2P_PORT: "9945"
      BSVM_ROLE: prover
      BSVM_COINBASE: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
      BSVM_PEERS: "node1:9945,node3:9945"
    ports:
      - "8546:8545"
      - "9946:9945"
    volumes:
      - shared-genesis:/shared/genesis:ro
      - node2-data:/data/bsvm
    depends_on:
      bsvm-init:
        condition: service_completed_successfully

  node3:
    <<: *bsvm-common
    environment:
      <<: *bsvm-env
      BSVM_NODE_NAME: node3
      BSVM_RPC_PORT: "8545"
      BSVM_P2P_PORT: "9945"
      BSVM_ROLE: follower
      BSVM_PEERS: "node1:9945,node2:9945"
    ports:
      - "8547:8545"
      - "9947:9945"
    volumes:
      - shared-genesis:/shared/genesis:ro
      - node3-data:/data/bsvm
    depends_on:
      bsvm-init:
        condition: service_completed_successfully
