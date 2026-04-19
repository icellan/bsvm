module bsvm-multinode-tests

go 1.26

replace (
	github.com/icellan/bsvm => ../..
	github.com/icellan/runar/compilers/go => ../../../runar/compilers/go
	github.com/icellan/runar/packages/runar-go => ../../../runar/packages/runar-go
	runar-integration => ../../../runar/integration/go
)

require (
	github.com/holiman/uint256 v1.3.2
	github.com/icellan/bsvm v0.0.0
)

require (
	github.com/bits-and-blooms/bitset v1.14.2 // indirect
	github.com/consensys/bavard v0.1.13 // indirect
	github.com/consensys/gnark-crypto v0.14.0 // indirect
	github.com/crate-crypto/go-kzg-4844 v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)
