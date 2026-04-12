module bsvm-integration

go 1.26

replace (
	github.com/icellan/runar/compilers/go => ../../../runar/compilers/go
	github.com/icellan/runar/packages/runar-go => ../../../runar/packages/runar-go
	runar-integration => ../../../runar/integration/go
)

require (
	github.com/icellan/runar/compilers/go v0.0.0
	github.com/icellan/runar/packages/runar-go v0.3.2
	runar-integration v0.0.0-00010101000000-000000000000
)

require (
	github.com/bsv-blockchain/go-sdk v1.2.21 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/smacker/go-tree-sitter v0.0.0-20240827094217-dd81d9e9be82 // indirect
	golang.org/x/crypto v0.48.0 // indirect
)
