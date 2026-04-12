module github.com/icellan/bsvm

go 1.26

require github.com/icellan/runar/packages/runar-go v0.0.0

require (
	github.com/bsv-blockchain/go-sdk v1.2.21 // indirect
	github.com/icellan/runar/compilers/go v0.0.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/smacker/go-tree-sitter v0.0.0-20240827094217-dd81d9e9be82 // indirect
	golang.org/x/crypto v0.48.0 // indirect
)

replace (
	github.com/icellan/runar/compilers/go => ../runar/compilers/go
	github.com/icellan/runar/packages/runar-go => ../runar/packages/runar-go
)
