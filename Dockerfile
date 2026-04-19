# Build stage — context must be the PARENT directory containing both
# bsv-evm/ and runar/ so that go.mod replace directives resolve.
#
# Build with: docker build -f bsv-evm/Dockerfile -t bsvm:test .
# from the parent directory, or use test/multinode/docker/build.sh.
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git gcc musl-dev

WORKDIR /src

# Copy runar dependencies (referenced via replace directives in go.mod).
COPY runar/compilers/go /runar/compilers/go
COPY runar/packages/runar-go /runar/packages/runar-go
COPY runar/integration/go /runar/integration/go

# Copy bsv-evm source.
COPY bsv-evm/ /src/

# Fix replace directives for Docker paths.
RUN sed -i 's|=> \.\./runar/compilers/go|=> /runar/compilers/go|' go.mod && \
    sed -i 's|=> \.\./runar/packages/runar-go|=> /runar/packages/runar-go|' go.mod && \
    sed -i 's|=> \.\./runar/integration/go|=> /runar/integration/go|' go.mod

RUN go mod download
RUN CGO_ENABLED=1 go build -o /src/bsvm ./cmd/bsvm

# Runtime stage
FROM alpine:3.21

RUN apk add --no-cache ca-certificates iproute2

COPY --from=builder /src/bsvm /usr/local/bin/bsvm

# Covenant source files needed by `bsvm init` for contract compilation.
# The binary's fallback path is pkg/covenant/contracts/ relative to CWD.
COPY --from=builder /src/pkg/covenant/contracts/ /app/pkg/covenant/contracts/

WORKDIR /app

EXPOSE 8545 9945

HEALTHCHECK --interval=5s --timeout=3s --start-period=10s --retries=5 \
    CMD wget -qO- --post-data='{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
        --header='Content-Type: application/json' http://localhost:8545 || exit 1

ENTRYPOINT ["bsvm"]
CMD ["run"]
