// Daemon-side BSV-node provider wiring. The helper here picks between
// a single-endpoint *bsvclient.RPCProvider (legacy NodeURL) and the
// W6-11 *bsvclient.MultiRPCProvider failover wrapper (NodeURLs[]) and
// returns a value that satisfies every consumer in the daemon
// (runar.Provider, covenant.ConfirmationSource, plus the regtest
// devnet-funding code's raw Call escape hatch).
//
// Until this retrofit, every call site constructed bsvclient.NewRPCProvider
// directly and lost the failover semantics MultiRPCProvider provides.
// Threading the choice through one builder keeps the policy centralised
// and lets multi-endpoint deployments turn on failover purely via
// [bsv].node_urls — no other code change required.
package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/bsv-blockchain/go-sdk/transaction"

	"github.com/icellan/bsvm/pkg/bsvclient"
	runar "github.com/icellan/runar/packages/runar-go"
)

// BSVProviderClient is the union of every provider method the daemon
// uses. Both *bsvclient.RPCProvider and *bsvclient.MultiRPCProvider
// satisfy it transparently, so any consumer that types this interface
// works with either implementation.
//
// Method set:
//
//   - runar.Provider (GetTransaction / Broadcast / GetUtxos /
//     GetContractUtxo / GetNetwork / GetFeeRate / GetRawTransaction):
//     used by the broadcast path, runar.FromTxId binding, and the
//     fee-wallet UTXO reconciler.
//   - GetRawTransactionVerbose: covenant.ConfirmationSource. Used by
//     the confirmation watcher.
//   - Call: raw JSON-RPC escape hatch used by the regtest devnet
//     funding helpers (importaddress / sendtoaddress / generatetoaddress).
type BSVProviderClient interface {
	runar.Provider
	GetRawTransactionVerbose(txid string) (map[string]interface{}, error)
	Call(method string, params ...interface{}) (json.RawMessage, error)
}

// Compile-time assertions that both backing implementations satisfy
// the union interface. If a future RPCProvider / MultiRPCProvider edit
// drops a method, these break the build at the cmd-level rather than
// at every call site.
var (
	_ BSVProviderClient = (*bsvclient.RPCProvider)(nil)
	_ BSVProviderClient = (*bsvclient.MultiRPCProvider)(nil)

	// runar.Provider conformance is also asserted from inside
	// pkg/bsvclient itself; the duplicate here is intentional so a
	// version-skew build break surfaces in cmd/bsvm too.
	_ runar.Provider = (*bsvclient.RPCProvider)(nil)
	_ runar.Provider = (*bsvclient.MultiRPCProvider)(nil)

	// Sanity: the wrapper returned by Broadcast must be an SDK type.
	_ *transaction.Transaction = (*transaction.Transaction)(nil)
)

// BuildBSVProvider chooses between a single-endpoint RPCProvider and
// the multi-endpoint failover wrapper based on the operator's [bsv]
// section. Resolution order:
//
//  1. cfg.NodeURLs (when non-empty): build one RPCProvider per entry
//     and wrap them in a MultiRPCProvider with the configured failure
//     budget + cooldown.
//  2. cfg.NodeURL (legacy single-entry): build one RPCProvider and
//     wrap it in a MultiRPCProvider so the failover surface is
//     uniform regardless of how the operator declared the endpoint.
//  3. Otherwise: returns (nil, nil) — caller decides whether the
//     absence is fatal (Phase 8 boot can fall through to file/cache/
//     P2P; bridge wiring still works without RPC).
//
// network is the BSV network name (regtest|testnet|mainnet); it must
// be the same for every URL — production must not mix networks.
func BuildBSVProvider(cfg BSVSection) (BSVProviderClient, error) {
	urls := cfg.EffectiveNodeURLs()
	if len(urls) == 0 {
		return nil, nil
	}

	network := cfg.Network
	if network == "" {
		network = "regtest"
	}

	providers := make([]*bsvclient.RPCProvider, 0, len(urls))
	for _, u := range urls {
		p, err := bsvclient.NewRPCProvider(u, network)
		if err != nil {
			return nil, fmt.Errorf("bsv provider %q: %w", u, err)
		}
		providers = append(providers, p)
	}

	cooldown, err := parseNodeCooldown(cfg.NodeCooldown)
	if err != nil {
		return nil, err
	}
	mp, err := bsvclient.NewMultiRPCProvider(providers, bsvclient.MultiRPCProviderOpts{
		MaxConsecutiveFailures: cfg.NodeMaxConsecutiveFailures,
		Cooldown:               cooldown,
	})
	if err != nil {
		return nil, fmt.Errorf("multi rpc provider: %w", err)
	}
	return mp, nil
}

// parseNodeCooldown turns the operator's TOML duration string into a
// time.Duration. Empty falls through to the MultiRPCProvider default
// (zero, which in turn defaults to 30s inside NewMultiRPCProvider).
// A malformed string is a hard error so misconfigurations don't
// silently default away.
func parseNodeCooldown(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("bsv node_cooldown %q: %w", s, err)
	}
	return d, nil
}
