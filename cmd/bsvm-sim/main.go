// Command bsvm-sim is a terminal UI load generator for the BSVM devnet.
// It initialises a pool of users and a library of representative EVM
// contracts, deploys them once, then runs continuous randomised
// traffic against them. Operators can add/remove users and start/stop
// workloads while traffic is running.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/holiman/uint256"
	"golang.org/x/term"

	"github.com/icellan/bsvm/pkg/sim"
	"github.com/icellan/bsvm/pkg/sim/rpc"
	"github.com/icellan/bsvm/pkg/sim/tui"
)

type flags struct {
	nodes     string
	users     int
	tps       int
	headless  bool
	deploy    bool
	duration  time.Duration
	workloads string
}

func main() {
	var f flags
	flag.StringVar(&f.nodes, "nodes", "http://localhost:8545,http://localhost:8546,http://localhost:8547", "comma-separated RPC URLs")
	flag.IntVar(&f.users, "users", 9, "initial user pool size (excluding the faucet)")
	flag.IntVar(&f.tps, "tps", 5, "default rate per active workload (tx/s)")
	flag.BoolVar(&f.headless, "headless", false, "print periodic stats instead of running the TUI")
	flag.BoolVar(&f.deploy, "deploy", true, "deploy contract suite at startup")
	flag.DurationVar(&f.duration, "duration", 0, "headless run duration (0 = forever)")
	flag.StringVar(&f.workloads, "workloads", "value-transfer,erc20-transfer,storage-set", "comma-separated workloads to start at boot")
	flag.Parse()

	urls := splitTrim(f.nodes, ",")
	if len(urls) == 0 {
		die("at least one --nodes URL required")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigc
		cancel()
	}()

	mc := rpc.NewMultiClient(urls)
	chainID, heights, err := dialSummary(ctx, mc)
	if err != nil {
		die(err.Error())
	}
	fmt.Printf("chain=%d heights=[%s] nodes=%d\n", chainID, strings.Join(heights, ","), mc.Len())

	pool, err := sim.NewUserPool(chainID, mc)
	if err != nil {
		die(fmt.Sprintf("pool: %v", err))
	}
	reg := sim.NewRegistry()
	eng := sim.NewEngine(pool, reg, chainID)

	if f.deploy {
		fmt.Println("deploying contract suite...")
		dctx, dcancel := context.WithTimeout(ctx, 90*time.Second)
		defer dcancel()
		if err := eng.SetupDeployments(dctx); err != nil {
			die(fmt.Sprintf("deploy: %v", err))
		}
		fmt.Printf("deployed: erc20a=%s erc20b=%s erc721=%s weth=%s amm=%s multisig=%s storage=%s\n",
			eng.Deploy.ERC20A.Hex(), eng.Deploy.ERC20B.Hex(), eng.Deploy.ERC721.Hex(),
			eng.Deploy.WETH.Hex(), eng.Deploy.AMM.Hex(), eng.Deploy.Multisig.Hex(),
			eng.Deploy.Storage.Hex())
	}
	eng.RegisterDefaultWorkloads(f.tps)

	// Seed ERC20 + AMM so workloads have balances / liquidity. Errors
	// are non-fatal because we might be starting against a mid-life devnet.
	if eng.Deploy != nil {
		seed := new(uint256.Int).Lsh(uint256.NewInt(1), 40)
		if erc, ok := reg.Get(sim.KindERC20Transfer).(*sim.ERC20Workload); ok {
			sctx, scancel := context.WithTimeout(ctx, 60*time.Second)
			if err := erc.SeedFromFaucet(sctx, seed); err != nil {
				fmt.Printf("seed erc20: %v\n", err)
			}
			scancel()
		}
		if amm, ok := reg.Get(sim.KindAMMSwap).(*sim.AMMWorkload); ok {
			sctx, scancel := context.WithTimeout(ctx, 60*time.Second)
			liq := new(uint256.Int).Lsh(uint256.NewInt(1), 50)
			if err := amm.SeedLiquidity(sctx, liq, liq); err != nil {
				fmt.Printf("seed amm: %v\n", err)
			}
			scancel()
		}
	}

	eng.StartNodeMonitor(ctx, 2*time.Second)
	eng.StartTPSTicker(ctx)

	for _, kind := range splitTrim(f.workloads, ",") {
		if err := reg.Start(ctx, sim.WorkloadKind(kind)); err != nil {
			fmt.Printf("start %s: %v\n", kind, err)
		}
	}

	// Auto-fall-back to headless on dumb / redirected terminals so CI
	// and `| tee` invocations just work.
	if f.headless || !term.IsTerminal(int(os.Stdout.Fd())) {
		runHeadless(ctx, eng, f.duration)
		return
	}
	runTUI(ctx, eng)
}

func runTUI(ctx context.Context, eng *sim.Engine) {
	model := tui.NewModel(ctx, eng)
	prog := tea.NewProgram(model, tea.WithAltScreen(), tea.WithContext(ctx))
	if _, err := prog.Run(); err != nil {
		die(fmt.Sprintf("tui: %v", err))
	}
}

func runHeadless(ctx context.Context, eng *sim.Engine, duration time.Duration) {
	var deadline <-chan time.Time
	if duration > 0 {
		deadline = time.After(duration)
	}
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			fmt.Println("shutdown: ctx cancelled")
			return
		case <-deadline:
			fmt.Println("shutdown: duration reached")
			return
		case <-t.C:
			printStats(eng.EngineStats())
		}
	}
}

func printStats(s sim.EngineStats) {
	fmt.Printf("[%s] users=%d tps5=%.1f tps30=%.1f",
		time.Now().Format("15:04:05"), s.Users, s.TPS5s, s.TPS30s)
	for _, w := range s.Workloads {
		fmt.Printf(" | %s=%d/%d@%d", w.Kind, w.Succeeded, w.Failed, w.Rate)
		if w.LastErr != "" && w.Failed > 0 {
			fmt.Printf(" err=%q", truncate(w.LastErr, 80))
		}
	}
	var heights []string
	for _, n := range s.Nodes {
		heights = append(heights, fmt.Sprintf("%d", n.BlockNum))
	}
	fmt.Printf(" | heights=[%s]\n", strings.Join(heights, ","))
}

func dialSummary(ctx context.Context, mc *rpc.MultiClient) (uint64, []string, error) {
	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var chainID uint64
	heights := make([]string, mc.Len())
	for i, c := range mc.All() {
		cid, err := c.ChainID(dctx)
		if err != nil {
			return 0, nil, fmt.Errorf("dial %s: %w", c.URL(), err)
		}
		if chainID == 0 {
			chainID = cid
		} else if chainID != cid {
			return 0, nil, fmt.Errorf("chainID mismatch: %s reports %d, expected %d", c.URL(), cid, chainID)
		}
		h, err := c.BlockNumber(dctx)
		if err != nil {
			return 0, nil, fmt.Errorf("block number %s: %w", c.URL(), err)
		}
		heights[i] = fmt.Sprintf("%d", h)
	}
	return chainID, heights, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func splitTrim(s, sep string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, sep)
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func die(msg string) {
	fmt.Fprintln(os.Stderr, "bsvm-sim: "+msg)
	os.Exit(1)
}
