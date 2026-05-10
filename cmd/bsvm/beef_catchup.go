package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/icellan/bsvm/pkg/beef"
)

const (
	defaultBEEFCatchUpInterval     = 30 * time.Second
	defaultBEEFCatchUpLimit        = 100
	maxBEEFCatchUpLimit            = 500
	maxBEEFCatchUpEnvelopeBytes    = 10 * 1024 * 1024
	maxBEEFCatchUpResponseBodySize = 64 * 1024 * 1024
)

type beefCatchUpOptions struct {
	Store            beef.Store
	CovenantConsumer func(*beef.Envelope)
	PeerURLs         []string
	ShardID          uint64
	Limit            int
	Interval         time.Duration
	HTTPClient       *http.Client
	Logger           *slog.Logger
}

func startBEEFCovenantCatchUp(ctx context.Context, rt *beefRuntime, cfg BEEFSection, shardID uint64, logger *slog.Logger) {
	if rt == nil || rt.Store == nil {
		return
	}
	peers := resolveBEEFCatchUpPeers(cfg)
	if len(peers) == 0 {
		return
	}
	interval := defaultBEEFCatchUpInterval
	if raw := strings.TrimSpace(cfg.CatchUpInterval); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			logger.Warn("BEEF covenant catch-up interval invalid; using default",
				"value", raw,
				"default", defaultBEEFCatchUpInterval,
				"err", err)
		} else if parsed > 0 {
			interval = parsed
		}
	}
	limit := cfg.CatchUpLimit
	if limit <= 0 {
		limit = defaultBEEFCatchUpLimit
	}
	if limit > maxBEEFCatchUpLimit {
		limit = maxBEEFCatchUpLimit
	}
	opts := beefCatchUpOptions{
		Store:            rt.Store,
		CovenantConsumer: rt.CovenantConsumer,
		PeerURLs:         peers,
		ShardID:          shardID,
		Limit:            limit,
		Interval:         interval,
		HTTPClient: &http.Client{
			Timeout: 20 * time.Second,
		},
		Logger: logger,
	}
	logger.Info("BEEF covenant catch-up enabled",
		"peers", len(peers),
		"interval", interval,
		"limit", limit)
	go runBEEFCovenantCatchUpLoop(ctx, opts)
}

func resolveBEEFCatchUpPeers(cfg BEEFSection) []string {
	seen := make(map[string]struct{}, len(cfg.CatchUpPeers))
	out := make([]string, 0, len(cfg.CatchUpPeers))
	add := func(raw string) {
		peer := strings.TrimSpace(raw)
		if peer == "" {
			return
		}
		if _, ok := seen[peer]; ok {
			return
		}
		seen[peer] = struct{}{}
		out = append(out, peer)
	}
	for _, peer := range cfg.CatchUpPeers {
		add(peer)
	}
	for _, peer := range strings.Split(os.Getenv("BSVM_BEEF_CATCH_UP_PEERS"), ",") {
		add(peer)
	}
	return out
}

func runBEEFCovenantCatchUpLoop(ctx context.Context, opts beefCatchUpOptions) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	cursor, err := latestBEEFCovenantCatchUpCursor(opts.Store)
	if err != nil {
		logger.Warn("BEEF covenant catch-up: failed to read local cursor; starting from genesis",
			"err", err)
	}
	if count, runErr := runBEEFCovenantCatchUpOnce(ctx, opts, cursor); runErr != nil {
		logger.Warn("BEEF covenant catch-up failed", "err", runErr)
	} else if count > 0 {
		cursor, _ = latestBEEFCovenantCatchUpCursor(opts.Store)
	}

	ticker := time.NewTicker(opts.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			count, runErr := runBEEFCovenantCatchUpOnce(ctx, opts, cursor)
			if runErr != nil {
				logger.Warn("BEEF covenant catch-up failed", "err", runErr)
				continue
			}
			if count > 0 {
				cursor, _ = latestBEEFCovenantCatchUpCursor(opts.Store)
			}
		}
	}
}

func runBEEFCovenantCatchUpOnce(ctx context.Context, opts beefCatchUpOptions, cursor [32]byte) (int, error) {
	if opts.Store == nil {
		return 0, errors.New("BEEF covenant catch-up: store not configured")
	}
	client := opts.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = defaultBEEFCatchUpLimit
	}
	if limit > maxBEEFCatchUpLimit {
		limit = maxBEEFCatchUpLimit
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	total := 0
	var errs []error
	for _, peerURL := range opts.PeerURLs {
		for {
			envs, err := fetchBEEFCovenantCatchUp(ctx, client, peerURL, cursor, limit, opts.ShardID)
			if err != nil {
				errs = append(errs, err)
				break
			}
			if len(envs) == 0 {
				break
			}
			for _, env := range envs {
				if err := opts.Store.Put(env); err != nil {
					errs = append(errs, fmt.Errorf("store peer %s txid %s: %w", peerURL, hex.EncodeToString(env.TargetTxID[:]), err))
					continue
				}
				if opts.CovenantConsumer != nil {
					opts.CovenantConsumer(env)
				}
				cursor = env.TargetTxID
				total++
			}
			if len(envs) < limit {
				break
			}
		}
	}
	if total > 0 {
		logger.Info("BEEF covenant catch-up applied envelopes", "count", total)
		return total, nil
	}
	if len(errs) > 0 {
		return 0, errors.Join(errs...)
	}
	return 0, nil
}

func latestBEEFCovenantCatchUpCursor(store beef.Store) ([32]byte, error) {
	var cursor [32]byte
	if store == nil {
		return cursor, nil
	}
	err := store.Iterate(beef.IntentCovenantAdvanceConfirmed, func(env *beef.Envelope) bool {
		cursor = env.TargetTxID
		return true
	})
	return cursor, err
}

func fetchBEEFCovenantCatchUp(ctx context.Context, client *http.Client, peerBaseURL string, cursor [32]byte, limit int, shardID uint64) ([]*beef.Envelope, error) {
	requestURL, err := buildBEEFCatchUpURL(peerBaseURL, cursor, limit)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", requestURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("fetch %s: HTTP %d: %s", requestURL, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	limited := io.LimitReader(resp.Body, maxBEEFCatchUpResponseBodySize+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", requestURL, err)
	}
	if len(body) > maxBEEFCatchUpResponseBodySize {
		return nil, fmt.Errorf("fetch %s: response exceeds %d bytes", requestURL, maxBEEFCatchUpResponseBodySize)
	}
	envs, err := decodeBEEFCovenantCatchUpStream(body, shardID)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", requestURL, err)
	}
	return envs, nil
}

func buildBEEFCatchUpURL(peerBaseURL string, cursor [32]byte, limit int) (string, error) {
	u, err := url.Parse(strings.TrimSpace(peerBaseURL))
	if err != nil {
		return "", fmt.Errorf("parse BEEF catch-up peer URL %q: %w", peerBaseURL, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("BEEF catch-up peer URL %q must include scheme and host", peerBaseURL)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/bsvm/beef/covenant-chain"
	} else if !strings.HasSuffix(u.Path, "/bsvm/beef/covenant-chain") {
		u.Path = strings.TrimRight(u.Path, "/") + "/bsvm/beef/covenant-chain"
	}
	q := u.Query()
	q.Set("from", hex.EncodeToString(cursor[:]))
	q.Set("limit", strconv.Itoa(limit))
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func decodeBEEFCovenantCatchUpStream(body []byte, shardID uint64) ([]*beef.Envelope, error) {
	out := make([]*beef.Envelope, 0)
	for len(body) > 0 {
		if len(body) < 4 {
			return nil, io.ErrUnexpectedEOF
		}
		n := binary.BigEndian.Uint32(body[:4])
		body = body[4:]
		if n == 0 {
			return nil, errors.New("zero-length BEEF envelope frame")
		}
		if n > maxBEEFCatchUpEnvelopeBytes {
			return nil, fmt.Errorf("BEEF envelope frame %d exceeds %d bytes", n, maxBEEFCatchUpEnvelopeBytes)
		}
		if uint32(len(body)) < n {
			return nil, io.ErrUnexpectedEOF
		}
		env, err := decodeBEEFCovenantCatchUpEnvelope(body[:n], shardID)
		if err != nil {
			return nil, err
		}
		out = append(out, env)
		body = body[n:]
	}
	return out, nil
}

func decodeBEEFCovenantCatchUpEnvelope(encoded []byte, shardID uint64) (*beef.Envelope, error) {
	hdr, beefBody, err := beef.DecodeEnvelopeHeader(encoded)
	if err != nil {
		return nil, err
	}
	if hdr.Intent != beef.IntentCovenantAdvanceConfirmed {
		return nil, fmt.Errorf("unexpected BEEF catch-up intent %s", beef.IntentName(hdr.Intent))
	}
	if shardID != 0 {
		if !hdr.ShardBound() {
			return nil, errors.New("BEEF catch-up envelope missing shard binding")
		}
		if hdr.ShardID != shardID {
			return nil, fmt.Errorf("BEEF catch-up envelope shard %d does not match local shard %d", hdr.ShardID, shardID)
		}
	}
	parsed, err := beef.ParseBEEF(beefBody)
	if err != nil {
		return nil, err
	}
	target := parsed.Target()
	if target == nil {
		return nil, errors.New("BEEF catch-up envelope has no target transaction")
	}
	env := &beef.Envelope{
		Header:     hdr,
		Beef:       append([]byte(nil), beefBody...),
		TargetTxID: target.TxID,
		Confirmed:  target.HasBUMP,
		ReceivedAt: time.Now().UTC(),
	}
	if target.HasBUMP && int(target.BUMPRef) < len(parsed.BUMPs) {
		env.BlockHeight = parsed.BUMPs[target.BUMPRef].BlockHeight
	}
	return env, nil
}
