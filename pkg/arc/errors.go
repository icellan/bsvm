package arc

import (
	"errors"
	"strings"
)

// ARCBroadcastError is the typed error returned by Client.Broadcast and
// Client.Status when the ARC server replies with a non-2xx status (or
// when the response body indicates a server-side rejection). Consumers
// classify retry vs drop via errors.As + IsTransient/IsPermanent
// instead of string-matching the wrapped fmt.Errorf message.
//
// Field semantics:
//
//   - HTTPStatus: the HTTP status code returned by ARC. 0 when the
//     broadcast failed before a response was received (e.g. dial
//     refused) — use Underlying for the wire-level cause.
//   - TxStatus: the BSV-side `txStatus` enum from ARC's structured
//     response body, when present. Empty when the response was
//     unparseable or absent.
//   - Detail: human-readable detail (the response body, when it isn't
//     a parsed JSON shape — primarily for debug logs).
//   - Underlying: the wrapped transport / parse error, when one exists.
//     errors.Is / errors.As recurse through this so callers can match
//     net errors, context.Canceled, etc.
type ARCBroadcastError struct {
	HTTPStatus int
	TxStatus   string
	Detail     string
	Underlying error
}

// Error implements error. Format:
//
//	arc: broadcast status <HTTP>: <Detail>          (when TxStatus empty)
//	arc: broadcast status <HTTP> tx_status=<S>: <D> (when TxStatus set)
//
// The "arc: broadcast status %d" prefix is preserved exactly so the
// legacy regex-based extractHTTPStatus in pkg/bridge stays a working
// fallback for any non-typed call sites that haven't migrated yet.
func (e *ARCBroadcastError) Error() string {
	var b strings.Builder
	b.WriteString("arc: broadcast status ")
	if e.HTTPStatus > 0 {
		b.WriteString(itoa(e.HTTPStatus))
	} else {
		b.WriteString("0")
	}
	if e.TxStatus != "" {
		b.WriteString(" tx_status=")
		b.WriteString(e.TxStatus)
	}
	if e.Detail != "" {
		b.WriteString(": ")
		b.WriteString(e.Detail)
	}
	if e.Underlying != nil && e.Detail == "" {
		b.WriteString(": ")
		b.WriteString(e.Underlying.Error())
	}
	return b.String()
}

// Unwrap returns the wrapped transport error, allowing errors.Is to
// recurse into context.Canceled / net.OpError / etc.
func (e *ARCBroadcastError) Unwrap() error {
	return e.Underlying
}

// IsTransient reports whether the error is safe to retry. Decision:
//
//   - HTTP 5xx / 408 / 429 — server-side hiccup, retry.
//   - HTTP 0 with a non-nil Underlying — pre-response transport failure
//     (dial refused, EOF, timeout). Retry on the next pass.
//   - Otherwise (no signal, or definitive 4xx) — not transient.
func (e *ARCBroadcastError) IsTransient() bool {
	if e == nil {
		return false
	}
	switch {
	case e.HTTPStatus == 408 || e.HTTPStatus == 429:
		return true
	case e.HTTPStatus >= 500 && e.HTTPStatus < 600:
		return true
	case e.HTTPStatus == 0 && e.Underlying != nil:
		return true
	}
	return false
}

// IsPermanent reports whether the error definitively rejects the tx —
// retrying with the same payload will not help. Decision:
//
//   - Any 4xx other than 408/429.
//   - TxStatus is one of ARC's terminal-rejection enums (REJECTED,
//     DOUBLE_SPEND_*, SEEN_IN_ORPHAN_MEMPOOL).
//   - Detail mentions a covenant-level rejection (covenant-failed,
//     verify-failed) — these surface on 200 responses with txStatus
//     set, so the HTTPStatus alone is insufficient.
func (e *ARCBroadcastError) IsPermanent() bool {
	if e == nil {
		return false
	}
	if e.HTTPStatus >= 400 && e.HTTPStatus < 500 &&
		e.HTTPStatus != 408 && e.HTTPStatus != 429 {
		return true
	}
	switch Status(e.TxStatus) {
	case StatusRejected,
		StatusDoubleSpendAttempted,
		StatusDoubleSpendConfirmed,
		StatusSeenInOrphanMempool:
		return true
	}
	low := strings.ToLower(e.Detail)
	for _, kw := range []string{
		"covenant-failed", "covenant-rejected", "verify-failed",
		"double-spend", "double spend", "rejected", "bad-txns",
		"missing inputs", "txn-mempool-conflict", "non-canonical",
	} {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}

// AsBroadcastError extracts an *ARCBroadcastError from err via
// errors.As, returning nil when err is not (or does not wrap) one. Used
// by callers that prefer a single helper over the explicit errors.As
// dance.
func AsBroadcastError(err error) *ARCBroadcastError {
	if err == nil {
		return nil
	}
	var arcErr *ARCBroadcastError
	if errors.As(err, &arcErr) {
		return arcErr
	}
	return nil
}

// itoa is a tiny, allocation-free uint→decimal converter used only by
// ARCBroadcastError.Error. We avoid the strconv dependency to keep
// this file's import surface minimal.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if negative {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
