package bridge

import (
	"errors"
	"fmt"
	"testing"

	"github.com/icellan/bsvm/pkg/arc"
)

// TestClassifyBroadcastError_TypedARCError confirms the classifier
// prefers the typed *arc.ARCBroadcastError path over string-matching.
// Each case mirrors a real ARC response shape EE will see in
// production.
func TestClassifyBroadcastError_TypedARCError(t *testing.T) {
	cases := []struct {
		name string
		in   error
		want error
	}{
		{
			"503 transient",
			&arc.ARCBroadcastError{HTTPStatus: 503, Detail: "bad gateway"},
			ErrBroadcastTransient,
		},
		{
			"400 rejected permanent",
			&arc.ARCBroadcastError{HTTPStatus: 400, TxStatus: "REJECTED"},
			ErrBroadcastPermanent,
		},
		{
			"408 timeout transient",
			&arc.ARCBroadcastError{HTTPStatus: 408},
			ErrBroadcastTransient,
		},
		{
			"429 rate-limited transient",
			&arc.ARCBroadcastError{HTTPStatus: 429},
			ErrBroadcastTransient,
		},
		{
			"200 with REJECTED txStatus permanent",
			&arc.ARCBroadcastError{HTTPStatus: 200, TxStatus: "REJECTED"},
			ErrBroadcastPermanent,
		},
		{
			"200 with DOUBLE_SPEND_ATTEMPTED txStatus permanent",
			&arc.ARCBroadcastError{HTTPStatus: 200, TxStatus: "DOUBLE_SPEND_ATTEMPTED"},
			ErrBroadcastPermanent,
		},
		{
			"transport failure (HTTPStatus 0) transient",
			&arc.ARCBroadcastError{Underlying: errors.New("dial tcp: refused")},
			ErrBroadcastTransient,
		},
		{
			"wrapped 503 transient via errors.As",
			fmt.Errorf("withdrawer: %w", &arc.ARCBroadcastError{HTTPStatus: 503}),
			ErrBroadcastTransient,
		},
		{
			"wrapped 422 rejected permanent via errors.As",
			fmt.Errorf("withdrawer: %w", &arc.ARCBroadcastError{HTTPStatus: 422, Detail: "covenant-failed"}),
			ErrBroadcastPermanent,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyBroadcastError(tc.in)
			if !errors.Is(got, tc.want) {
				t.Errorf("got %v, want sentinel %v", got, tc.want)
			}
		})
	}
}
