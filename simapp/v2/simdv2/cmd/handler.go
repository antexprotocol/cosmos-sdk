package cmd

import (
	"context"
	"encoding/json"
	"fmt"

	"cosmossdk.io/core/transaction"
	"cosmossdk.io/server/v2/cometbft"
	"cosmossdk.io/server/v2/cometbft/handlers"
	v1 "github.com/cometbft/cometbft/api/cometbft/abci/v1"
)

func CustomPrepareProposal[T transaction.Tx]() handlers.PrepareHandler[T] {
	return func(ctx context.Context, app handlers.AppManager[T], codec transaction.Codec[T], req *v1.PrepareProposalRequest, chainID string) ([]T, error) {
		var txs []T
		for _, tx := range req.Txs {
			decTx, err := codec.Decode(tx)
			if err != nil {
				fmt.Println("CustomPrepareProposal error decoding tx", err)
				continue
			}

			txs = append(txs, decTx)
		}

		// "Process" vote extensions (we'll just inject all votes)
		injectedTx, err := json.Marshal(req.LocalLastCommit)
		if err != nil {
			return nil, err
		}

		// put the injected tx into the first position
		txs = append([]T{cometbft.RawTx(injectedTx).(T)}, txs...)

		return txs, nil
	}
}
